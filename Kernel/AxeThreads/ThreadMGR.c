
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <KHeap.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <Sync.h>
#include <Timer.h>
#include <VMM.h>

uint32_t        NextThreadId = 1;
Thread*         ThreadList   = NULL;
SpinLock        ThreadListLock;
Thread*         CurrentThreads[MaxCPUs];
static SpinLock CurrentThreadLock; /*Mutexes would have been fine ig*/

void
InitializeThreadManager(void)
{
    InitializeSpinLock(&ThreadListLock, "ThreadList");
    InitializeSpinLock(&CurrentThreadLock, "CurrentThread");
    NextThreadId = 1;
    ThreadList   = NULL;

    /*
     * Initialize current threads array to NULL for all CPUs.
     * This prevents accessing invalid thread pointers on startup.
     */
    for (uint32_t CpuIndex = 0; CpuIndex < MaxCPUs; CpuIndex++)
    {
        CurrentThreads[CpuIndex] = NULL;
    }

    PSuccess("Thread Manager initialized\n");
}

uint32_t
AllocateThreadId(void)
{
    return __atomic_fetch_add(&NextThreadId, 1, __ATOMIC_SEQ_CST);
}

Thread*
GetCurrentThread(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return NULL;
    }

    AcquireSpinLock(&CurrentThreadLock);
    Thread* Result = CurrentThreads[__CpuId__];
    ReleaseSpinLock(&CurrentThreadLock);

    return Result;
}

void
SetCurrentThread(uint32_t __CpuId__, Thread* __ThreadPtr__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return;
    }

    AcquireSpinLock(&CurrentThreadLock);
    CurrentThreads[__CpuId__] = __ThreadPtr__;
    ReleaseSpinLock(&CurrentThreadLock);
}

Thread*
CreateThread(ThreadType     __Type__,
             void*          __EntryPoint__,
             void*          __Argument__,
             ThreadPriority __Priority__)
{
    PDebug("CreateThread: Entry - Type=%u, EntryPoint=%p, Arg=%p\n",
           __Type__,
           __EntryPoint__,
           __Argument__);

    PDebug("CreateThread: About to allocate TCB (size=%zu)\n", sizeof(Thread));
    Thread* NewThread = (Thread*)KMalloc(sizeof(Thread));
    if (!NewThread)
    {
        PError("CreateThread: Failed to allocate thread\n");
        ReleaseSpinLock(&ThreadListLock);
        return NULL;
    }
    PDebug("CreateThread: TCB allocated at %p\n", NewThread);

    PDebug("CreateThread: Clearing TCB\n");
    for (size_t Index = 0; Index < sizeof(Thread); Index++)
    {
        ((uint8_t*)NewThread)[Index] = 0;
    }
    PDebug("CreateThread: TCB cleared\n");

    PDebug("CreateThread: Allocating thread ID\n");
    NewThread->ThreadId = AllocateThreadId();
    PDebug("CreateThread: Thread ID allocated: %u\n", NewThread->ThreadId);

    NewThread->ProcessId    = 1;
    NewThread->State        = ThreadStateReady;
    NewThread->Type         = __Type__;
    NewThread->Priority     = __Priority__;
    NewThread->BasePriority = __Priority__;
    PDebug("CreateThread: Core fields initialized\n");

    PDebug("CreateThread: Setting thread name\n");
    KrnPrintf(NewThread->Name, "Thread-%u", NewThread->ThreadId);
    PDebug("CreateThread: Thread name set to: %s\n", NewThread->Name);

    PDebug("CreateThread: About to allocate stacks\n");
    if (__Type__ == ThreadTypeKernel)
    {
        PDebug("CreateThread: Allocating kernel stack (8192 bytes)\n");
        void* KernelStackBase = KMalloc(8192);
        if (!KernelStackBase)
        {
            PError("CreateThread: Failed to allocate kernel stack\n");
            KFree(NewThread);
            ReleaseSpinLock(&ThreadListLock);
            return NULL;
        }
        NewThread->KernelStack =
            (uint64_t)KernelStackBase + 8192; /** Stack grows downwards; store top */
        NewThread->UserStack = 0;             /** Kernel thread has no user stack */
        NewThread->StackSize = 8192;
        PDebug("CreateThread: Kernel stack allocated at %p (top: %p)\n",
               KernelStackBase,
               (void*)NewThread->KernelStack);
    }
    else
    {
        PDebug("CreateThread: Allocating kernel and user stacks\n");
        void* KernelStackBase = KMalloc(8192);
        void* UserStackBase   = KMalloc(8192);
        if (!KernelStackBase || !UserStackBase)
        {
            PError("CreateThread: Failed to allocate stacks\n");
            if (KernelStackBase)
            {
                KFree(KernelStackBase);
            }
            if (UserStackBase)
            {
                KFree(UserStackBase);
            }
            KFree(NewThread);
            ReleaseSpinLock(&ThreadListLock);
            return NULL;
        }
        NewThread->KernelStack = (uint64_t)KernelStackBase + 8192;
        NewThread->UserStack   = (uint64_t)UserStackBase + 8192;
        NewThread->StackSize   = 8192;
        PDebug("CreateThread: Stacks allocated - Kernel: %p, User: %p\n",
               (void*)NewThread->KernelStack,
               (void*)NewThread->UserStack);
    }

    PDebug("CreateThread: Initializing thread context\n");
    NewThread->Context.Rip    = (uint64_t)__EntryPoint__;
    NewThread->Context.Rsp    = (NewThread->KernelStack & ~0xFULL) - 16;
    NewThread->Context.Rflags = 0x202;
    if (__Type__ == ThreadTypeKernel)
    {
        NewThread->Context.Cs = KernelCodeSelector;
        NewThread->Context.Ss = KernelDataSelector;
    }
    else
    {
        NewThread->Context.Cs  = UserCodeSelector;
        NewThread->Context.Ss  = UserDataSelector;
        NewThread->Context.Rsp = (NewThread->UserStack & ~0xFULL) - 16;
    }

    NewThread->Context.Ds  = NewThread->Context.Ss;
    NewThread->Context.Es  = NewThread->Context.Ss;
    NewThread->Context.Fs  = NewThread->Context.Ss;
    NewThread->Context.Gs  = NewThread->Context.Ss;
    NewThread->Context.Rdi = (uint64_t)__Argument__;
    PDebug("CreateThread: Context initialized - RIP=%p, RSP=%p\n",
           (void*)NewThread->Context.Rip,
           (void*)NewThread->Context.Rsp);

    PDebug("CreateThread: Initializing scheduling fields\n");
    NewThread->CpuAffinity = 0xFFFFFFFF;
    NewThread->LastCpu     = 0xFFFFFFFF;
    NewThread->TimeSlice   = 10;
    NewThread->Cooldown    = 0;
    PDebug("CreateThread: About to call GetSystemTicks\n");
    NewThread->StartTime    = GetSystemTicks();
    NewThread->CreationTick = GetSystemTicks();
    PDebug("CreateThread: System ticks retrieved\n");
    NewThread->WaitReason = WaitReasonNone;

    NewThread->PageDirectory = 0;
    NewThread->VirtualBase   = UserVirtualBase;
    NewThread->MemoryUsage   = (NewThread->StackSize * 2) / 1024;
    PDebug("CreateThread: Scheduling and memory fields initialized\n");

    PDebug("CreateThread: Adding to thread list (current head: %p)\n", ThreadList);
    NewThread->Next = ThreadList;
    if (ThreadList)
    {
        ThreadList->Prev = NewThread;
    }
    ThreadList = NewThread;
    PDebug("CreateThread: Added to thread list (new head: %p)\n", ThreadList);

    PDebug("Created thread %u (%s)\n",
           NewThread->ThreadId,
           __Type__ == ThreadTypeKernel ? "Kernel" : "User");
    PDebug("CreateThread: Returning thread %p\n", NewThread);

    return NewThread;
}

void
DestroyThread(Thread* __ThreadPtr__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    __ThreadPtr__->State = ThreadStateTerminated;

    AcquireSpinLock(&ThreadListLock);

    if (__ThreadPtr__->Prev)
    {
        __ThreadPtr__->Prev->Next = __ThreadPtr__->Next;
    }
    else
    {
        ThreadList = __ThreadPtr__->Next;
    }

    if (__ThreadPtr__->Next)
    {
        __ThreadPtr__->Next->Prev = __ThreadPtr__->Prev;
    }

    ReleaseSpinLock(&ThreadListLock);

    if (__ThreadPtr__->KernelStack)
    {
        KFree((void*)(__ThreadPtr__->KernelStack - __ThreadPtr__->StackSize));
    }

    if (__ThreadPtr__->UserStack)
    {
        KFree((void*)(__ThreadPtr__->UserStack - __ThreadPtr__->StackSize));
    }

    KFree(__ThreadPtr__);

    PDebug("Destroyed thread %u\n", __ThreadPtr__->ThreadId);
}

void
SuspendThread(Thread* __ThreadPtr__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    AcquireSpinLock(&ThreadListLock);

    __ThreadPtr__->Flags |= ThreadFlagSuspended;

    if (__ThreadPtr__->State == ThreadStateRunning || __ThreadPtr__->State == ThreadStateReady)
    {
        __ThreadPtr__->State      = ThreadStateBlocked;
        __ThreadPtr__->WaitReason = WaitReasonNone;
    }

    ReleaseSpinLock(&ThreadListLock);

    PDebug("Suspended thread %u\n", __ThreadPtr__->ThreadId);
}

void
ResumeThread(Thread* __ThreadPtr__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    __ThreadPtr__->Flags &= ~ThreadFlagSuspended;

    if (__ThreadPtr__->State == ThreadStateBlocked && __ThreadPtr__->WaitReason == WaitReasonNone)
    {
        __ThreadPtr__->State = ThreadStateReady;
    }

    PDebug("Resumed thread %u\n", __ThreadPtr__->ThreadId);
}

void
SetThreadPriority(Thread* __ThreadPtr__, ThreadPriority __Priority__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    __ThreadPtr__->Priority = __Priority__;

    PDebug("Set thread %u priority to %u\n", __ThreadPtr__->ThreadId, __Priority__);
}

void
SetThreadAffinity(Thread* __ThreadPtr__, uint32_t __CpuMask__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    __ThreadPtr__->CpuAffinity = __CpuMask__;

    PDebug("Set thread %u affinity to 0x%x\n", __ThreadPtr__->ThreadId, __CpuMask__);
}

uint32_t
GetCpuLoad(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return 0xFFFFFFFF; /* Invalid CPU indicator */
    }

    return GetCpuReadyCount(__CpuId__);
}

uint32_t
FindLeastLoadedCpu(void)
{
    uint32_t BestCpu = 0;
    uint32_t MinLoad = GetCpuLoad(0);

    for (uint32_t CpuIndex = 1; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        uint32_t Load = GetCpuLoad(CpuIndex);
        if (Load < MinLoad)
        {
            MinLoad = Load;
            BestCpu = CpuIndex;
        }
    }

    return BestCpu;
}

uint32_t
CalculateOptimalCpu(Thread* __ThreadPtr__)
{
    if (!__ThreadPtr__)
    {
        return 0;
    }

    if (__ThreadPtr__->CpuAffinity != 0xFFFFFFFF)
    {
        uint32_t BestCpu       = 0;
        uint32_t MinLoad       = 0xFFFFFFFF;
        bool     FoundValidCpu = false;

        for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
        {
            if (__ThreadPtr__->CpuAffinity & (1 << CpuIndex))
            {
                uint32_t Load = GetCpuLoad(CpuIndex);
                if (!FoundValidCpu || Load < MinLoad)
                {
                    MinLoad       = Load;
                    BestCpu       = CpuIndex;
                    FoundValidCpu = true;
                }
            }
        }

        return FoundValidCpu ? BestCpu : 0;
    }

    return FindLeastLoadedCpu();
}

void
ThreadExecute(Thread* __ThreadPtr__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    /* Determine best CPU for this thread */
    uint32_t TargetCpu = CalculateOptimalCpu(__ThreadPtr__);

    /* Update thread's last CPU assignment */
    AcquireSpinLock(&ThreadListLock);
    __ThreadPtr__->LastCpu = TargetCpu;
    __ThreadPtr__->State   = ThreadStateReady;
    ReleaseSpinLock(&ThreadListLock);

    /* Enqueue thread in target CPU’s ready queue */
    AddThreadToReadyQueue(TargetCpu, __ThreadPtr__);

    PDebug("ThreadExecute: Thread %u assigned to CPU %u (Load: %u)\n",
           __ThreadPtr__->ThreadId,
           TargetCpu,
           GetCpuLoad(TargetCpu));
}

void
ThreadExecuteMultiple(Thread** __ThreadArray__, uint32_t __ThreadCount__)
{
    if (!__ThreadArray__ || __ThreadCount__ == 0)
    {
        return;
    }

    for (uint32_t ThreadIndex = 0; ThreadIndex < __ThreadCount__; ThreadIndex++)
    {
        Thread* ThreadPtr = __ThreadArray__[ThreadIndex];
        if (!ThreadPtr)
        {
            continue;
        }

        uint32_t TargetCpu = CalculateOptimalCpu(ThreadPtr);
        AcquireSpinLock(&ThreadListLock);
        ThreadPtr->LastCpu = TargetCpu;
        ThreadPtr->State   = ThreadStateReady;
        ReleaseSpinLock(&ThreadListLock);
        AddThreadToReadyQueue(TargetCpu, ThreadPtr);

        PDebug("ThreadExecuteMultiple: Thread %u \u2192 CPU %u (Load: %u)\n",
               ThreadPtr->ThreadId,
               TargetCpu,
               GetCpuLoad(TargetCpu));
    }
}

void
LoadBalanceThreads(void)
{
    uint32_t CpuLoads[MaxCPUs];
    uint32_t MaxLoad = 0;
    uint32_t MinLoad = 0xFFFFFFFF;
    uint32_t MaxCpu  = 0;
    uint32_t MinCpu  = 0;

    /* Gather load information */
    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        CpuLoads[CpuIndex] = GetCpuLoad(CpuIndex);

        if (CpuLoads[CpuIndex] > MaxLoad)
        {
            MaxLoad = CpuLoads[CpuIndex];
            MaxCpu  = CpuIndex;
        }

        if (CpuLoads[CpuIndex] < MinLoad)
        {
            MinLoad = CpuLoads[CpuIndex];
            MinCpu  = CpuIndex;
        }
    }

    /* Only perform migration if load difference is significant */
    if (MaxLoad > MinLoad + 2)
    {
        Thread* ThreadToMigrate = GetNextThread(MaxCpu);
        if (ThreadToMigrate)
        {
            /* Check if thread's affinity allows migration */
            if (ThreadToMigrate->CpuAffinity == 0xFFFFFFFF ||
                (ThreadToMigrate->CpuAffinity & (1 << MinCpu)))
            {
                ThreadToMigrate->LastCpu = MinCpu;
                AddThreadToReadyQueue(MinCpu, ThreadToMigrate);

                PDebug("LoadBalance: Migrated Thread %u from CPU %u to CPU %u\n",
                       ThreadToMigrate->ThreadId,
                       MaxCpu,
                       MinCpu);
            }
            else
            {
                PWarn("Migration Failed\n");

                /* Put thread back into original CPU’s ready queue if migration failed */
                AddThreadToReadyQueue(MaxCpu, ThreadToMigrate);
            }
        }
    }
}

void
GetSystemLoadStats(uint32_t* __TotalThreads__,
                   uint32_t* __AverageLoad__,
                   uint32_t* __MaxLoad__,
                   uint32_t* __MinLoad__)
{
    uint32_t TotalLoad = 0;
    uint32_t MaxLoad   = 0;
    uint32_t MinLoad   = 0xFFFFFFFF;

    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        uint32_t Load = GetCpuLoad(CpuIndex);
        TotalLoad += Load;

        if (Load > MaxLoad)
        {
            MaxLoad = Load;
        }
        if (Load < MinLoad)
        {
            MinLoad = Load;
        }
    }

    if (MinLoad == 0xFFFFFFFF)
    {
        MinLoad = 0;
    }

    if (__TotalThreads__)
    {
        *__TotalThreads__ = TotalLoad;
    }
    if (__AverageLoad__)
    {
        *__AverageLoad__ = (Smp.CpuCount > 0) ? TotalLoad / Smp.CpuCount : 0;
    }
    if (__MaxLoad__)
    {
        *__MaxLoad__ = MaxLoad;
    }
    if (__MinLoad__)
    {
        *__MinLoad__ = MinLoad;
    }
}

void
ThreadYield(void)
{
    /*Software Interrupt*/
    __asm__ volatile("int $0x20");
}

void
ThreadSleep(uint64_t __Milliseconds__)
{
    uint32_t CpuId   = GetCurrentCpuId();
    Thread*  Current = GetCurrentThread(CpuId);

    if (Current)
    {
        Current->State      = ThreadStateSleeping;
        Current->WaitReason = WaitReasonSleep;
        Current->WakeupTime = GetSystemTicks() + __Milliseconds__;

        /* Trigger scheduler by invoking timer interrupt */
        __asm__ volatile("int $0x20");
    }
    else
    {
        PWarn("Sleep Halt loop Has been jumped!\n");

        /* Busy wait fallback using halt instruction */
        uint64_t WakeupTime = GetSystemTicks() + __Milliseconds__;
        while (GetSystemTicks() < WakeupTime)
        {
            __asm__ volatile("hlt");
        }
    }
}

void
ThreadExit(uint32_t __ExitCode__)
{
    uint32_t CpuId   = GetCurrentCpuId();
    Thread*  Current = GetCurrentThread(CpuId);

    if (!Current)
    {
        return;
    }

    Current->State    = ThreadStateZombie;
    Current->ExitCode = __ExitCode__;

    PInfo("Thread %u exiting with code %u\n", Current->ThreadId, __ExitCode__);

    AddThreadToZombieQueue(CpuId, Current);
    __asm__ volatile("int $0x20");
}

Thread*
FindThreadById(uint32_t __ThreadId__)
{
    AcquireSpinLock(&ThreadListLock);

    Thread* Current = ThreadList;
    while (Current)
    {
        if (Current->ThreadId == __ThreadId__)
        {
            ReleaseSpinLock(&ThreadListLock);
            return Current;
        }
        Current = Current->Next;
    }

    ReleaseSpinLock(&ThreadListLock);
    return NULL;
}

uint32_t
GetThreadCount(void)
{
    uint32_t Count = 0;

    AcquireSpinLock(&ThreadListLock);
    Thread* Current = ThreadList;
    while (Current)
    {
        Count++;
        Current = Current->Next;
    }
    ReleaseSpinLock(&ThreadListLock);

    return Count;
}

void
WakeSleepingThreads(void)
{
    uint64_t CurrentTicks = GetSystemTicks();

    AcquireSpinLock(&ThreadListLock);
    Thread* Current = ThreadList;

    while (Current)
    {
        if (Current->State == ThreadStateSleeping && Current->WakeupTime <= CurrentTicks)
        {
            Current->State      = ThreadStateReady;
            Current->WaitReason = WaitReasonNone;
            Current->WakeupTime = 0;
        }
        Current = Current->Next;
    }

    ReleaseSpinLock(&ThreadListLock);
}

void
DumpThreadInfo(Thread* __ThreadPtr__)
{
    if (!__ThreadPtr__)
    {
        return;
    }

    PInfo("Thread %u (%s):\n", __ThreadPtr__->ThreadId, __ThreadPtr__->Name);
    PInfo("  State: %u, Type: %u, Priority: %u\n",
          __ThreadPtr__->State,
          __ThreadPtr__->Type,
          __ThreadPtr__->Priority);
    PInfo("  CPU Time: %llu, Context Switches: %llu\n",
          __ThreadPtr__->CpuTime,
          __ThreadPtr__->ContextSwitches);
    PInfo("  Stack: K=0x%llx U=0x%llx Size=%u\n",
          __ThreadPtr__->KernelStack,
          __ThreadPtr__->UserStack,
          __ThreadPtr__->StackSize);
    PInfo("  Memory: %u KB, Affinity: 0x%x\n",
          __ThreadPtr__->MemoryUsage,
          __ThreadPtr__->CpuAffinity);
}

void
DumpAllThreads(void)
{
    AcquireSpinLock(&ThreadListLock);
    Thread*  Current = ThreadList;
    uint32_t Count   = 0;

    while (Current)
    {
        PInfo("Thread %u: %s (State: %u, CPU: %u)\n",
              Current->ThreadId,
              Current->Name,
              Current->State,
              Current->LastCpu);
        Current = Current->Next;
        Count++;
    }

    ReleaseSpinLock(&ThreadListLock);

    PInfo("Total threads: %u\n", Count);
}