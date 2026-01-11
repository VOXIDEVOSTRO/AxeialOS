#include <AxeSchd.h>
#include <AxeThreads.h>
#include <KHeap.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <Sync.h>
#include <Timer.h>
#include <VMM.h>

uint32_t NextThreadId = 1;
Thread*  ThreadList   = NULL;
Thread*  CurrentThreads[MaxCPUs];
Thread*  IdleThread;
SpinLock ThreadListLock;

static inline uint32_t
ThreadPriorityToSchedulerPrio(ThreadPriority __Priority__)
{
    switch (__Priority__)
    {
        case ThreadPriorityUltra:
            return PRIO_CRITICAL;
        case ThreadPrioritySuper:
            return PRIO_INTERRUPT;
        case ThreadPrioritykernel: /*TODO: fix this typo, i'm feeling lazy*/
            return PRIO_IRQ;
        case ThreadPriorityHigh:
            return PRIO_KERNEL_HIGH;
        case ThreadPriorityNormal:
            return PRIO_USER_NORMAL;
        case ThreadPriorityLow:
            return PRIO_USER_LOW;
        case ThreadPriorityIdle:
            return PRIO_IDLE;
        case ThreadPriorityUnknown:
        default:
            return PRIO_USER_NORMAL;
    }
}

static inline ThreadPriority
SchedulerPrioToThreadPriority(uint32_t __Prio__)
{
    if (__Prio__ <= 1)
    {
        return ThreadPriorityUltra;
    }
    else if (__Prio__ <= 3)
    {
        return ThreadPrioritySuper;
    }
    else if (__Prio__ <= 5)
    {
        return ThreadPriorityHigh;
    }
    else if (__Prio__ <= 7)
    {
        return ThreadPrioritykernel;
    }
    else if (__Prio__ <= 9)
    {
        return ThreadPriorityHigh;
    }
    else if (__Prio__ <= 11)
    {
        return ThreadPriorityNormal;
    }
    else if (__Prio__ <= 13)
    {
        return ThreadPriorityLow;
    }
    else if (__Prio__ <= 30)
    {
        return ThreadPriorityLow;
    }
    return ThreadPriorityIdle;
}

/*Idle worker*/
static void
Idler(void* __Arg__ _unused)
{
    for (;;)
    {
        __asm__ volatile("hlt" ::: "memory");
    }
}

void
InitializeThreadManager(SysErr* __Err__)
{
    __atomic_store_n(&NextThreadId, 1u, __ATOMIC_SEQ_CST);
    __atomic_store_n(&ThreadList, (Thread*)NULL, __ATOMIC_SEQ_CST);

    for (uint32_t CpuIndex = 0; CpuIndex < MaxCPUs; CpuIndex++)
    {
        __atomic_store_n(&CurrentThreads[CpuIndex], (Thread*)NULL, __ATOMIC_SEQ_CST);
    }

    SysErr  err;
    SysErr* Error = &err;

    IdleThread = CreateThread(ThreadTypeKernel, Idler, NULL, ThreadPriorityIdle);

    if (Probe_IF_Error(IdleThread))
    {
        SlotError(__Err__, -BadAlloc);
        return;
    }

    __atomic_store_n(&IdleThread->State, ThreadStateBlocked, __ATOMIC_SEQ_CST);

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
        return Error_TO_Pointer(-Limits);
    }

    Thread* Result = __atomic_load_n(&CurrentThreads[__CpuId__], __ATOMIC_SEQ_CST);
    return Result;
}

void
SetCurrentThread(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__ _unused)
{
    if (__CpuId__ >= MaxCPUs)
    {
        SlotError(__Err__, -Limits);
        return;
    }

    __atomic_store_n(&CurrentThreads[__CpuId__], __ThreadPtr__, __ATOMIC_SEQ_CST);
}

Thread*
CreateThread(ThreadType     __Type__,
             void*          __EntryPoint__,
             void*          __Argument__,
             ThreadPriority __Priority__)
{
    SysErr  err;
    SysErr* Error     = &err;
    Thread* NewThread = (Thread*)KMalloc(sizeof(Thread));
    if (Probe_IF_Error(NewThread) || !NewThread)
    {
        return Error_TO_Pointer(-BadAlloc);
    }

    for (size_t Index = 0; Index < sizeof(Thread); Index++)
    {
        __atomic_store_n(&((uint8_t*)NewThread)[Index], (uint8_t)0, __ATOMIC_SEQ_CST);
    }

    __atomic_store_n(&NewThread->ThreadId, AllocateThreadId(), __ATOMIC_SEQ_CST);

    __atomic_store_n(&NewThread->ProcessId, 1u, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->State, ThreadStateReady, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Type, __Type__, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Priority, __Priority__, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->BasePriority, __Priority__, __ATOMIC_SEQ_CST);
    KrnPrintf(NewThread->Name, "Thread-%u", NewThread->ThreadId);

    if (__Type__ == ThreadTypeKernel)
    {
        void* KernelStackBase = KMalloc(KStackSize);
        if (Probe_IF_Error(KernelStackBase) || !KernelStackBase)
        {
            KFree(NewThread, Error);
            return Error_TO_Pointer(-BadAlloc);
        }
        __atomic_store_n(
            &NewThread->KernelStack, (uint64_t)KernelStackBase + KStackSize, __ATOMIC_SEQ_CST);
        __atomic_store_n(&NewThread->UserStack, (uint64_t)0, __ATOMIC_SEQ_CST);
        __atomic_store_n(&NewThread->StackSize, KStackSize, __ATOMIC_SEQ_CST);
    }
    else
    {
        void* KernelStackBase = KMalloc(KStackSize);
        void* UserStackBase   = KMalloc(KStackSize);
        if (Probe_IF_Error(KernelStackBase) || !KernelStackBase || Probe_IF_Error(UserStackBase) ||
            !UserStackBase)
        {
            if (KernelStackBase)
            {
                KFree(KernelStackBase, Error);
            }
            if (UserStackBase)
            {
                KFree(UserStackBase, Error);
            }
            KFree(NewThread, Error);
            return Error_TO_Pointer(-BadAlloc);
        }
        __atomic_store_n(
            &NewThread->KernelStack, (uint64_t)KernelStackBase + KStackSize, __ATOMIC_SEQ_CST);
        __atomic_store_n(
            &NewThread->UserStack, (uint64_t)UserStackBase + KStackSize, __ATOMIC_SEQ_CST);
        __atomic_store_n(&NewThread->StackSize, KStackSize, __ATOMIC_SEQ_CST);
    }

    __atomic_store_n(&NewThread->Context.Rip, (uint64_t)__EntryPoint__, __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &NewThread->Context.Rsp, ((NewThread->KernelStack & ~0xFULL) - 16), __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Context.Rflags, 0x202ull, __ATOMIC_SEQ_CST);

    if (__Type__ == ThreadTypeKernel)
    {
        __atomic_store_n(&NewThread->Context.Cs, KernelCodeSelector, __ATOMIC_SEQ_CST);
        __atomic_store_n(&NewThread->Context.Ss, KernelDataSelector, __ATOMIC_SEQ_CST);
    }
    else
    {
        __atomic_store_n(&NewThread->Context.Cs, UserCodeSelector, __ATOMIC_SEQ_CST);
        __atomic_store_n(&NewThread->Context.Ss, UserDataSelector, __ATOMIC_SEQ_CST);
        __atomic_store_n(
            &NewThread->Context.Rsp, ((NewThread->UserStack & ~0xFULL) - 16), __ATOMIC_SEQ_CST);
    }

    __atomic_store_n(&NewThread->Context.Ds, NewThread->Context.Ss, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Context.Es, NewThread->Context.Ss, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Context.Fs, NewThread->Context.Ss, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Context.Gs, NewThread->Context.Ss, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Context.Rdi, (uint64_t)__Argument__, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->CpuAffinity, 0xFFFFFFFFu, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->LastCpu, 0xFFFFFFFFu, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->TimeSlice, DEFAULT_TIME_SLICE, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Cooldown, 0u, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->StartTime, GetSystemTicks(), __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->CreationTick, GetSystemTicks(), __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->WaitReason, WaitReasonNone, __ATOMIC_SEQ_CST);

    __atomic_store_n(&NewThread->PageDirectory, (uint64_t)0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->VirtualBase, UserVirtualBase, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->MemoryUsage, (NewThread->StackSize * 2) / 1024, __ATOMIC_SEQ_CST);

    Thread* OLDHead = __atomic_load_n(&ThreadList, __ATOMIC_SEQ_CST);
    __atomic_store_n(&NewThread->Next, OLDHead, __ATOMIC_SEQ_CST);
    if (OLDHead)
    {
        __atomic_store_n(&OLDHead->Prev, NewThread, __ATOMIC_SEQ_CST);
    }
    __atomic_store_n(&ThreadList, NewThread, __ATOMIC_SEQ_CST);

    return NewThread;
}

void
DestroyThread(Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    __atomic_store_n(&__ThreadPtr__->State, ThreadStateTerminated, __ATOMIC_SEQ_CST);

    Thread* Previous = __atomic_load_n(&__ThreadPtr__->Prev, __ATOMIC_SEQ_CST);
    Thread* Next     = __atomic_load_n(&__ThreadPtr__->Next, __ATOMIC_SEQ_CST);

    if (Previous)
    {
        __atomic_store_n(&Previous->Next, Next, __ATOMIC_SEQ_CST);
    }
    else
    {
        __atomic_store_n(&ThreadList, Next, __ATOMIC_SEQ_CST);
    }

    if (Next)
    {
        __atomic_store_n(&Next->Prev, Previous, __ATOMIC_SEQ_CST);
    }

    if (__atomic_load_n(&__ThreadPtr__->KernelStack, __ATOMIC_SEQ_CST))
    {
        KFree((void*)(__atomic_load_n(&__ThreadPtr__->KernelStack, __ATOMIC_SEQ_CST) -
                      __atomic_load_n(&__ThreadPtr__->StackSize, __ATOMIC_SEQ_CST)),
              __Err__);
    }

    if (__atomic_load_n(&__ThreadPtr__->UserStack, __ATOMIC_SEQ_CST))
    {
        KFree((void*)(__atomic_load_n(&__ThreadPtr__->UserStack, __ATOMIC_SEQ_CST) -
                      __atomic_load_n(&__ThreadPtr__->StackSize, __ATOMIC_SEQ_CST)),
              __Err__);
    }

    KFree(__ThreadPtr__, __Err__);
}

void
SuspendThread(Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint32_t Flgs = __atomic_load_n(&__ThreadPtr__->Flags, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Flags, Flgs | ThreadFlagSuspended, __ATOMIC_SEQ_CST);

    ThreadState CurrentState = __atomic_load_n(&__ThreadPtr__->State, __ATOMIC_SEQ_CST);
    if (CurrentState == ThreadStateRunning || CurrentState == ThreadStateReady)
    {
        __atomic_store_n(&__ThreadPtr__->State, ThreadStateBlocked, __ATOMIC_SEQ_CST);
        __atomic_store_n(&__ThreadPtr__->WaitReason, WaitReasonNone, __ATOMIC_SEQ_CST);

        if (CurrentState == ThreadStateReady)
        {
            uint32_t CpuId = __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST);
            if (CpuId < MaxCPUs)
            {
                RemoveThreadFromAllQueues(CpuId, __ThreadPtr__, __Err__);
            }
        }
    }
}

void
ResumeThread(Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint32_t Flgs = __atomic_load_n(&__ThreadPtr__->Flags, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Flags, Flgs & ~ThreadFlagSuspended, __ATOMIC_SEQ_CST);

    ThreadState CurrentState = __atomic_load_n(&__ThreadPtr__->State, __ATOMIC_SEQ_CST);
    if (CurrentState == ThreadStateBlocked)
    {
        uint32_t WaitReason = __atomic_load_n(&__ThreadPtr__->WaitReason, __ATOMIC_SEQ_CST);
        if (WaitReason == WaitReasonNone)
        {
            uint32_t CpuId = __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST);
            if (CpuId >= MaxCPUs)
            {
                CpuId = CalculateOptimalCpu(__ThreadPtr__);
            }

            __atomic_store_n(&__ThreadPtr__->State, ThreadStateReady, __ATOMIC_SEQ_CST);
            __atomic_store_n(&__ThreadPtr__->LastCpu, CpuId, __ATOMIC_SEQ_CST);

            AddThreadToReadyQueue(CpuId, __ThreadPtr__, __Err__);
        }
    }
}

/*Priority*/

void
SetThreadPriority(Thread* __ThreadPtr__, ThreadPriority __Priority__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint32_t OldPrio =
        ThreadPriorityToSchedulerPrio(__atomic_load_n(&__ThreadPtr__->Priority, __ATOMIC_SEQ_CST));
    uint32_t    NewPrio      = ThreadPriorityToSchedulerPrio(__Priority__);
    ThreadState CurrentState = __atomic_load_n(&__ThreadPtr__->State, __ATOMIC_SEQ_CST);

    __atomic_store_n(&__ThreadPtr__->BasePriority, __Priority__, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Priority, __Priority__, __ATOMIC_SEQ_CST);

    if (CurrentState == ThreadStateReady || CurrentState == ThreadStateRunning)
    {
        uint32_t CpuId = __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST);

        if (CpuId < MaxCPUs)
        {
            RemoveThreadFromAllQueues(CpuId, __ThreadPtr__, __Err__);
            __atomic_store_n(&__ThreadPtr__->State, ThreadStateReady, __ATOMIC_SEQ_CST);
            AddThreadToPrioQueue(CpuId, __ThreadPtr__, NewPrio, __Err__);
        }
    }

    PDebug("Thread %u priority changed: %u -> %u (scheduler: %u -> %u)\n",
           __atomic_load_n(&__ThreadPtr__->ThreadId, __ATOMIC_SEQ_CST),
           __atomic_load_n(&__ThreadPtr__->BasePriority, __ATOMIC_SEQ_CST),
           __Priority__,
           OldPrio,
           NewPrio);
}

/*Super simple load balancing, just equally distributes threads across CPU cores, nothing too
 * fancy*/

void
SetThreadAffinity(Thread* __ThreadPtr__, uint32_t __CpuMask__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    __atomic_store_n(&__ThreadPtr__->CpuAffinity, __CpuMask__, __ATOMIC_SEQ_CST);

    ThreadState CurrentState = __atomic_load_n(&__ThreadPtr__->State, __ATOMIC_SEQ_CST);
    if (CurrentState == ThreadStateReady &&
        __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST) < MaxCPUs)
    {
        uint32_t CurrentCpu = __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST);
        if (!(__CpuMask__ & (1u << CurrentCpu)))
        {
            uint32_t TargetCpu = Nothing;
            for (uint32_t C = 0; C < Smp.CpuCount; C++)
            {
                if (__CpuMask__ & (1u << C))
                {
                    TargetCpu = C;
                    break;
                }
            }

            if (TargetCpu != Nothing)
            {
                MigrateThreadToCpu(__ThreadPtr__, TargetCpu, __Err__);
            }
        }
    }
}

/*loads*/
uint32_t
GetCpuLoad(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return 0xFFFFFFFF;
    }

    uint32_t Red = GetCpuReadyCount(__CpuId__);
    Thread*  Cur = GetCurrentThread(__CpuId__);
    uint32_t Run = (Probe_IF_Error(Cur) || !Cur) ? 0u : 1u;
    return Red + Run;
}

uint32_t
FindLeastLoadedCpu(void)
{
    uint32_t BestCpu = 0;
    uint32_t MinLoad = GetCpuReadyCount(0);

    for (uint32_t CpuIndex = 1; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        uint32_t Load = GetCpuReadyCount(CpuIndex);
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
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        return Nothing;
    }

    uint32_t Affinity = __atomic_load_n(&__ThreadPtr__->CpuAffinity, __ATOMIC_SEQ_CST);

    if (Affinity != 0xFFFFFFFF)
    {
        uint32_t BestCpu = Nothing;
        uint32_t MinLoad = 0xFFFFFFFF;

        for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
        {
            if (Affinity & (1u << CpuIndex))
            {
                uint32_t Load = GetCpuReadyCount(CpuIndex);
                if (Load < MinLoad)
                {
                    MinLoad = Load;
                    BestCpu = CpuIndex;
                }
            }
        }

        return BestCpu;
    }

    return FindLeastLoadedCpu();
}

void
ThreadExecute(Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint32_t TargetCpu = CalculateOptimalCpu(__ThreadPtr__);

    __atomic_store_n(&__ThreadPtr__->LastCpu, TargetCpu, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->State, ThreadStateReady, __ATOMIC_SEQ_CST);

    AddThreadToReadyQueue(TargetCpu, __ThreadPtr__, __Err__);

    PDebug("Thread %u assigned to CPU %u (Load: %u)\n",
           __atomic_load_n(&__ThreadPtr__->ThreadId, __ATOMIC_SEQ_CST),
           TargetCpu,
           GetCpuLoad(TargetCpu));
}

void
ThreadExecuteMultiple(Thread** __ThreadArray__, uint32_t __ThreadCount__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadArray__) || !__ThreadArray__ || __ThreadCount__ == 0)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    for (uint32_t ThreadIndex = 0; ThreadIndex < __ThreadCount__; ThreadIndex++)
    {
        Thread* ThreadPtr = __ThreadArray__[ThreadIndex];
        if (Probe_IF_Error(ThreadPtr) || !ThreadPtr)
        {
            continue;
        }

        uint32_t TargetCpu = CalculateOptimalCpu(ThreadPtr);
        __atomic_store_n(&ThreadPtr->LastCpu, TargetCpu, __ATOMIC_SEQ_CST);
        __atomic_store_n(&ThreadPtr->State, ThreadStateReady, __ATOMIC_SEQ_CST);

        AddThreadToReadyQueue(TargetCpu, ThreadPtr, __Err__);

        PDebug("Thread %u -> CPU %u (Load: %u)\n",
               __atomic_load_n(&ThreadPtr->ThreadId, __ATOMIC_SEQ_CST),
               TargetCpu,
               GetCpuLoad(TargetCpu));
    }
}

void
LoadBalanceThreads(SysErr* __Err__)
{
    uint32_t CpuLoads[MaxCPUs];
    uint32_t MaxLoad = 0;
    uint32_t MinLoad = 0xFFFFFFFF;
    uint32_t MaxCpu  = 0;
    uint32_t MinCpu  = 0;

    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        CpuLoads[CpuIndex] = GetCpuReadyCount(CpuIndex);

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

    if (MaxLoad > MinLoad + 2)
    {
        Thread* ThreadToMigrate = GetNextThread(MaxCpu);
        if (ThreadToMigrate)
        {
            uint32_t Affinity = __atomic_load_n(&ThreadToMigrate->CpuAffinity, __ATOMIC_SEQ_CST);
            if (Affinity == 0xFFFFFFFF || (Affinity & (1u << MinCpu)))
            {
                __atomic_store_n(&ThreadToMigrate->LastCpu, MinCpu, __ATOMIC_SEQ_CST);
                AddThreadToReadyQueue(MinCpu, ThreadToMigrate, __Err__);

                PDebug("Migrated Thread %u from CPU %u to CPU %u\n",
                       __atomic_load_n(&ThreadToMigrate->ThreadId, __ATOMIC_SEQ_CST),
                       MaxCpu,
                       MinCpu);
            }
            else
            {
                AddThreadToReadyQueue(MaxCpu, ThreadToMigrate, __Err__);
            }
        }
    }
}

void
GetSystemLoadStats(uint32_t*       __TotalThreads__,
                   uint32_t*       __AverageLoad__,
                   uint32_t*       __MaxLoad__,
                   uint32_t*       __MinLoad__,
                   SysErr* __Err__ _unused)
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
        __atomic_store_n(__TotalThreads__, TotalLoad, __ATOMIC_SEQ_CST);
    }
    if (__AverageLoad__)
    {
        __atomic_store_n(__AverageLoad__,
                         (Smp.CpuCount > 0) ? TotalLoad / Smp.CpuCount : Nothing,
                         __ATOMIC_SEQ_CST);
    }
    if (__MaxLoad__)
    {
        __atomic_store_n(__MaxLoad__, MaxLoad, __ATOMIC_SEQ_CST);
    }
    if (__MinLoad__)
    {
        __atomic_store_n(__MinLoad__, MinLoad, __ATOMIC_SEQ_CST);
    }
}

/*tc*/

void
ThreadYield(SysErr* __Err__ _unused)
{
    __asm__ volatile("int $0x20"); /*Simple*/
}

void
ThreadSleep(uint64_t __Milliseconds__, SysErr* __Err__)
{
    uint32_t CpuId   = GetCurrentCpuId();
    Thread*  Current = GetCurrentThread(CpuId);

    if (Current)
    {
        __atomic_store_n(&Current->State, ThreadStateSleeping, __ATOMIC_SEQ_CST);
        __atomic_store_n(&Current->WaitReason, WaitReasonSleep, __ATOMIC_SEQ_CST);
        __atomic_store_n(
            &Current->WakeupTime, GetSystemTicks() + __Milliseconds__, __ATOMIC_SEQ_CST);

        RemoveThreadFromAllQueues(CpuId, Current, __Err__);

        ThreadYield(__Err__);
    }
    else
    {
        uint64_t WakeupTime = GetSystemTicks() + __Milliseconds__;
        while (GetSystemTicks() < WakeupTime)
        {
            __asm__ volatile("hlt");
        }
    }
}

void
ThreadExit(uint32_t __ExitCode__, SysErr* __Err__)
{
    uint32_t CpuId   = GetCurrentCpuId();
    Thread*  Current = GetCurrentThread(CpuId);

    if (Probe_IF_Error(Current) || !Current)
    {
        SlotError(__Err__, -NoOperations);
        return;
    }

    __atomic_store_n(&Current->State, ThreadStateZombie, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Current->ExitCode, __ExitCode__, __ATOMIC_SEQ_CST);

    PInfo("Thread %u exiting with code %u\n",
          __atomic_load_n(&Current->ThreadId, __ATOMIC_SEQ_CST),
          __ExitCode__);

    AddThreadToZombieQueue(CpuId, Current, __Err__);

    RemoveThreadFromAllQueues(CpuId, Current, __Err__);

    ThreadYield(__Err__);
}

/*queries*/

Thread*
FindThreadById(uint32_t __ThreadId__)
{
    Thread* Current = __atomic_load_n(&ThreadList, __ATOMIC_SEQ_CST);
    while (Current)
    {
        if (__atomic_load_n(&Current->ThreadId, __ATOMIC_SEQ_CST) == __ThreadId__)
        {
            return Current;
        }
        Current = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);
    }

    return Error_TO_Pointer(-NoSuch);
}

uint32_t
GetThreadCount(void)
{
    uint32_t Count = 0;

    Thread* Current = __atomic_load_n(&ThreadList, __ATOMIC_SEQ_CST);
    while (Current)
    {
        Count++;
        Current = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);
    }

    return Count;
}

/*utils*/
void
WakeSleepingThreads(SysErr* __Err__)
{
    uint64_t CurrentTicks = GetSystemTicks();

    Thread* Current = __atomic_load_n(&ThreadList, __ATOMIC_SEQ_CST);

    while (Current)
    {
        Thread* Next = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);

        ThreadState CurrentState = __atomic_load_n(&Current->State, __ATOMIC_SEQ_CST);
        if (CurrentState == ThreadStateSleeping)
        {
            uint64_t WakeupTime = __atomic_load_n(&Current->WakeupTime, __ATOMIC_SEQ_CST);
            if (WakeupTime != 0 && WakeupTime <= CurrentTicks)
            {
                __atomic_store_n(&Current->State, ThreadStateReady, __ATOMIC_SEQ_CST);
                __atomic_store_n(&Current->WaitReason, WaitReasonNone, __ATOMIC_SEQ_CST);
                __atomic_store_n(&Current->WakeupTime, 0ull, __ATOMIC_SEQ_CST);

                uint32_t CpuId = __atomic_load_n(&Current->LastCpu, __ATOMIC_SEQ_CST);
                if (CpuId >= MaxCPUs)
                {
                    CpuId = CalculateOptimalCpu(Current);
                }

                AddThreadToReadyQueue(CpuId, Current, __Err__);
            }
        }

        Current = Next;
    }
}

void
DumpThreadInfo(Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    PInfo("Thread %u (%s):\n",
          __atomic_load_n(&__ThreadPtr__->ThreadId, __ATOMIC_SEQ_CST),
          __ThreadPtr__->Name);
    PInfo("  State: %u, Type: %u, Priority: %u\n",
          __atomic_load_n(&__ThreadPtr__->State, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->Type, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->Priority, __ATOMIC_SEQ_CST));
    PInfo("  CPU Time: %llu, Context Switches: %llu\n",
          __atomic_load_n(&__ThreadPtr__->CpuTime, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->ContextSwitches, __ATOMIC_SEQ_CST));
    PInfo("  Stack: K=0x%llx U=0x%llx Size=%u\n",
          __atomic_load_n(&__ThreadPtr__->KernelStack, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->UserStack, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->StackSize, __ATOMIC_SEQ_CST));
    PInfo("  Memory: %u KB, Affinity: 0x%x, LastCpu: %u\n",
          __atomic_load_n(&__ThreadPtr__->MemoryUsage, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->CpuAffinity, __ATOMIC_SEQ_CST),
          __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST));
}

void
DumpAllThreads(SysErr* __Err__ _unused)
{
    Thread*  Current = __atomic_load_n(&ThreadList, __ATOMIC_SEQ_CST);
    uint32_t Count   = 0;

    while (Current)
    {
        PInfo("Thread %u: %s (State: %u, CPU: %u, Prio: %u)\n",
              __atomic_load_n(&Current->ThreadId, __ATOMIC_SEQ_CST),
              Current->Name,
              __atomic_load_n(&Current->State, __ATOMIC_SEQ_CST),
              __atomic_load_n(&Current->LastCpu, __ATOMIC_SEQ_CST),
              __atomic_load_n(&Current->Priority, __ATOMIC_SEQ_CST));
        Current = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);
        Count++;
    }

    PInfo("Total threads: %u\n", Count);
}