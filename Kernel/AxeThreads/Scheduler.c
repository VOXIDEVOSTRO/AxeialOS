
#include <AxeSchd.h>
#include <IDT.h>
#include <Timer.h>

CpuScheduler CpuSchedulers[MaxCPUs];

static inline void
ThreadFxSave(void* __State__)
{
    __asm__ volatile("fxsave %0" : "=m"(*(char (*)[512])__State__));
}

static inline void
ThreadFxRestore(const void* __State__)
{
    __asm__ volatile("fxrstor %0" ::"m"(*(const char (*)[512])__State__));
}

void
AddThreadToReadyQueue(uint32_t __CpuId__, Thread* __ThreadPtr__)
{
    if (__CpuId__ >= MaxCPUs || !__ThreadPtr__)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    __atomic_store_n(&__ThreadPtr__->State, ThreadStateReady, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->LastCpu, __CpuId__, __ATOMIC_SEQ_CST);
    __ThreadPtr__->Next = NULL;
    __ThreadPtr__->Prev = NULL;

    AcquireSpinLock(&Scheduler->SchedulerLock);

    if (!Scheduler->ReadyQueue)
    {
        Scheduler->ReadyQueue = __ThreadPtr__;
    }
    else
    {
        Thread* Tail = Scheduler->ReadyQueue;
        while (Tail->Next)
        {
            Tail = Tail->Next;
        }
        Tail->Next          = __ThreadPtr__;
        __ThreadPtr__->Prev = Tail;
    }

    /* increment while still holding the lock */
    Scheduler->ReadyCount++;

    ReleaseSpinLock(&Scheduler->SchedulerLock);
}

Thread*
RemoveThreadFromReadyQueue(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return NULL;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    AcquireSpinLock(&Scheduler->SchedulerLock);

    Thread* ThreadPtr = Scheduler->ReadyQueue;
    if (!ThreadPtr)
    {
        ReleaseSpinLock(&Scheduler->SchedulerLock);
        return NULL;
    }

    Scheduler->ReadyQueue = ThreadPtr->Next;
    if (ThreadPtr->Next)
    {
        ThreadPtr->Next->Prev = NULL;
    }

    ThreadPtr->Next = NULL;
    ThreadPtr->Prev = NULL;

    /* decrement while still holding the lock */
    if (Scheduler->ReadyCount > 0)
    {
        Scheduler->ReadyCount--;
    }

    ReleaseSpinLock(&Scheduler->SchedulerLock);
    return ThreadPtr;
}

void
AddThreadToWaitingQueue(uint32_t __CpuId__, Thread* __ThreadPtr__)
{
    if (__CpuId__ >= MaxCPUs || !__ThreadPtr__)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    /* Set thread state to blocked atomically */
    __atomic_store_n(&__ThreadPtr__->State, ThreadStateBlocked, __ATOMIC_SEQ_CST);

    /* Acquire spinlock before modifying the waiting queue */
    AcquireSpinLock(&Scheduler->SchedulerLock);

    /* Add thread at head of waiting queue */
    __ThreadPtr__->Next     = Scheduler->WaitingQueue;
    Scheduler->WaitingQueue = __ThreadPtr__;

    /* Release spinlock after modification */
    ReleaseSpinLock(&Scheduler->SchedulerLock);
}

void
AddThreadToZombieQueue(uint32_t __CpuId__, Thread* __ThreadPtr__)
{
    if (__CpuId__ >= MaxCPUs || !__ThreadPtr__)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    /* Set thread state to zombie atomically */
    __atomic_store_n(&__ThreadPtr__->State, ThreadStateZombie, __ATOMIC_SEQ_CST);

    /* Acquire spinlock before modifying zombie queue */
    AcquireSpinLock(&Scheduler->SchedulerLock);

    /* Insert thread at the head of zombie queue */
    __ThreadPtr__->Next    = Scheduler->ZombieQueue;
    Scheduler->ZombieQueue = __ThreadPtr__;

    /* Release spinlock */
    ReleaseSpinLock(&Scheduler->SchedulerLock);

    /* Decrement overall thread count atomically */
    __atomic_fetch_sub(&Scheduler->ThreadCount, 1, __ATOMIC_SEQ_CST);
}

void
AddThreadToSleepingQueue(uint32_t __CpuId__, Thread* __ThreadPtr__)
{
    if (__CpuId__ >= MaxCPUs || !__ThreadPtr__)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    /* Atomically set thread state to sleeping */
    __atomic_store_n(&__ThreadPtr__->State, ThreadStateSleeping, __ATOMIC_SEQ_CST);

    /* Lock scheduler queue for safe insertion */
    AcquireSpinLock(&Scheduler->SchedulerLock);

    /* Insert at head of sleeping queue */
    __ThreadPtr__->Next      = Scheduler->SleepingQueue;
    Scheduler->SleepingQueue = __ThreadPtr__;

    /* Unlock after modification */
    ReleaseSpinLock(&Scheduler->SchedulerLock);
}

void
MigrateThreadToCpu(Thread* __ThreadPtr__, uint32_t __TargetCpuId__)
{
    if (!__ThreadPtr__ || __TargetCpuId__ >= MaxCPUs)
    {
        return;
    }

    /* Only migrate if thread is ready to run */
    if (__ThreadPtr__->State == ThreadStateReady)
    {
        __ThreadPtr__->LastCpu = __TargetCpuId__;
        AddThreadToReadyQueue(__TargetCpuId__, __ThreadPtr__);
    }
}

uint32_t
GetCpuThreadCount(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return 0;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].ThreadCount, __ATOMIC_SEQ_CST);
}

uint32_t
GetCpuReadyCount(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return 0;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].ReadyCount, __ATOMIC_SEQ_CST);
}

uint64_t
GetCpuContextSwitches(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return 0;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].ContextSwitches, __ATOMIC_SEQ_CST);
}

uint32_t
GetCpuLoadAverage(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return 0;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].LoadAverage, __ATOMIC_SEQ_CST);
}

void
WakeupSleepingThreads(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return;
    }

    CpuScheduler* Scheduler    = &CpuSchedulers[__CpuId__];
    uint64_t      CurrentTicks = GetSystemTicks();

    AcquireSpinLock(&Scheduler->SchedulerLock);

    Thread* Current = Scheduler->SleepingQueue;
    Thread* Prev    = NULL;

    while (Current)
    {
        Thread* Next = Current->Next;

        if (__atomic_load_n(&Current->WakeupTime, __ATOMIC_SEQ_CST) <= CurrentTicks)
        {
            /* unlink from sleeping */
            if (Prev)
            {
                Prev->Next = Next;
            }
            else
            {
                Scheduler->SleepingQueue = Next;
            }

            __atomic_store_n(&Current->WaitReason, WaitReasonNone, __ATOMIC_SEQ_CST);
            __atomic_store_n(&Current->WakeupTime, 0, __ATOMIC_SEQ_CST);
            Current->State = ThreadStateReady;
            Current->Prev  = NULL;
            Current->Next  = NULL;

            /* splice into ready tail under lock */
            if (!Scheduler->ReadyQueue)
            {
                Scheduler->ReadyQueue = Current;
            }
            else
            {
                Thread* Tail = Scheduler->ReadyQueue;
                while (Tail->Next)
                {
                    Tail = Tail->Next;
                }
                Tail->Next    = Current;
                Current->Prev = Tail;
            }

            Scheduler->ReadyCount++;
        }
        else
        {
            Prev = Current;
        }

        Current = Next;
    }

    ReleaseSpinLock(&Scheduler->SchedulerLock);
}

void
CleanupZombieThreads(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    /* Acquire spinlock before clearing zombie queue */
    AcquireSpinLock(&Scheduler->SchedulerLock);

    /* Extract zombie queue and clear it quickly under lock */
    Thread* Current        = Scheduler->ZombieQueue;
    Scheduler->ZombieQueue = NULL;

    ReleaseSpinLock(&Scheduler->SchedulerLock);

    /* Destroy freed zombie threads outside the lock to avoid long lock holds */
    while (Current)
    {
        Thread* Next = Current->Next;
        DestroyThread(Current);
        Current = Next;
    }
}

void
InitializeCpuScheduler(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    /* Reset all thread queues to empty */
    Scheduler->ReadyQueue    = NULL;
    Scheduler->WaitingQueue  = NULL;
    Scheduler->ZombieQueue   = NULL;
    Scheduler->SleepingQueue = NULL;
    Scheduler->CurrentThread = NULL;
    Scheduler->NextThread    = NULL;
    Scheduler->IdleThread    = NULL;

    /* Reset all counters atomically */
    __atomic_store_n(&Scheduler->ThreadCount, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->ReadyCount, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->ContextSwitches, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->IdleTicks, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->LoadAverage, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->ScheduleTicks, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->LastSchedule, 0, __ATOMIC_SEQ_CST);

    /* Initialize spinlock with identifier for debug */
    InitializeSpinLock(&Scheduler->SchedulerLock, "CpuScheduler");

    PDebug("CPU %u scheduler initialized\n", __CpuId__);
}

void
SaveInterruptFrameToThread(Thread* __ThreadPtr__, InterruptFrame* __Frame__)
{
    if (!__ThreadPtr__ || !__Frame__)
    {
        return;
    }

    ThreadContext* Context = &__ThreadPtr__->Context;

    /* Save general-purpose registers */
    Context->Rax = __Frame__->Rax;
    Context->Rbx = __Frame__->Rbx;
    Context->Rcx = __Frame__->Rcx;
    Context->Rdx = __Frame__->Rdx;
    Context->Rsi = __Frame__->Rsi;
    Context->Rdi = __Frame__->Rdi;
    Context->Rbp = __Frame__->Rbp;
    Context->R8  = __Frame__->R8;
    Context->R9  = __Frame__->R9;
    Context->R10 = __Frame__->R10;
    Context->R11 = __Frame__->R11;
    Context->R12 = __Frame__->R12;
    Context->R13 = __Frame__->R13;
    Context->R14 = __Frame__->R14;
    Context->R15 = __Frame__->R15;

    /* Save execution state registers */
    Context->Rip    = __Frame__->Rip;
    Context->Rsp    = __Frame__->Rsp;
    Context->Rflags = __Frame__->Rflags;
    Context->Cs     = __Frame__->Cs;
    Context->Ss     = __Frame__->Ss;
}

void
LoadThreadContextToInterruptFrame(Thread* __ThreadPtr__, InterruptFrame* __Frame__)
{
    if (!__ThreadPtr__ || !__Frame__)
    {
        return;
    }

    uint64_t __Pd__ = __ThreadPtr__->PageDirectory;
    if (__Pd__)
    {
        __asm__ volatile("mov %0, %%cr3" ::"r"(__Pd__) : "memory");
    }

    /*FPU*/
    ThreadFxRestore(__ThreadPtr__->Context.FpuState);

    ThreadContext* Context = &__ThreadPtr__->Context;

    /* Load general-purpose registers into interrupt frame */
    __Frame__->Rax = Context->Rax;
    __Frame__->Rbx = Context->Rbx;
    __Frame__->Rcx = Context->Rcx;
    __Frame__->Rdx = Context->Rdx;
    __Frame__->Rsi = Context->Rsi;
    __Frame__->Rdi = Context->Rdi;
    __Frame__->Rbp = Context->Rbp;
    __Frame__->R8  = Context->R8;
    __Frame__->R9  = Context->R9;
    __Frame__->R10 = Context->R10;
    __Frame__->R11 = Context->R11;
    __Frame__->R12 = Context->R12;
    __Frame__->R13 = Context->R13;
    __Frame__->R14 = Context->R14;
    __Frame__->R15 = Context->R15;

    /* Load execution state registers */
    __Frame__->Rip    = Context->Rip;
    __Frame__->Rsp    = Context->Rsp;
    __Frame__->Rflags = Context->Rflags;
    __Frame__->Cs     = Context->Cs;
    __Frame__->Ss     = Context->Ss;
}

void
Schedule(uint32_t __CpuId__, InterruptFrame* __Frame__)
{
    if (__CpuId__ >= MaxCPUs || !__Frame__)
    {
        return;
    }

    CpuScheduler* Scheduler  = &CpuSchedulers[__CpuId__];
    Thread*       Current    = Scheduler->CurrentThread;
    Thread*       NextThread = NULL;

    /* Update scheduler tick counters */
    __atomic_fetch_add(&Scheduler->ScheduleTicks, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Scheduler->LastSchedule, GetSystemTicks(), __ATOMIC_SEQ_CST);

    /* If there is a currently running thread */
    if (Current)
    {
        /*FPU*/
        ThreadFxSave(Current->Context.FpuState);

        /* Save current thread's CPU context */
        SaveInterruptFrameToThread(Current, __Frame__);
        __atomic_fetch_add(&Current->CpuTime, 1, __ATOMIC_SEQ_CST);

        /* Handle current thread's state transitions */
        switch (Current->State)
        {
            case ThreadStateRunning:
                /* Thread was preempted normally, add it back to ready queue */
                AddThreadToReadyQueue(__CpuId__, Current);
                break;

            case ThreadStateTerminated:
                /* Thread has finished, move it to zombie queue */
                AddThreadToZombieQueue(__CpuId__, Current);
                break;

            case ThreadStateBlocked:
                /* Thread is waiting for I/O or resource, move to waiting queue */
                AddThreadToWaitingQueue(__CpuId__, Current);
                break;

            case ThreadStateSleeping:
                /* Thread is sleeping, add it to sleeping queue */
                AddThreadToSleepingQueue(__CpuId__, Current);
                break;

            case ThreadStateReady:
                /* Thread yielded CPU voluntarily, add back to ready queue */
                AddThreadToReadyQueue(__CpuId__, Current);
                break;

            default:
                /* Unknown state, safeguard by marking ready and enqueue */
                Current->State = ThreadStateReady;
                AddThreadToReadyQueue(__CpuId__, Current);
                break;
        }
    }

SelectAgain:
    /* Attempt to wake up any sleeping threads whose timeout expired */
    WakeupSleepingThreads(__CpuId__);

    /* Cleanup any zombie threads */
    CleanupZombieThreads(__CpuId__);

    /* Select next thread from ready queue */
    NextThread = RemoveThreadFromReadyQueue(__CpuId__);

    /* If no ready thread exists, CPU is idle */
    if (!NextThread)
    {
        Scheduler->CurrentThread = NULL;
        __atomic_fetch_add(&Scheduler->IdleTicks, 1, __ATOMIC_SEQ_CST);
        return;
    }

    /* Override code segment and stack segment selectors based on thread type */
    if (NextThread->Type == ThreadTypeUser)
    {
        NextThread->Context.Cs = UserCodeSelector;
        NextThread->Context.Ss = UserDataSelector;
    }
    else
    {
        NextThread->Context.Cs = KernelCodeSelector;
        NextThread->Context.Ss = KernelDataSelector;
    }

    /* Determine frequency stride based on thread priority */
    uint32_t Stride = 1;
    switch (NextThread->Priority)
    {
        case ThreadPrioritykernel:
            Stride = 1;
            break; /* Kernel threads run constantly */
        case ThreadPrioritySuper:
            Stride = 2;
            break;
        case ThreadPriorityUltra:
            Stride = 4;
            break;
        case ThreadPriorityHigh:
            Stride = 8;
            break;
        case ThreadPriorityNormal:
            Stride = 16;
            break;
        case ThreadPriorityLow:
            Stride = 32;
            break;
        case ThreadPriorityIdle:
            Stride = 64;
            break;

        default:
            Stride = 16;
            break; /* Default to normal priority */
    }

    /* Frequency scheduling cooldown to prevent over-scheduling lower priority threads */
    if (__atomic_load_n(&NextThread->Cooldown, __ATOMIC_SEQ_CST) > 0)
    {
        /* Thread is cooling down, decrement cooldown counter */
        __atomic_fetch_sub(&NextThread->Cooldown, 1, __ATOMIC_SEQ_CST);

        /* Reinsert thread at end of ready queue */
        AddThreadToReadyQueue(__CpuId__, NextThread);

        /* Select another thread to run */
        goto SelectAgain;
    }
    else
    {
        /* Thread is ready, reset cooldown count */
        __atomic_store_n(&NextThread->Cooldown, Stride - 1, __ATOMIC_SEQ_CST);
    }

    /* Set the selected thread as current running and update state */
    Scheduler->CurrentThread = NextThread;
    NextThread->State        = ThreadStateRunning;
    NextThread->LastCpu      = __CpuId__;
    __atomic_store_n(&NextThread->StartTime, GetSystemTicks(), __ATOMIC_SEQ_CST);

    /* Update context switch statistics */
    __atomic_fetch_add(&Scheduler->ContextSwitches, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&NextThread->ContextSwitches, 1, __ATOMIC_SEQ_CST);

    /* Load the next thread's saved context into the interrupt frame */
    LoadThreadContextToInterruptFrame(NextThread, __Frame__);

    /* Update current thread reference for the CPU */
    SetCurrentThread(__CpuId__, NextThread);
}

void
DumpCpuSchedulerInfo(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return;
    }

    CpuScheduler* Scheduler = &CpuSchedulers[__CpuId__];

    PInfo("CPU %u Scheduler:\n", __CpuId__);
    PInfo("  Threads: %u, Ready: %u\n",
          __atomic_load_n(&Scheduler->ThreadCount, __ATOMIC_SEQ_CST),
          __atomic_load_n(&Scheduler->ReadyCount, __ATOMIC_SEQ_CST));
    PInfo("  Context Switches: %llu\n",
          __atomic_load_n(&Scheduler->ContextSwitches, __ATOMIC_SEQ_CST));
    PInfo("  Current Thread: %u\n",
          Scheduler->CurrentThread ? Scheduler->CurrentThread->ThreadId : 0);
}

void
DumpAllSchedulers(void)
{
    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        DumpCpuSchedulerInfo(CpuIndex);
    }
}

Thread*
GetNextThread(uint32_t __CpuId__)
{
    return RemoveThreadFromReadyQueue(__CpuId__);
}

void
InitializeScheduler(void)
{
    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        InitializeCpuScheduler(CpuIndex);
    }

    PSuccess("Scheduler initialized for %u CPUs\n", Smp.CpuCount);
}