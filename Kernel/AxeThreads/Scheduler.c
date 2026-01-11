#include <AxeSchd.h>
#include <AxeThreads.h>
#include <IDT.h>
#include <PerCPUData.h>
#include <Sync.h>
#include <Timer.h>

/*Multilevel Feedback Queue Scheduler (sort of)*/

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

static uint32_t
FindHighestReadyPriority(CpuScheduler* __Schd__)
{
    for (uint32_t Prio = 0; Prio < PRIO_MAX; Prio++)
    {
        if (!PrioQueueIsEmpty(&__Schd__->ReadyQueues[Prio]))
        {
            return Prio;
        }
    }
    return PRIO_MAX;
}

void
AddThreadToPrioQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, uint32_t __Prio__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || !__ThreadPtr__ || __Prio__ >= PRIO_MAX)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    __atomic_store_n(&__ThreadPtr__->State, ThreadStateReady, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->LastCpu, __CpuId__, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Next, NULL, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Prev, NULL, __ATOMIC_SEQ_CST);

    PrioQueue* Q = &Schd->ReadyQueues[__Prio__];
    PrioQueuePush(Q, __ThreadPtr__);

    uint32_t Hi = __atomic_load_n(&Schd->HighestPrio, __ATOMIC_SEQ_CST);
    if (__Prio__ < Hi)
    {
        __atomic_store_n(&Schd->HighestPrio, __Prio__, __ATOMIC_SEQ_CST);
    }

    uint64_t Ctx = __atomic_load_n(&__ThreadPtr__->ContextSwitches, __ATOMIC_SEQ_CST);
    if (Ctx == 0)
    {
        __atomic_fetch_add(&Schd->ThreadCount, 1, __ATOMIC_SEQ_CST);
    }
    __atomic_fetch_add(&Schd->ReadyCount, 1, __ATOMIC_SEQ_CST);
}

void
AddThreadToReadyQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint32_t Prio = __atomic_load_n(&__ThreadPtr__->Priority, __ATOMIC_SEQ_CST);
    AddThreadToPrioQueue(__CpuId__, __ThreadPtr__, Prio, __Err__);
}

Thread*
RemoveThreadFromReadyQueue(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return Error_TO_Pointer(-BadArgs);
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    uint32_t Hi = __atomic_load_n(&Schd->HighestPrio, __ATOMIC_SEQ_CST);
    if (Hi >= PRIO_MAX || PrioQueueIsEmpty(&Schd->ReadyQueues[Hi]))
    {
        uint32_t NewHi = FindHighestReadyPriority(Schd);
        __atomic_store_n(&Schd->HighestPrio, NewHi, __ATOMIC_SEQ_CST);
        if (NewHi >= PRIO_MAX)
        {
            return Error_TO_Pointer(-Dangling);
        }
        Hi = NewHi;
    }

    PrioQueue* Q    = &Schd->ReadyQueues[Hi];
    Thread*    Thrd = PrioQueuePop(Q);

    if (!Thrd)
    {
        return Error_TO_Pointer(-Dangling);
    }

    if (PrioQueueIsEmpty(Q))
    {
        uint32_t NewHi = FindHighestReadyPriority(Schd);
        __atomic_store_n(&Schd->HighestPrio, NewHi, __ATOMIC_SEQ_CST);
    }

    uint32_t Ready = __atomic_load_n(&Schd->ReadyCount, __ATOMIC_SEQ_CST);
    if (Ready > 0)
    {
        __atomic_fetch_sub(&Schd->ReadyCount, 1, __ATOMIC_SEQ_CST);
    }

    return Thrd;
}

void
AddThreadToWaitingQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    __atomic_store_n(&__ThreadPtr__->State, ThreadStateBlocked, __ATOMIC_SEQ_CST);

    Thread* Skull = __atomic_load_n(&Schd->WaitingQueue, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Next, Skull, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Prev, NULL, __ATOMIC_SEQ_CST);
    if (Skull)
    {
        __atomic_store_n(&Skull->Prev, __ThreadPtr__, __ATOMIC_SEQ_CST);
    }
    __atomic_store_n(&Schd->WaitingQueue, __ThreadPtr__, __ATOMIC_SEQ_CST);
}

void
AddThreadToZombieQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    __atomic_store_n(&__ThreadPtr__->State, ThreadStateZombie, __ATOMIC_SEQ_CST);

    Thread* Skull = __atomic_load_n(&Schd->ZombieQueue, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Next, Skull, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Prev, NULL, __ATOMIC_SEQ_CST);
    if (Skull)
    {
        __atomic_store_n(&Skull->Prev, __ThreadPtr__, __ATOMIC_SEQ_CST);
    }
    __atomic_store_n(&Schd->ZombieQueue, __ThreadPtr__, __ATOMIC_SEQ_CST);

    __atomic_fetch_sub(&Schd->ThreadCount, 1, __ATOMIC_SEQ_CST);
}

void
AddThreadToSleepingQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    __atomic_store_n(&__ThreadPtr__->State, ThreadStateSleeping, __ATOMIC_SEQ_CST);

    Thread* Skull = __atomic_load_n(&Schd->SleepingQueue, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Next, Skull, __ATOMIC_SEQ_CST);
    __atomic_store_n(&__ThreadPtr__->Prev, NULL, __ATOMIC_SEQ_CST);
    if (Skull)
    {
        __atomic_store_n(&Skull->Prev, __ThreadPtr__, __ATOMIC_SEQ_CST);
    }
    __atomic_store_n(&Schd->SleepingQueue, __ThreadPtr__, __ATOMIC_SEQ_CST);
}

void
RemoveThreadFromAllQueues(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || !__ThreadPtr__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    for (uint32_t Prio = 0; Prio < PRIO_MAX; Prio++)
    {
        PrioQueue* Q = &Schd->ReadyQueues[Prio];
        if (!PrioQueueIsEmpty(Q))
        {
            Thread* Current = __atomic_load_n(&Q->Head, __ATOMIC_SEQ_CST);
            while (Current)
            {
                if (Current == __ThreadPtr__)
                {
                    PrioQueueRemove(Q, __ThreadPtr__, __Err__);
                    __atomic_fetch_sub(&Schd->ReadyCount, 1, __ATOMIC_SEQ_CST);
                    uint32_t Hi = __atomic_load_n(&Schd->HighestPrio, __ATOMIC_SEQ_CST);
                    if (PrioQueueIsEmpty(Q) && Prio == Hi)
                    {
                        uint32_t NewHi = FindHighestReadyPriority(Schd);
                        __atomic_store_n(&Schd->HighestPrio, NewHi, __ATOMIC_SEQ_CST);
                    }
                    return;
                }
                Current = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);
            }
        }
    }
}

void
MigrateThreadToCpu(Thread* __ThreadPtr__, uint32_t __TargetCpuId__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__ || __TargetCpuId__ >= MaxCPUs)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint32_t CurrentCpu = __atomic_load_n(&__ThreadPtr__->LastCpu, __ATOMIC_SEQ_CST);

    ThreadState ThrdSt = __atomic_load_n(&__ThreadPtr__->State, __ATOMIC_SEQ_CST);
    if (ThrdSt == ThreadStateReady)
    {
        RemoveThreadFromAllQueues(CurrentCpu, __ThreadPtr__, __Err__);
        __atomic_store_n(&__ThreadPtr__->LastCpu, __TargetCpuId__, __ATOMIC_SEQ_CST);
        AddThreadToReadyQueue(__TargetCpuId__, __ThreadPtr__, __Err__);
    }
}

uint32_t
GetCpuThreadCount(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return Nothing;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].ThreadCount, __ATOMIC_SEQ_CST);
}

uint32_t
GetCpuReadyCount(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return Nothing;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].ReadyCount, __ATOMIC_SEQ_CST);
}

uint64_t
GetCpuContextSwitches(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return Nothing;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].ContextSwitches, __ATOMIC_SEQ_CST);
}

uint32_t
GetCpuLoadAverage(uint32_t __CpuId__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        return Nothing;
    }
    return __atomic_load_n(&CpuSchedulers[__CpuId__].LoadAverage, __ATOMIC_SEQ_CST);
}

void
WakeupSleepingThreads(uint32_t __CpuId__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];
    uint64_t      Now  = GetSystemTicks();

    Thread* Current  = __atomic_load_n(&Schd->SleepingQueue, __ATOMIC_SEQ_CST);
    Thread* Previous = NULL;

    while (Current)
    {
        Thread* Next = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);

        uint64_t Wakey = __atomic_load_n(&Current->WakeupTime, __ATOMIC_SEQ_CST);
        if (Wakey && Wakey <= Now)
        {
            if (Previous)
            {
                __atomic_store_n(&Previous->Next, Next, __ATOMIC_SEQ_CST);
            }
            else
            {
                __atomic_store_n(&Schd->SleepingQueue, Next, __ATOMIC_SEQ_CST);
            }
            if (Next)
            {
                __atomic_store_n(&Next->Prev, Previous, __ATOMIC_SEQ_CST);
            }

            __atomic_store_n(&Current->WaitReason, WaitReasonNone, __ATOMIC_SEQ_CST);
            __atomic_store_n(&Current->WakeupTime, 0, __ATOMIC_SEQ_CST);
            __atomic_store_n(&Current->State, ThreadStateReady, __ATOMIC_SEQ_CST);
            __atomic_store_n(&Current->Prev, NULL, __ATOMIC_SEQ_CST);
            __atomic_store_n(&Current->Next, NULL, __ATOMIC_SEQ_CST);

            uint32_t   Prio = __atomic_load_n(&Current->Priority, __ATOMIC_SEQ_CST);
            PrioQueue* Q    = &Schd->ReadyQueues[Prio];
            PrioQueuePush(Q, Current);

            uint32_t Hi = __atomic_load_n(&Schd->HighestPrio, __ATOMIC_SEQ_CST);
            if (Prio < Hi)
            {
                __atomic_store_n(&Schd->HighestPrio, Prio, __ATOMIC_SEQ_CST);
            }

            __atomic_fetch_add(&Schd->ReadyCount, 1, __ATOMIC_SEQ_CST);
        }
        else
        {
            Previous = Current;
        }

        Current = Next;
    }
}

void
CleanupZombieThreads(uint32_t __CpuId__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    Thread* Current = __atomic_load_n(&Schd->ZombieQueue, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->ZombieQueue, NULL, __ATOMIC_SEQ_CST);

    while (Current)
    {
        Thread* Next = __atomic_load_n(&Current->Next, __ATOMIC_SEQ_CST);
        DestroyThread(Current, __Err__);
        Current = Next;
    }
}

void
InitializeCpuScheduler(uint32_t __CpuId__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    for (uint32_t Prio = 0; Prio < PRIO_MAX; Prio++)
    {
        PrioQueueInit(&Schd->ReadyQueues[Prio]);
    }

    __atomic_store_n(&Schd->WaitingQueue, NULL, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->ZombieQueue, NULL, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->SleepingQueue, NULL, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->CurrentThread, NULL, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->NextThread, NULL, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->IdleThread, NULL, __ATOMIC_SEQ_CST);

    __atomic_store_n(&Schd->ThreadCount, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->ReadyCount, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->ContextSwitches, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->IdleTicks, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->LoadAverage, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->ScheduleTicks, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->LastSchedule, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->HighestPrio, PRIO_MAX, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->Priority, PRIO_USER_NORMAL, __ATOMIC_SEQ_CST);

    InitializeSpinLock(&Schd->SchedulerLock, "CpuScheduler", __Err__);

    PDebug("CPU %u priority scheduler initialized\n", __CpuId__);
}

void
SaveInterruptFrameToThread(Thread* __ThreadPtr__, InterruptFrame* __Frame__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__ || Probe_IF_Error(__Frame__) || !__Frame__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    ThreadContext* Context = &__ThreadPtr__->Context;

    __atomic_store_n(&Context->Rax, __Frame__->Rax, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rbx, __Frame__->Rbx, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rcx, __Frame__->Rcx, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rdx, __Frame__->Rdx, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rsi, __Frame__->Rsi, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rdi, __Frame__->Rdi, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rbp, __Frame__->Rbp, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R8, __Frame__->R8, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R9, __Frame__->R9, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R10, __Frame__->R10, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R11, __Frame__->R11, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R12, __Frame__->R12, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R13, __Frame__->R13, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R14, __Frame__->R14, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->R15, __Frame__->R15, __ATOMIC_SEQ_CST);

    __atomic_store_n(&Context->Rip, __Frame__->Rip, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rsp, __Frame__->Rsp, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Rflags, __Frame__->Rflags, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Cs, __Frame__->Cs, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Context->Ss, __Frame__->Ss, __ATOMIC_SEQ_CST);
}

void
LoadThreadContextToInterruptFrame(Thread* __ThreadPtr__, InterruptFrame* __Frame__, SysErr* __Err__)
{
    if (Probe_IF_Error(__ThreadPtr__) || !__ThreadPtr__ || Probe_IF_Error(__Frame__) || !__Frame__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    uint64_t Pd = __atomic_load_n(&__ThreadPtr__->PageDirectory, __ATOMIC_SEQ_CST);
    if (Pd)
    {
        __asm__ volatile("mov %0, %%cr3" ::"r"(Pd) : "memory");
    }

    ThreadContext* Context = &__ThreadPtr__->Context;

    __atomic_store_n(
        &__Frame__->Rax, __atomic_load_n(&Context->Rax, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rbx, __atomic_load_n(&Context->Rbx, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rcx, __atomic_load_n(&Context->Rcx, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rdx, __atomic_load_n(&Context->Rdx, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rsi, __atomic_load_n(&Context->Rsi, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rdi, __atomic_load_n(&Context->Rdi, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rbp, __atomic_load_n(&Context->Rbp, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R8, __atomic_load_n(&Context->R8, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R9, __atomic_load_n(&Context->R9, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R10, __atomic_load_n(&Context->R10, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R11, __atomic_load_n(&Context->R11, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R12, __atomic_load_n(&Context->R12, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R13, __atomic_load_n(&Context->R13, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R14, __atomic_load_n(&Context->R14, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->R15, __atomic_load_n(&Context->R15, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);

    __atomic_store_n(
        &__Frame__->Rip, __atomic_load_n(&Context->Rip, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rsp, __atomic_load_n(&Context->Rsp, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Rflags, __atomic_load_n(&Context->Rflags, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Cs, __atomic_load_n(&Context->Cs, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &__Frame__->Ss, __atomic_load_n(&Context->Ss, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
}

void
Schedule(uint32_t __CpuId__, InterruptFrame* __Frame__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs || Probe_IF_Error(__Frame__) || !__Frame__)
    {
        PError("Bad Arguments to the Schedular, CPUID %u\n", __CpuId__);
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd    = &CpuSchedulers[__CpuId__];
    Thread*       Current = __atomic_load_n(&Schd->CurrentThread, __ATOMIC_SEQ_CST);

    __atomic_fetch_add(&Schd->ScheduleTicks, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Schd->LastSchedule, GetSystemTicks(), __ATOMIC_SEQ_CST);

    bool TimeSliceExpired = false;
    if (Current)
    {
        SaveInterruptFrameToThread(Current, __Frame__, __Err__);
        __atomic_fetch_add(&Current->CpuTime, 1, __ATOMIC_SEQ_CST);

        ThreadState CurThrdSt = __atomic_load_n(&Current->State, __ATOMIC_SEQ_CST);
        switch (CurThrdSt)
        {
            case ThreadStateRunning:
            case ThreadStateReady:
                {
                    __atomic_store_n(&Current->State, ThreadStateReady, __ATOMIC_SEQ_CST);

                    bool     HigherPrioReady = false;
                    uint32_t CurPrio = __atomic_load_n(&Current->Priority, __ATOMIC_SEQ_CST);
                    for (uint32_t P = 0; P < CurPrio; P++)
                    {
                        if (!PrioQueueIsEmpty(&Schd->ReadyQueues[P]))
                        {
                            HigherPrioReady = true;
                            break;
                        }
                    }

                    uint32_t TimeSl = __atomic_load_n(&Current->TimeSlice, __ATOMIC_SEQ_CST);
                    if (TimeSl > 0)
                    {
                        __atomic_fetch_sub(&Current->TimeSlice, 1, __ATOMIC_SEQ_CST);
                        uint32_t nts = __atomic_load_n(&Current->TimeSlice, __ATOMIC_SEQ_CST);
                        if (nts == 0)
                        {
                            TimeSliceExpired = true;
                        }
                    }

                    if (HigherPrioReady)
                    {
                        uint32_t Prio = CurPrio;
                        PrioQueuePush(&Schd->ReadyQueues[Prio], Current);
                        __atomic_fetch_add(&Schd->ReadyCount, 1, __ATOMIC_SEQ_CST);
                    }
                    else if (TimeSliceExpired)
                    {
                        uint32_t   Prio = CurPrio;
                        PrioQueue* Q    = &Schd->ReadyQueues[Prio];

                        if (Q->Head != Q->Tail || Q->Head != Current)
                        {
                            PrioQueuePush(&Schd->ReadyQueues[Prio], Current);
                            __atomic_fetch_add(&Schd->ReadyCount, 1, __ATOMIC_SEQ_CST);
                        }
                        __atomic_store_n(&Current->TimeSlice, DEFAULT_TIME_SLICE, __ATOMIC_SEQ_CST);
                    }
                    break;
                }
            case ThreadStateTerminated:
            case ThreadStateZombie:
                AddThreadToZombieQueue(__CpuId__, Current, __Err__);
                break;
            case ThreadStateBlocked:
                AddThreadToWaitingQueue(__CpuId__, Current, __Err__);
                break;
            case ThreadStateSleeping:
                AddThreadToSleepingQueue(__CpuId__, Current, __Err__);
                break;
            default:
                __atomic_store_n(&Current->State, ThreadStateReady, __ATOMIC_SEQ_CST);
                AddThreadToReadyQueue(__CpuId__, Current, __Err__);
                break;
        }
    }

    WakeupSleepingThreads(__CpuId__, __Err__);
    CleanupZombieThreads(__CpuId__, __Err__);

    Thread* Next = NULL;
    if (Current && __atomic_load_n(&Current->State, __ATOMIC_SEQ_CST) == ThreadStateReady)
    {
        bool     HigherPrioReady = false;
        uint32_t CurPrio         = __atomic_load_n(&Current->Priority, __ATOMIC_SEQ_CST);
        for (uint32_t P = 0; P < CurPrio; P++)
        {
            if (!PrioQueueIsEmpty(&Schd->ReadyQueues[P]))
            {
                HigherPrioReady = true;
                break;
            }
        }

        uint32_t TimeSl = __atomic_load_n(&Current->TimeSlice, __ATOMIC_SEQ_CST);
        if (!HigherPrioReady && TimeSl > 0 && !TimeSliceExpired)
        {
            Next = Current;
        }
    }

    if (!Next)
    {
        Next = RemoveThreadFromReadyQueue(__CpuId__);
    }

    if (Probe_IF_Error(Next) || !Next)
    {
        __atomic_store_n(&Schd->NextThread, NULL, __ATOMIC_SEQ_CST);
        __atomic_store_n(&Schd->CurrentThread, NULL, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(&Schd->IdleTicks, 1, __ATOMIC_SEQ_CST);
        SlotError(__Err__, -NoSuch);
        return;
    }
    else
    {
        __atomic_store_n(&Schd->NextThread, Next, __ATOMIC_SEQ_CST);
    }

    ThreadType TypeThrd = __atomic_load_n(&Next->Type, __ATOMIC_SEQ_CST);

    /*ring3*/
    if (TypeThrd == ThreadTypeUser)
    {
        __atomic_store_n(&Next->Context.Cs, UserCodeSelector, __ATOMIC_SEQ_CST);
        __atomic_store_n(&Next->Context.Ss, UserDataSelector, __ATOMIC_SEQ_CST);
    }

    /*ring0*/
    else
    {
        __atomic_store_n(&Next->Context.Cs, KernelCodeSelector, __ATOMIC_SEQ_CST);
        __atomic_store_n(&Next->Context.Ss, KernelDataSelector, __ATOMIC_SEQ_CST);
    }

    __atomic_store_n(&Next->State, ThreadStateRunning, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Next->LastCpu, __CpuId__, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Next->StartTime, GetSystemTicks(), __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&Schd->ContextSwitches, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&Next->ContextSwitches, 1, __ATOMIC_SEQ_CST);

    if (Next != Current)
    {
        LoadThreadContextToInterruptFrame(Next, __Frame__, __Err__);
    }

    SetCurrentThread(__CpuId__, Next, __Err__);
    __atomic_store_n(&Schd->CurrentThread, Next, __ATOMIC_SEQ_CST);
}

void
DumpCpuSchedulerInfo(uint32_t __CpuId__, SysErr* __Err__)
{
    if (__CpuId__ >= MaxCPUs)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    CpuScheduler* Schd = &CpuSchedulers[__CpuId__];

    PInfo("CPU %u Scheduler:\n", __CpuId__);
    PInfo("  ThreadCount     : %u\n", __atomic_load_n(&Schd->ThreadCount, __ATOMIC_SEQ_CST));
    PInfo("  ReadyCount      : %u\n", __atomic_load_n(&Schd->ReadyCount, __ATOMIC_SEQ_CST));
    PInfo("  ContextSwitches : %llu\n", __atomic_load_n(&Schd->ContextSwitches, __ATOMIC_SEQ_CST));
    PInfo("  IdleTicks       : %llu\n", __atomic_load_n(&Schd->IdleTicks, __ATOMIC_SEQ_CST));
    PInfo("  LoadAverage     : %u\n", __atomic_load_n(&Schd->LoadAverage, __ATOMIC_SEQ_CST));
    PInfo("  LastSchedule    : %llu\n", __atomic_load_n(&Schd->LastSchedule, __ATOMIC_SEQ_CST));
    PInfo("  ScheduleTicks   : %llu\n", __atomic_load_n(&Schd->ScheduleTicks, __ATOMIC_SEQ_CST));
    PInfo("  Priority        : %u\n", __atomic_load_n(&Schd->Priority, __ATOMIC_SEQ_CST));
    PInfo("  HighestPrio     : %u\n", __atomic_load_n(&Schd->HighestPrio, __ATOMIC_SEQ_CST));

    Thread* Current = __atomic_load_n(&Schd->CurrentThread, __ATOMIC_SEQ_CST);
    Thread* Nxt     = __atomic_load_n(&Schd->NextThread, __ATOMIC_SEQ_CST);
    Thread* Idle    = __atomic_load_n(&Schd->IdleThread, __ATOMIC_SEQ_CST);

    PInfo("  CurrentThread   : %u (state=%d type=%d prio=%d)\n",
          Current ? __atomic_load_n(&Current->ThreadId, __ATOMIC_SEQ_CST) : 0,
          Current ? __atomic_load_n(&Current->State, __ATOMIC_SEQ_CST) : ThreadStateUnknown,
          Current ? __atomic_load_n(&Current->Type, __ATOMIC_SEQ_CST) : ThreadTypeUnknown,
          Current ? __atomic_load_n(&Current->Priority, __ATOMIC_SEQ_CST) : 0);

    PInfo("  NextThread      : %u (state=%d type=%d prio=%d)\n",
          Nxt ? __atomic_load_n(&Nxt->ThreadId, __ATOMIC_SEQ_CST) : 0,
          Nxt ? __atomic_load_n(&Nxt->State, __ATOMIC_SEQ_CST) : ThreadStateUnknown,
          Nxt ? __atomic_load_n(&Nxt->Type, __ATOMIC_SEQ_CST) : ThreadTypeUnknown,
          Nxt ? __atomic_load_n(&Nxt->Priority, __ATOMIC_SEQ_CST) : 0);

    PInfo("  IdleThread      : %u\n",
          Idle ? __atomic_load_n(&Idle->ThreadId, __ATOMIC_SEQ_CST) : 0);

    for (uint32_t Prio = 0; Prio < PRIO_MAX; Prio++)
    {
        PrioQueue* Q = &Schd->ReadyQueues[Prio];
        if (!PrioQueueIsEmpty(Q))
        {
            Thread* Thrd = __atomic_load_n(&Q->Head, __ATOMIC_SEQ_CST);
            int     Idx  = 0;
            while (Thrd)
            {
                PInfo("    Ready[Prio=%u][%d]: tid=%u pid=%u state=%d rip=0x%llx rsp=0x%llx\n",
                      Prio,
                      Idx,
                      __atomic_load_n(&Thrd->ThreadId, __ATOMIC_SEQ_CST),
                      __atomic_load_n(&Thrd->ProcessId, __ATOMIC_SEQ_CST),
                      __atomic_load_n(&Thrd->State, __ATOMIC_SEQ_CST),
                      (unsigned long long)__atomic_load_n(&Thrd->Context.Rip, __ATOMIC_SEQ_CST),
                      (unsigned long long)__atomic_load_n(&Thrd->Context.Rsp, __ATOMIC_SEQ_CST));
                Thrd = __atomic_load_n(&Thrd->Next, __ATOMIC_SEQ_CST);
                Idx++;
            }
        }
    }
}

void
DumpAllSchedulers(SysErr* __Err__)
{
    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        DumpCpuSchedulerInfo(CpuIndex, __Err__);
    }
}

Thread*
GetNextThread(uint32_t __CpuId__)
{
    return RemoveThreadFromReadyQueue(__CpuId__);
}

void
InitializeScheduler(SysErr* __Err__)
{
    for (uint32_t CpuIndex = 0; CpuIndex < Smp.CpuCount; CpuIndex++)
    {
        InitializeCpuScheduler(CpuIndex, __Err__);
    }

    PSuccess("Scheduler initialized for %u CPUs\n", Smp.CpuCount);
}