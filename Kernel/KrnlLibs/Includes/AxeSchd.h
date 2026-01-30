#pragma once

#include <AllTypes.h>
#include <AxeThreads.h>
#include <Errnos.h>
#include <IDT.h>
#include <Sync.h>
#include <Timer.h>

#define DEFAULT_TIME_SLICE 10

typedef struct PrioQueue
{
    Thread*  Head;
    Thread*  Tail;
    uint32_t Count;
} PrioQueue;

typedef struct CpuScheduler
{

    PrioQueue ReadyQueues[PRIO_MAX];

    Thread* WaitingQueue;
    Thread* ZombieQueue;
    Thread* SleepingQueue;

    Thread* CurrentThread;
    Thread* NextThread;
    Thread* IdleThread;

    SpinLock SchedulerLock;

    uint64_t ScheduleTicks;
    uint64_t LastSchedule;
    uint64_t ContextSwitches;
    uint64_t IdleTicks;
    uint64_t LoadAverage;

    uint32_t ThreadCount;
    uint32_t ReadyCount;
    uint32_t Priority;

    uint32_t HighestPrio;

} CpuScheduler;

extern CpuScheduler CpuSchedulers[MaxCPUs];

static inline void
PrioQueueInit(PrioQueue* Q)
{
    if (!Q)
    {
        return;
    }
    Q->Head  = NULL;
    Q->Tail  = NULL;
    Q->Count = 0;
}

static inline bool
PrioQueueIsEmpty(PrioQueue* Q)
{
    return Q->Head == NULL;
}

static inline uint32_t
PrioQueueCount(PrioQueue* Q)
{
    return Q ? Q->Count : 0;
}

static inline void
PrioQueuePush(PrioQueue* Q, Thread* T)
{
    if (!Q || !T)
    {
        return;
    }

    T->Next = NULL;
    T->Prev = Q->Tail;

    if (Q->Tail)
    {
        Q->Tail->Next = T;
    }
    else
    {
        Q->Head = T;
    }

    Q->Tail = T;
    Q->Count++;
}

static inline Thread*
PrioQueuePop(PrioQueue* Q)
{
    if (!Q || !Q->Head)
    {
        return Error_TO_Pointer(-BadArguments);
    }

    Thread* T = Q->Head;
    Q->Head   = T->Next;

    if (Q->Head)
    {
        Q->Head->Prev = NULL;
    }
    else
    {
        Q->Tail = NULL;
    }

    T->Next = NULL;
    T->Prev = NULL;
    Q->Count--;

    return T;
}

static inline void
PrioQueueRemove(PrioQueue* Q, Thread* T, SysErr* __Err__)
{
    if (!Q || !T)
    {
        SlotError(__Err__, -BadArguments);
        return;
    }

    if (T->Prev)
    {
        T->Prev->Next = T->Next;
    }
    else
    {
        Q->Head = T->Next;
    }

    if (T->Next)
    {
        T->Next->Prev = T->Prev;
    }
    else
    {
        Q->Tail = T->Prev;
    }

    T->Next = NULL;
    T->Prev = NULL;
    Q->Count--;
}

void AddThreadToReadyQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__);

void
AddThreadToPrioQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, uint32_t __Prio__, SysErr* __Err__);

Thread* RemoveThreadFromReadyQueue(uint32_t __CpuId__);

void AddThreadToWaitingQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__);

void AddThreadToZombieQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__);

void AddThreadToSleepingQueue(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__);

void RemoveThreadFromAllQueues(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__);

void Schedule(uint32_t __CpuId__, InterruptFrame* __Frame__, SysErr* __Err__);

void WakeupSleepingThreads(uint32_t __CpuId__, SysErr* __Err__);

void CleanupZombieThreads(uint32_t __CpuId__, SysErr* __Err__);

void InitializeCpuScheduler(uint32_t __CpuId__, SysErr* __Err__);

void InitializeScheduler(SysErr* __Err__);

Thread* GetNextThread(uint32_t __CpuId__);

uint32_t GetCpuReadyCount(uint32_t __CpuId__);

uint32_t GetCpuThreadCount(uint32_t __CpuId__);

uint64_t GetCpuContextSwitches(uint32_t __CpuId__);

uint32_t GetCpuLoadAverage(uint32_t __CpuId__);

uint32_t GetCpuLoad(uint32_t __CpuId__);

uint32_t FindLeastLoadedCpu(void);

uint32_t CalculateOptimalCpu(Thread* __ThreadPtr__);

void MigrateThreadToCpu(Thread* __ThreadPtr__, uint32_t __TargetCpuId__, SysErr* __Err__);

void DumpCpuSchedulerInfo(uint32_t __CpuId__, SysErr* __Err__);

void DumpAllSchedulers(SysErr* __Err__);

void SaveInterruptFrameToThread(Thread* __ThreadPtr__, InterruptFrame* __Frame__, SysErr* __Err__);

void LoadThreadContextToInterruptFrame(Thread*         __ThreadPtr__,
                                       InterruptFrame* __Frame__,
                                       SysErr*         __Err__);

void SpawnIdleThreadCPU(uint32_t __CpuId__, SysErr* __Err__);

KEXPORT(GetNextThread);
KEXPORT(GetCpuReadyCount);
KEXPORT(GetCpuThreadCount);
KEXPORT(GetCpuContextSwitches);
KEXPORT(GetCpuLoadAverage);
KEXPORT(GetCpuLoad);

KEXPORT(FindLeastLoadedCpu);
KEXPORT(CalculateOptimalCpu);

KEXPORT(MigrateThreadToCpu);