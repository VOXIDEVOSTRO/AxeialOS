#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <SMP.h>
#include <Sync.h>
#include <VMM.h>

typedef enum
{
    ThreadStateUnknown,
    ThreadStateReady,
    ThreadStateRunning,
    ThreadStateBlocked,
    ThreadStateSleeping,
    ThreadStateZombie,
    ThreadStateTerminated,

} ThreadState;

typedef enum
{
    ThreadTypeUnknown,
    ThreadTypeKernel,
    ThreadTypeUser,

} ThreadType;

typedef enum
{
    ThreadPriorityUnknown = 0,
    ThreadPriorityIdle    = 1,
    ThreadPriorityLow     = 2,
    ThreadPriorityNormal  = 3,
    ThreadPriorityHigh    = 4,
    ThreadPriorityUltra   = 5,
    ThreadPrioritySuper   = 6,
    ThreadPrioritykernel  = 7,

} ThreadPriority;

typedef struct
{

    uint64_t Rax, Rbx, Rcx, Rdx;
    uint64_t Rsi, Rdi, Rbp, Rsp;
    uint64_t R8, R9, R10, R11;
    uint64_t R12, R13, R14, R15;

    uint64_t Rip;
    uint64_t Rflags;
    uint16_t Cs, Ss, Ds, Es, Fs, Gs;

    uint8_t FpuState[512] __attribute__((aligned(16)));

} ThreadContext;

typedef struct Thread
{

    uint32_t ThreadId;
    uint32_t ProcessId;
    char     Name[64];

    ThreadState    State;
    ThreadType     Type;
    ThreadPriority Priority;
    ThreadPriority BasePriority;

    uint32_t PriorityRaw;

    ThreadContext Context;
    uint64_t      KernelStack;
    uint64_t      UserStack;
    uint32_t      StackSize;

    uint64_t PageDirectory;
    uint64_t VirtualBase;
    uint32_t MemoryUsage;

    uint32_t CpuAffinity;
    uint32_t LastCpu;

    uint64_t CpuTime;
    uint64_t StartTime;
    uint64_t WakeupTime;

    void*    WaitingOn;
    uint32_t WaitReason;
    uint32_t ExitCode;
    uint32_t Cooldown;
    uint32_t TimeSlice;

    struct Thread* Next;
    struct Thread* Prev;
    struct Thread* Parent;
    struct Thread* Children;

    void*    FileTable[64];
    uint32_t FileCount;

    uint64_t SignalMask;
    void*    SignalHandlers[32];

    uint64_t ContextSwitches;
    uint64_t PageFaults;
    uint64_t SystemCalls;

    uint64_t CreationTick;
    uint32_t Flags;
    void*    DebugInfo;

} Thread;

#define PRIO_CRITICAL      0
#define PRIO_INTERRUPT     1
#define PRIO_IRQ           2
#define PRIO_IPI           3
#define PRIO_KERNEL_CRIT   4
#define PRIO_KERNEL_HIGH   5
#define PRIO_KERNEL_NORMAL 6
#define PRIO_KERNEL_LOW    7
#define PRIO_USER_CRITICAL 8
#define PRIO_USER_HIGH     9
#define PRIO_USER_NORMAL   10
#define PRIO_USER_LOW      11
#define PRIO_USER_BATCH    12
#define PRIO_IDLE_WORKER   13
#define PRIO_IDLE          31

#define PRIO_MAX 32

#define PRIO_IS_KERNEL(__p)   ((__p) <= 7)
#define PRIO_IS_USER(__p)     ((__p) >= 8 && (__p) <= 30)
#define PRIO_IS_CRITICAL(__p) ((__p) < 4)
#define PRIO_IS_IDLE(__p)     ((__p) == PRIO_IDLE)

#define ThreadFlagSystem    (1 << 0)
#define ThreadFlagRealtime  (1 << 1)
#define ThreadFlagPinned    (1 << 2)
#define ThreadFlagTraced    (1 << 3)
#define ThreadFlagSuspended (1 << 4)
#define ThreadFlagCritical  (1 << 5)

#define WaitReasonNone      0
#define WaitReasonMutex     1
#define WaitReasonSemaphore 2
#define WaitReasonIo        3
#define WaitReasonSleep     4
#define WaitReasonSignal    5
#define WaitReasonChild     6

#define UserVirtualBase 0x0000000000400000ULL
#define KStackSize      8192

extern uint32_t NextThreadId;
extern Thread*  ThreadList;
extern SpinLock ThreadListLock;
extern Thread*  CurrentThreads[MaxCPUs];
extern Thread*  IdleThread;

#define THREAD_PRIO_TO_RAW(__p)                                                                    \
    ((__p) == ThreadPriorityUltra    ? 0                                                           \
     : (__p) == ThreadPrioritySuper  ? 1                                                           \
     : (__p) == ThreadPrioritykernel ? 2                                                           \
     : (__p) == ThreadPriorityHigh   ? 5                                                           \
     : (__p) == ThreadPriorityNormal ? 10                                                          \
     : (__p) == ThreadPriorityLow    ? 20                                                          \
     : (__p) == ThreadPriorityIdle   ? 31                                                          \
                                     : 10)

#define RAW_PRIO_TO_THREAD_PRIO(__p)                                                               \
    ((__p) <= 1    ? ThreadPriorityUltra                                                           \
     : (__p) <= 3  ? ThreadPrioritySuper                                                           \
     : (__p) <= 4  ? ThreadPrioritykernel                                                          \
     : (__p) <= 6  ? ThreadPriorityHigh                                                            \
     : (__p) <= 12 ? ThreadPriorityNormal                                                          \
     : (__p) <= 20 ? ThreadPriorityLow                                                             \
                   : ThreadPriorityIdle)

#define PRIO_IS_KERNEL(__p) ((__p) <= 7)

#define PRIO_IS_USER(__p) ((__p) >= 8 && (__p) <= 30)

void    InitializeThreadManager(SysErr* __Err__);
Thread* GetCurrentThread(uint32_t __CpuId__);
void    SetCurrentThread(uint32_t __CpuId__, Thread* __ThreadPtr__, SysErr* __Err__);

Thread* CreateThread(ThreadType     __Type__,
                     void*          __EntryPoint__,
                     void*          __Argument__,
                     ThreadPriority __Priority__);
void    DestroyThread(Thread* __ThreadPtr__, SysErr* __Err__);
void    SuspendThread(Thread* __ThreadPtr__, SysErr* __Err__);
void    ResumeThread(Thread* __ThreadPtr__, SysErr* __Err__);

void SetThreadPriority(Thread* __ThreadPtr__, ThreadPriority __Priority__, SysErr* __Err__);

void SetThreadAffinity(Thread* __ThreadPtr__, uint32_t __CpuMask__, SysErr* __Err__);

static inline uint32_t
GetThreadRawPriority(Thread* __ThreadPtr__)
{
    return __ThreadPtr__ ? __ThreadPtr__->PriorityRaw : PRIO_USER_NORMAL;
}

void ThreadYield(SysErr* __Err__);

void ThreadSleep(uint64_t __Milliseconds__, SysErr* __Err__);

void ThreadExit(uint32_t __ExitCode__, SysErr* __Err__);

Thread*  FindThreadById(uint32_t __ThreadId__);
uint32_t GetThreadCount(void);

uint32_t GetCpuLoad(uint32_t __CpuId__);
uint32_t FindLeastLoadedCpu(void);
uint32_t CalculateOptimalCpu(Thread* __ThreadPtr__);
void     ThreadExecute(Thread* __ThreadPtr__, SysErr* __Err__);
void     ThreadExecuteMultiple(Thread** __ThreadArray__, uint32_t __ThreadCount__, SysErr* __Err__);
void     LoadBalanceThreads(SysErr* __Err__);
void     GetSystemLoadStats(uint32_t* __TotalThreads__,
                            uint32_t* __AverageLoad__,
                            uint32_t* __MaxLoad__,
                            uint32_t* __MinLoad__,
                            SysErr*   __Err__);
void     WakeSleepingThreads(SysErr* __Err__);
void     DumpThreadInfo(Thread* __ThreadPtr__, SysErr* __Err__);
void     DumpAllThreads(SysErr* __Err__);

KEXPORT(GetCurrentThread);
KEXPORT(CreateThread);
KEXPORT(DestroyThread);
KEXPORT(SuspendThread);
KEXPORT(ResumeThread);
KEXPORT(SetThreadPriority);
KEXPORT(SetThreadAffinity);
KEXPORT(ThreadYield);
KEXPORT(ThreadSleep);
KEXPORT(ThreadExit);
KEXPORT(FindThreadById);
KEXPORT(GetThreadCount);
KEXPORT(ThreadExecute);
KEXPORT(ThreadExecuteMultiple);
