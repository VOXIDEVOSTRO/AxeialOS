#include "KrnCommon.h"
#include <__AXEKCONF__.h>

#ifdef LOGTESTC_Debug
#    define LOGTESTC_PDebug(fmt, ...) PDebug("[KERNEL>>Test.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTESTC_PDebug(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTESTC_Logs
#    define LOGTESTC_PError(fmt, ...) PError("[KERNEL>>Test.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTESTC_PError(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTESTC_Logs
#    define LOGTESTC_PWarn(fmt, ...) PWarn("[KERNEL>>Test.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTESTC_PWarn(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTESTC_Logs
#    define LOGTESTC_PInfo(fmt, ...) PInfo("[KERNEL>>Test.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTESTC_PInfo(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTESTC_Logs
#    define LOGTESTC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Test.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTESTC_PSuccess(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

static SysErr  err;
static SysErr* Error = &err;

/*Proc test*/
void
__TEST__Proc(void)
{
    PosixProc* Proc = PosixProcCreate();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        LOGTESTC_PError("failed to create proc, errno: %d\n", Pointer_TO_Error(Proc));
        InitComplete = false;
        return;
    }

    LOGTESTC_PSuccess("Created process pid=%ld ppid=%ld\n", Proc->Pid, Proc->Ppid);

    /* Execve test */
    const char* argv[] = {"test", "test but shit", NULL};
    const char* envp[] = {NULL};
    int         Ret    = PosixProcExecve(Proc, "/Test.elf", argv, envp);
    if (Ret != SysOkay)
    {
        LOGTESTC_PError("Execve failed for pid=%ld, Errno: %d\n", Proc->Pid, Ret);
        InitComplete = false;
    }
    else
    {
        InitComplete = true;
    }
}

void
ThrdTest(void)
{
    uint32_t CPU   = GetCurrentCpuId();
    uint64_t Count = 0;
    uint32_t Step  = __SUBTEST__ItLoops;

    for (;;)
    {
#ifdef __SUBTEST__ThrdTest
        if ((Count % Step) == 0)
        {
            LOGTESTC_PDebug("Thread test, CPUID: %u, Tid: %u, LoopCount: %llu\n",
                            CPU,
                            GetCurrentThread(CPU)->ThreadId,
                            (unsigned long long)Count);
        }
#endif
        Count++;
    }
}

void
__TEST__Thrd(void)
{
    int I = 0;

    while (I < __SUBTEST__Thrd)
    {
        Thread* T = CreateThread(ThreadTypeKernel, ThrdTest, NULL, ThreadPrioritykernel);

        if (!T || Probe_IF_Error(T))
        {
            return;
        }

        uint32_t TargetCpu = (uint32_t)(I % MaxCPUs);
        SetThreadAffinity(T, (1u << (TargetCpu % 32)), NULL);

        ThreadExecute(T, Error);
        I++;
    }
}