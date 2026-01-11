#include "KrnCommon.h"

/*Proc test*/
void
__TEST__Proc(void)
{
    PosixProc* Proc = PosixProcCreate();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        PError("failed to create proc, errno: %d\n", Pointer_TO_Error(Proc));
        InitComplete = false;
        return;
    }

    PSuccess("Created process pid=%ld ppid=%ld\n", Proc->Pid, Proc->Ppid);

    /* Execve test */
    const char* argv[] = {"echo", "hello", NULL};
    const char* envp[] = {NULL};
    int         Ret    = PosixProcExecve(Proc, "/Test.elf", argv, envp);
    if (Ret != SysOkay)
    {
        PError("Execve failed for pid=%ld, Errno: %d\n", Proc->Pid, Ret);
        InitComplete = false;
    }
    else
    {
        InitComplete = true;
    }
}

#define __SUBTEST__Thrd                                                                            \
    1 /*change this if you wanna test absurd amount of threads (stress testing)*/

/*Uncomment if you want tracing NOTE!: enable PDebug too in KrnPrintf Header!*/
// #define __SUBTEST__ThrdTest

void
ThrdTest(void)
{
    uint32_t CPU = GetCurrentCpuId();
    for (;;)
    {
#ifdef __SUBTEST__ThrdTest
        PDebug("Thread test, CPUID: %ld, Tid: %ld\n", CPU, GetCurrentThread(CPU)->ThreadId);
#endif
    }
}

void
__TEST__Thrd(void)
{
    int     I = 0;
    SysErr  err;
    SysErr* Error = &err;

    while (I < __SUBTEST__Thrd)
    {
        Thread* T = CreateThread(ThreadTypeKernel, ThrdTest, NULL, ThreadPrioritykernel);

        if (!T || Probe_IF_Error(T))
        {
            return;
        }

        ThreadExecute(T, Error);
        I++;
    }
}
