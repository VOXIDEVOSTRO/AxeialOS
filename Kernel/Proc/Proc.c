#include <AllTypes.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <POSIXFd.h>
#include <POSIXProc.h>
#include <POSIXProcFS.h>
#include <POSIXSignals.h>
#include <String.h>
#include <Sync.h>
#include <Timer.h>
#include <VFS.h>
#include <VMM.h>
#include <VirtBin.h>

#define __attribute_unused__ __attribute__((unused))

#define MaxProcs      32768
#define MaxFdsDefault 256
#define MaxPathLen    256
#define DefaultUmask  022

#define TZombie 1
#define TAlive  0

#define RlimitMaxRss (64ULL * 1024ULL * 1024ULL)

static long    __NextPid__ = 1;
PosixProcTable PosixProcs  = {0};

static PosixProc* __AllocProc__(void);
static void       __FreeProc__(PosixProc* __Proc__);
static int        __AttachThread__(PosixProc* __Proc__, Thread* __Th__);
static int        __DetachThread__(PosixProc* __Proc__);
/*static int __CloneSpace__(VirtualMemorySpace*  __Src__,
                                               VirtualMemorySpace** __Out__);*/
static int  __ForkCopyFds__(PosixProc* __Parent__, PosixProc* __Child__);
static int  __SetDefaultFds__(PosixProc* __Proc__);
static int  __BuildArgsEnv__(const char* const* __Argv__,
                             const char* const* __Envp__,
                             const char*        __Path__,
                             PosixProc*         __Proc__);
static int  __PopulateTimesStart__(PosixProc* __Proc__);
static int  __UpdateTimesOnExit__(PosixProc* __Proc__);
static int  __CreateTableIfNeeded__(void);
static int  __TableInsert__(PosixProc* __Proc__);
static int  __TableRemove__(PosixProc* __Proc__);
static long __FindFreePid__(void);
static int  __ResolveExecFile__(const char* __Path__, File** __OutFile__);
static int  __EnsureCwdRoot__(PosixProc* __Proc__);

static void __WakeParent__(PosixProc* __Parent__, PosixProc* __Child__);
static int  __DeliverPendingSignals__(PosixProc* __Proc__);

static inline long
__Min__(long a, long IdxUal)
{
    return a < IdxUal ? a : IdxUal;
}

char
__ProcStateCode__(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        return 'X';
    } /* dead/invalid */
    if (__Proc__->Zombie)
    {
        return 'Z';
    } /* zombie */

    Thread* T = __Proc__->MainThread;
    if (!T)
    {
        return 'X';
    }

    switch (T->State)
    {
        case ThreadStateRunning:
            return 'R'; /* running */
        case ThreadStateReady:
            return 'R'; /* runnable */
        case ThreadStateSleeping:
            return 'S'; /* sleeping */
        case ThreadStateBlocked:
            return 'D'; /* uninterruptible (I/O) */
        case ThreadStateZombie:
            return 'Z';
        case ThreadStateTerminated:
            return 'X'; /* dead */
        default:
            return 'I'; /* idle/unknown */
    }
}

static PosixProc*
__CurrentProc__(void)
{
    uint32_t CPU  = GetCurrentCpuId();
    Thread*  Thrd = GetCurrentThread(CPU);
    if (!Thrd)
    {
        return NULL;
    }
    return PosixFind((long)Thrd->ProcessId);
}

PosixProc*
PosixProcCreate(void)
{
    if (__CreateTableIfNeeded__() != 0)
    {
        PError("PosixProcCreate: table init failed\n");
        return NULL;
    }

    PosixProc* Proc = __AllocProc__();
    if (!Proc)
    {
        PError("PosixProcCreate: alloc failed\n");
        return NULL;
    }

    Proc->Pid = __FindFreePid__();
    if (Proc->Pid <= 0)
    {
        __FreeProc__(Proc);
        PError("PosixProcCreate: pid alloc failed\n");
        return NULL;
    }

    Proc->Ppid = 0; /*set later*/
    Proc->Pgrp = Proc->Pid;
    Proc->Sid  = Proc->Pid;

    Proc->Cred.Ruid  = 0;
    Proc->Cred.Euid  = 0;
    Proc->Cred.Suid  = 0;
    Proc->Cred.Rgid  = 0;
    Proc->Cred.Egid  = 0;
    Proc->Cred.Sgid  = 0;
    Proc->Cred.Umask = DefaultUmask;

    StringCopy(Proc->Cwd, "/", MaxPathLen);
    StringCopy(Proc->Root, "/", MaxPathLen);

    if (__SetDefaultFds__(Proc) != 0)
    {
        __FreeProc__(Proc);
        PError("PosixProcCreate: default FDs failed\n");
        return NULL;
    }

    Proc->Space = VirtCreateSpace();
    if (!Proc->Space)
    {
        __FreeProc__(Proc);
        PError("PosixProcCreate: space create failed\n");
        return NULL;
    }

    PDebug("Allocated At: %llx\n", (unsigned long long)Proc->Space->PhysicalBase);

    __PopulateTimesStart__(Proc);

    if (__TableInsert__(Proc) != 0)
    {
        __FreeProc__(Proc);
        PError("PosixProcCreate: table insert failed\n");
        return NULL;
    }

    /* Mirror into /proc */
    ProcFsNotifyProcAdded(Proc);

    PSuccess("PosixProcCreate: PID=%ld\n", Proc->Pid);
    return Proc;
}

int
PosixProcExecve(PosixProc*         __Proc__,
                const char*        __Path__,
                const char* const* __Argv__,
                const char* const* __Envp__)
{
    if (!__Proc__ || !__Path__ || __Path__[0] == '\0')
    {
        PError("Execve: bad args\n");
        return -1;
    }

    File* F = NULL;
    if (__ResolveExecFile__(__Path__, &F) != 0 || !F)
    {
        PError("Execve: resolve failed '%s'\n", __Path__);
        return -1;
    }

    /*Select the loader*/
    const DynLoader* Loader = DynLoaderSelect(F);
    if (!Loader)
    {
        VfsClose(F);
        PError("Execve: no loader for '%s'\n", __Path__);
        return -1;
    }

    if (!__Proc__->Space || __Proc__->Space->PhysicalBase == 0)
    {
        VfsClose(F);
        PError("Execve: invalid space\n");
        return -1;
    }

    VirtImage Img = {0};
    Img.Space     = __Proc__->Space;

    VirtRequest Req = {.Path = __Path__, .File = F, .Argv = __Argv__, .Envp = __Envp__, .Hints = 0};
    if (VirtLoad(&Req, &Img) != 0)
    {
        VfsClose(F);
        PError("Execve: VirtLoad failed '%s'\n", __Path__);
        return -1;
    }

    /*TODO: Make commit do something probably*/
    if (VirtCommit(&Img) != 0)
    {
        VfsClose(F);
        PError("Execve: VirtCommit failed '%s'\n", __Path__);
        return -1;
    }

    /* Build Comm/cmdline/environ buffers */
    if (__BuildArgsEnv__(__Argv__, __Envp__, __Path__, __Proc__) != 0)
    {
        VfsClose(F);
        PError("Execve: BuildArgsEnv failed\n");
        return -1;
    }

    VfsClose(F);

    uint64_t UserSp = 0;
    if (VirtSetupStack(__Proc__->Space, __Argv__, __Envp__, /*Nx*/ 1, &UserSp) == 0)
    {
        PError("Execve: VirtSetupStack failed\n");
        return -1;
    }

    if (!__Proc__->MainThread)
    {
        Thread* Th = CreateThread(ThreadTypeUser, (void*)Img.Entry, NULL, ThreadPrioritykernel);
        if (!Th)
        {
            PError("Execve: thread create failed\n");
            return -1;
        }

        Th->Context.Rip   = Img.Entry;
        Th->Context.Rsp   = UserSp;
        Th->Type          = ThreadTypeUser;
        Th->State         = ThreadStateReady;
        Th->PageDirectory = (uint64_t)__Proc__->Space->PhysicalBase;
        Th->ProcessId     = __Proc__->Pid;

        if (__AttachThread__(__Proc__, Th) != 0)
        {
            DestroyThread(Th);
            PError("Execve: attach thread failed\n");
            return -1;
        }

        PDebug("Execve: Thread RIP=0x%llx RSP=0x%llx PD=0x%llx\n",
               (unsigned long long)Th->Context.Rip,
               (unsigned long long)Th->Context.Rsp,
               (unsigned long long)Th->PageDirectory);
    }
    else
    {
        Thread* Th = __Proc__->MainThread;
        /* thread is in a reusable state */
        if (Th->State == ThreadStateTerminated || Th->State == ThreadStateZombie)
        {
            PError("Execve: main thread not reusable\n");
            return -1;
        }

        Th->Context.Rip   = Img.Entry;
        Th->Context.Rsp   = UserSp;
        Th->Type          = ThreadTypeUser;
        Th->State         = ThreadStateReady;
        Th->PageDirectory = (uint64_t)__Proc__->Space->PhysicalBase;
        Th->ProcessId     = __Proc__->Pid;

        PDebug("Execve: Thread RIP=0x%llx RSP=0x%llx PD=0x%llx\n",
               (unsigned long long)Th->Context.Rip,
               (unsigned long long)Th->Context.Rsp,
               (unsigned long long)Th->PageDirectory);
    }

    /* Reset process status */
    __Proc__->Zombie   = 0;
    __Proc__->ExitCode = 0;

    PSuccess("Execve: PID=%ld '%s'\n", __Proc__->Pid, __Path__);

    ThreadExecute(__Proc__->MainThread);
    return 0;
}

static inline int
__IsUserVa__(uint64_t __Va__)
{
    return (__Va__ >= UserVirtualBase) && (__Va__ < KernelVirtualBase);
}

long
PosixFork(PosixProc* __Parent__, PosixProc** __OutChild__)
{
    if (!__Parent__ || !__OutChild__ || !__Parent__->MainThread || !__Parent__->Space)
    {
        PError("Fork: bad args/state\n");
        return -1;
    }

    uint64_t __ParentRip__ = __Parent__->MainThread->Context.Rip;
    uint64_t __ParentRsp__ = __Parent__->MainThread->Context.Rsp;
    if (!__IsUserVa__(__ParentRip__) || !__IsUserVa__(__ParentRsp__))
    {
        PError("Fork: parent context not user-space (rip=0x%llx rsp=0x%llx)\n",
               (unsigned long long)__ParentRip__,
               (unsigned long long)__ParentRsp__);
        return -1;
    }

    PosixProc* Child = PosixProcCreate();
    if (!Child)
    {
        PError("Fork: ProcCreate failed\n");
        return -1;
    }

    Child->Ppid = __Parent__->Pid;
    Child->Pgrp = __Parent__->Pgrp;
    Child->Sid  = __Parent__->Sid;
    Child->Cred = __Parent__->Cred;
    StringCopy(Child->Cwd, __Parent__->Cwd, MaxPathLen);
    StringCopy(Child->Root, __Parent__->Root, MaxPathLen);

    if (__ForkCopyFds__(__Parent__, Child) != 0)
    {
        PError("Fork: FDs copy failed\n");
        PosixExit(Child, -1);
        return -1;
    }

    Thread* Pth = __Parent__->MainThread;
    Thread* Cth = CreateThread(ThreadTypeUser, (void*)__ParentRip__, NULL, Pth->Priority);
    if (!Cth)
    {
        PError("Fork: CreateThread failed\n");
        PosixExit(Child, -1);
        return -1;
    }

    /* Copy parent context, adjust for child */
    Cth->Context        = Pth->Context;
    Cth->Context.Rax    = 0; /* fork return value in child */
    Cth->Context.Rip    = __ParentRip__;
    Cth->Context.Rsp    = __ParentRsp__;
    Cth->Context.Cs     = 0x23;
    Cth->Context.Ss     = 0x1b;
    Cth->Context.Rflags = 0x202;
    Cth->Type           = ThreadTypeUser;
    Cth->State          = ThreadStateReady;
    Cth->PageDirectory  = (uint64_t)Child->Space->PhysicalBase;
    Cth->ProcessId      = (uint32_t)Child->Pid;

    /* More direct copy
        TODO: Probably add COW(Copy On Write)
        Which is way more efficient */
    uint64_t* __Pml4__ = __Parent__->Space->Pml4;
    for (uint64_t l4 = 0; l4 < 512; l4++)
    {
        uint64_t __Pml4e__ = __Pml4__[l4];
        if (!(__Pml4e__ & PTEPRESENT))
        {
            continue;
        }
        uint64_t* __Pdpt__ = (uint64_t*)PhysToVirt(__Pml4e__ & ~0xFFFULL);

        for (uint64_t l3 = 0; l3 < 512; l3++)
        {
            uint64_t __Pdpte__ = __Pdpt__[l3];
            if (!(__Pdpte__ & PTEPRESENT))
            {
                continue;
            }
            if (__Pdpte__ & (1ULL << 7))
            {
                continue; /* skip huge */
            }
            uint64_t* __Pd__ = (uint64_t*)PhysToVirt(__Pdpte__ & ~0xFFFULL);

            for (uint64_t l2 = 0; l2 < 512; l2++)
            {
                uint64_t __Pde__ = __Pd__[l2];
                if (!(__Pde__ & PTEPRESENT))
                {
                    continue;
                }
                if (__Pde__ & (1ULL << 7))
                {
                    continue; /* skip huge */
                }
                uint64_t* __Pt__ = (uint64_t*)PhysToVirt(__Pde__ & ~0xFFFULL);

                for (uint64_t l1 = 0; l1 < 512; l1++)
                {
                    uint64_t __Leaf__ = __Pt__[l1];
                    if (!(__Leaf__ & PTEPRESENT) || !(__Leaf__ & PTEUSER))
                    {
                        continue;
                    }

                    uint64_t __Va__ = ((l4 << 39) | (l3 << 30) | (l2 << 21) | (l1 << 12));
                    if (!__IsUserVa__(__Va__))
                    {
                        continue;
                    }

                    uint64_t __SrcPhys__ = __Leaf__ & 0x000FFFFFFFFFF000ULL;
                    uint64_t __NewPhys__ = AllocPage();
                    if (__NewPhys__ == 0)
                    {
                        PError("Fork: AllocPage failed va=0x%llx\n", (unsigned long long)__Va__);
                        PosixExit(Child, -1);
                        return -1;
                    }

                    uint8_t* __Dst__ = (uint8_t*)PhysToVirt(__NewPhys__);
                    uint8_t* __Src__ = (uint8_t*)PhysToVirt(__SrcPhys__);
                    __builtin_memcpy(__Dst__, __Src__, (size_t)PageSize);

                    uint64_t __Flags__ =
                        __Leaf__ & (PTEWRITABLE | PTEUSER | PTEPRESENT | PTEWRITETHROUGH |
                                    PTECACHEDISABLE | PTEACCESSED | PTEDIRTY | PTENOEXECUTE);

                    VirtMapPage(Child->Space, __Va__, __NewPhys__, __Flags__);
                }
            }
        }
    }

    if (__AttachThread__(Child, Cth) != 0)
    {
        DestroyThread(Cth);
        PosixExit(Child, -1);
        return -1;
    }

    *__OutChild__ = Child;

    PDebug("Fork: child PID=%ld RIP=0x%llx RSP=0x%llx\n",
           Child->Pid,
           (unsigned long long)Cth->Context.Rip,
           (unsigned long long)Cth->Context.Rsp);

    ThreadExecute(Cth);
    return Child->Pid;
}

int
PosixExit(PosixProc* __Proc__, int __Status__)
{
    if (!__Proc__)
    {
        PError("Exit: bad proc\n");
        return -1;
    }

    __Proc__->ExitCode = __Status__;
    __Proc__->Zombie   = 1;

    __UpdateTimesOnExit__(__Proc__);

    AcquireSpinLock(&ThreadListLock);

    /* clear per-CPU current thread references */
    for (uint32_t CpuIndex = 0; CpuIndex < MaxCPUs; CpuIndex++)
    {
        Thread* Ct = CurrentThreads[CpuIndex];
        if (Ct && (long)Ct->ProcessId == __Proc__->Pid)
        {
            CurrentThreads[CpuIndex] = NULL;
        }
    }

    __DetachThread__(__Proc__);

    Thread* ThreadPtr = ThreadList;
    while (ThreadPtr)
    {
        Thread* NextThread = ThreadPtr->Next;
        if ((long)ThreadPtr->ProcessId == __Proc__->Pid)
        {
            ThreadPtr->State = ThreadStateTerminated;
            DestroyThread(ThreadPtr);
            PInfo("Exit: Destroyed ThreadId=%u of Pid=%u\n", ThreadPtr->ThreadId, __Proc__->Pid);
        }
        ThreadPtr = NextThread;
    }

    ReleaseSpinLock(&ThreadListLock);

    PosixProc* ParentProc = PosixFind(__Proc__->Ppid);
    if (ParentProc)
    {
        __WakeParent__(ParentProc, __Proc__);
    }

    PSuccess("Exit (zombie): Pid=%ld Status=%d\n", __Proc__->Pid, __Status__);
    return 0;
}

long
PosixWait4(PosixProc*   __Parent__,
           long         __Pid__,
           int*         __OutStatus__,
           int          __Options__,
           PosixRusage* __OutUsage__)
{
    if (!__Parent__)
    {
        PError("Wait4: bad parent\n");
        return -1;
    }

    long TargetPid = __Pid__;

    for (;;)
    {
        for (long I = 1; I <= MaxProcs; I++)
        {
            PosixProc* P = PosixFind(I);
            if (!P || P->Ppid != __Parent__->Pid)
            {
                continue;
            }
            if (TargetPid > 0 && P->Pid != TargetPid)
            {
                continue;
            }

            if (P->Zombie)
            {
                if (__OutStatus__)
                {
                    *__OutStatus__ = P->ExitCode;
                }
                if (__OutUsage__)
                {
                    __OutUsage__->UtimeUsec       = P->Times.UserUsec;
                    __OutUsage__->StimeUsec       = P->Times.SysUsec;
                    __OutUsage__->MaxRss          = RlimitMaxRss;
                    __OutUsage__->MinorFaults     = 0;
                    __OutUsage__->MajorFaults     = 0;
                    __OutUsage__->VoluntaryCtxt   = 0;
                    __OutUsage__->InvoluntaryCtxt = 0;
                }

                long ReapedId = P->Pid;
                ProcFsNotifyProcRemoved(P);
                __TableRemove__(P);
                __FreeProc__(P);
                PSuccess("Wait4: reaped=%ld\n", ReapedId);
                return ReapedId;
            }
        }

        if (__Options__ & WNOHANG)
        {
            return 0;
        }

        if (__Parent__->MainThread)
        {
            __Parent__->MainThread->State      = ThreadStateBlocked;
            __Parent__->MainThread->WaitReason = WaitReasonChild;
        }
        ThreadYield();
    }
}

int
PosixSetSid(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        return -1;
    }
    __Proc__->Sid  = __Proc__->Pid;
    __Proc__->Pgrp = __Proc__->Pid;
    return 0;
}

int
PosixSetPgrp(PosixProc* __Proc__, long __Pgid__)
{
    if (!__Proc__ || __Pgid__ <= 0)
    {
        return -1;
    }
    __Proc__->Pgrp = __Pgid__;
    return 0;
}

int
PosixGetPid(PosixProc* __Proc__)
{
    return __Proc__ ? (int)__Proc__->Pid : -1;
}
int
PosixGetPpid(PosixProc* __Proc__)
{
    return __Proc__ ? (int)__Proc__->Ppid : -1;
}
int
PosixGetPgrp(PosixProc* __Proc__)
{
    return __Proc__ ? (int)__Proc__->Pgrp : -1;
}
int
PosixGetSid(PosixProc* __Proc__)
{
    return __Proc__ ? (int)__Proc__->Sid : -1;
}

int
PosixChdir(PosixProc* __Proc__, const char* __Path__)
{
    if (!__Proc__ || !__Path__)
    {
        return -1;
    }
    if (!VfsIsDir(__Path__))
    {
        return -1;
    }
    StringCopy(__Proc__->Cwd, __Path__, MaxPathLen);
    return 0;
}

int
PosixFchdir(PosixProc* __Proc__, int __Fd__)
{
    if (!__Proc__ || __Fd__ < 0 || !__Proc__->Fds)
    {
        return -1;
    }

    VfsStat St = {0};
    if (PosixFstat(__Proc__->Fds, __Fd__, &St) != 0)
    {
        return -1;
    }
    if (St.Type != VNodeDIR)
    {
        return -1;
    }

    return 0;
}

int
PosixSetUmask(PosixProc* __Proc__, long __Mask__)
{
    if (!__Proc__)
    {
        return -1;
    }
    __Proc__->Cred.Umask = __Mask__ & 0777;
    return 0;
}

int
PosixGetTty(PosixProc* __Proc__, char* __Out__, long __Len__)
{
    if (!__Proc__ || !__Out__ || __Len__ <= 0)
    {
        return -1;
    }
    if (!__Proc__->TtyName)
    {
        StringCopy(__Out__, "notty", (uint32_t)__Len__);
    }
    else
    {
        StringCopy(__Out__, __Proc__->TtyName, (uint32_t)__Len__);
    }
    return 0;
}

int
PosixKill(long __Pid__, int __Sig__)
{
    PosixProc* P = PosixFind(__Pid__);
    if (!P)
    {
        return -1;
    }
    /* Enqueue signal bit */
    P->SigPending |= (1ULL << (__Sig__ & 63));
    return 0;
}

int
PosixTkill(long __Tid__, int __Sig__)
{
    /* Map TID to thread->ProcessId then call kill */
    Thread* Th = FindThreadById((uint32_t)__Tid__);
    if (!Th)
    {
        return -1;
    }
    return PosixKill((long)Th->ProcessId, __Sig__);
}

int
PosixSigaction(int __Sig__, const PosixSigAction* __Act__, PosixSigAction* __OldAct__)
{
    if (__Sig__ <= 0 || __Sig__ > 31)
    {
        PError("Sigaction: invalid signal %d\n", __Sig__);
        return -1;
    }

    PosixProc* P = __CurrentProc__();
    if (!P || !P->MainThread)
    {
        PError("Sigaction: no current process/thread\n");
        return -1;
    }

    /* Old */
    if (__OldAct__)
    {
        __OldAct__->Handler = (PosixSigHandler)P->MainThread->SignalHandlers[__Sig__];
        __OldAct__->Mask    = P->SigMask;
        __OldAct__->Flags   = 0;
    }

    /* New */
    if (__Act__)
    {
        P->MainThread->SignalHandlers[__Sig__] = (void*)__Act__->Handler;
        P->SigMask                             = __Act__->Mask;
    }

    return 0;
}

int
PosixSigprocmask(int __How__, const uint64_t* __Set__, uint64_t* __OldSet__)
{
    PosixProc* P = __CurrentProc__();
    if (!P)
    {
        return -1;
    }
    if (__OldSet__)
    {
        *__OldSet__ = P->SigMask;
    }
    if (!__Set__)
    {
        return 0;
    }

    /* 0=BLOCK, 1=UNBLOCK, 2=SETMASK */
    if (__How__ == 0)
    {
        P->SigMask |= *(__Set__);
    }
    else if (__How__ == 1)
    {
        P->SigMask &= ~(*__Set__);
    }
    else if (__How__ == 2)
    {
        P->SigMask = *(__Set__);
    }
    return 0;
}

int
PosixSigpending(uint64_t* __OutMask__)
{
    if (!__OutMask__)
    {
        return -1;
    }
    PosixProc* P = __CurrentProc__();
    if (!P)
    {
        *__OutMask__ = 0;
        return 0;
    }
    *__OutMask__ = P->SigPending;
    return 0;
}

int
PosixSigsuspend(const uint64_t* __Mask__)
{
    __attribute_unused__ const uint64_t* __unused_mask__ = __Mask__;
    /* Yield until a signal arrives */
    ThreadYield();
    return 0;
}

int
PosixSigqueue(long __Pid__, int __Sig__, int __Value__)
{
    __attribute_unused__ int __unused_value__ = __Value__;
    return PosixKill(__Pid__, __Sig__);
}

int
PosixDeliverSignals(void)
{
    for (long I = 1; I <= MaxProcs; I++)
    {
        PosixProc* P = PosixFind(I);
        if (!P)
        {
            continue;
        }
        __DeliverPendingSignals__(P);
    }
    return 0;
}

PosixProc*
PosixFind(long __Pid__)
{
    if (__Pid__ <= 0 || !PosixProcs.Items)
    {
        return NULL;
    }
    for (long I = 0; I < PosixProcs.Count; I++)
    {
        PosixProc* P = PosixProcs.Items[I];
        if (P && P->Pid == __Pid__)
        {
            return P;
        }
    }
    return NULL;
}

static int
__CreateTableIfNeeded__(void)
{
    if (PosixProcs.Items)
    {
        return 0;
    }
    PosixProcs.Cap   = MaxProcs;
    PosixProcs.Count = 0;
    PosixProcs.Items = (PosixProc**)KMalloc(sizeof(PosixProc*) * (size_t)PosixProcs.Cap);
    if (!PosixProcs.Items)
    {
        return -1;
    }
    InitializeSpinLock(&PosixProcs.Lock, "PosixProcs");
    return 0;
}

static long
__FindFreePid__(void)
{
    /* Naive monotonic PID allocation */
    long pid = __NextPid__++;
    if (pid <= 0)
    {
        pid = (__NextPid__ = 1);
    }
    return pid;
}

static int
__TableInsert__(PosixProc* __Proc__)
{
    AcquireSpinLock(&PosixProcs.Lock);
    if (PosixProcs.Count >= PosixProcs.Cap)
    {
        ReleaseSpinLock(&PosixProcs.Lock);
        return -1;
    }
    PosixProcs.Items[PosixProcs.Count++] = __Proc__;
    ReleaseSpinLock(&PosixProcs.Lock);
    return 0;
}

static int
__TableRemove__(PosixProc* __Proc__)
{
    AcquireSpinLock(&PosixProcs.Lock);
    long idx = -1;
    for (long I = 0; I < PosixProcs.Count; I++)
    {
        if (PosixProcs.Items[I] == __Proc__)
        {
            idx = I;
            break;
        }
    }
    if (idx >= 0)
    {
        PosixProcs.Items[idx]                  = PosixProcs.Items[PosixProcs.Count - 1];
        PosixProcs.Items[PosixProcs.Count - 1] = NULL;
        PosixProcs.Count--;
    }
    ReleaseSpinLock(&PosixProcs.Lock);
    return 0;
}

static PosixProc*
__AllocProc__(void)
{
    PosixProc* P = (PosixProc*)KMalloc(sizeof(PosixProc));
    if (!P)
    {
        return NULL;
    }
    memset(P, 0, sizeof(*P));
    InitializeSpinLock(&P->Lock, "proc");

    /* allocate cmdline/environ buffers */
    P->CmdlineBuf = (char*)KMalloc(4096);
    P->EnvironBuf = (char*)KMalloc(8192);
    if (!P->CmdlineBuf || !P->EnvironBuf)
    {
        if (P->CmdlineBuf)
        {
            KFree(P->CmdlineBuf);
        }
        if (P->EnvironBuf)
        {
            KFree(P->EnvironBuf);
        }
        KFree(P);
        return NULL;
    }
    P->CmdlineLen = 0;
    P->EnvironLen = 0;
    P->Comm[0]    = '\0';
    return P;
}

static void
__FreeProc__(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        return;
    }

    if (__Proc__->Fds)
    {
        for (long I = 0; I < __Proc__->Fds->Cap; I++)
        {
            PosixFd* E = &__Proc__->Fds->Entries[I];
            if (E->Fd >= 0)
            {
                PosixClose(__Proc__->Fds, (int)E->Fd);
            }
        }
        KFree(__Proc__->Fds->Entries);
        KFree(__Proc__->Fds);
        __Proc__->Fds = NULL;
    }

    if (__Proc__->CmdlineBuf)
    {
        KFree(__Proc__->CmdlineBuf);
        __Proc__->CmdlineBuf = NULL;
    }
    if (__Proc__->EnvironBuf)
    {
        KFree(__Proc__->EnvironBuf);
        __Proc__->EnvironBuf = NULL;
    }

    if (__Proc__->Space)
    {
        DestroyVirtualSpace(__Proc__->Space);
        __Proc__->Space = NULL;
    }
    KFree(__Proc__);
}

static int
__AttachThread__(PosixProc* __Proc__, Thread* __Th__)
{
    if (!__Proc__ || !__Th__)
    {
        return -1;
    }
    __Proc__->MainThread = __Th__;
    __Th__->ProcessId    = (uint32_t)__Proc__->Pid;
    __Th__->State        = ThreadStateReady;
    return 0;
}
static int
__DetachThread__(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        return -1;
    }
    Thread* Th = __Proc__->MainThread;
    if (Th)
    {
        Th->State = ThreadStateTerminated; /*Sceduler will automatically remove from ready*/
        DestroyThread(Th);
        __Proc__->MainThread = NULL;
    }
    return 0;
}

static int
__ForkCopyFds__(PosixProc* __Parent__, PosixProc* __Child__)
{
    if (!__Parent__ || !__Parent__->Fds || !__Child__)
    {
        PError("ForkFds: bad args\n");
        return -1;
    }

    __Child__->SigMask         = __Parent__->SigMask;
    __Child__->SigPending      = 0;
    __Child__->MainThread      = NULL;
    __Child__->Times.UserUsec  = 0;
    __Child__->Times.SysUsec   = 0;
    __Child__->Times.StartTick = __Parent__->Times.StartTick;

    __Child__->Fds = (PosixFdTable*)KMalloc(sizeof(PosixFdTable));
    if (!__Child__->Fds)
    {
        PError("ForkFds: table alloc failed\n");
        return -1;
    }
    if (PosixFdInit(__Child__->Fds, __Parent__->Fds->Cap) != 0)
    {
        KFree(__Child__->Fds);
        __Child__->Fds = NULL;
        PError("ForkFds: init failed\n");
        return -1;
    }

    /* Duplicate entries with refcounts */
    for (long I = 0; I < __Parent__->Fds->Cap; I++)
    {
        PosixFd* E = &__Parent__->Fds->Entries[I];
        if (E->Fd < 0)
        {
            continue;
        }

        int NewFd = __FindFreeFd__(__Child__->Fds, 0);
        if (NewFd < 0)
        {
            PError("ForkFds: no free fd\n");
            return -1;
        }

        __Child__->Fds->Entries[NewFd]    = *E;
        __Child__->Fds->Entries[NewFd].Fd = NewFd;
        __Child__->Fds->Entries[NewFd].Refcnt++;

        if (__Child__->Fds->Entries[NewFd].IsFile && __Child__->Fds->Entries[NewFd].Obj)
        {
            ((File*)__Child__->Fds->Entries[NewFd].Obj)->Refcnt++;
        }

        __Child__->Fds->Count++;
    }

    __Child__->Fds->StdinFd  = __Parent__->Fds->StdinFd;
    __Child__->Fds->StdoutFd = __Parent__->Fds->StdoutFd;
    __Child__->Fds->StderrFd = __Parent__->Fds->StderrFd;

    /* Comm, cmdline, environ (bounded copy) */
    StringCopy(__Child__->Comm, __Parent__->Comm, (uint32_t)sizeof(__Child__->Comm));

    __Child__->CmdlineLen = __Min__(__Parent__->CmdlineLen, 4096);
    __Child__->EnvironLen = __Min__(__Parent__->EnvironLen, 8192);

    if (__Child__->CmdlineLen > 0 && __Child__->CmdlineBuf && __Parent__->CmdlineBuf)
    {
        __builtin_memcpy(
            __Child__->CmdlineBuf, __Parent__->CmdlineBuf, (size_t)__Child__->CmdlineLen);
    }
    if (__Child__->EnvironLen > 0 && __Child__->EnvironBuf && __Parent__->EnvironBuf)
    {
        __builtin_memcpy(
            __Child__->EnvironBuf, __Parent__->EnvironBuf, (size_t)__Child__->EnvironLen);
    }

    return 0;
}

static int
__SetDefaultFds__(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        PError("SetDefaultFds: bad proc\n");
        return -1;
    }

    __Proc__->Fds = (PosixFdTable*)KMalloc(sizeof(PosixFdTable));
    if (!__Proc__->Fds)
    {
        PError("SetDefaultFds: alloc failed\n");
        return -1;
    }

    if (PosixFdInit(__Proc__->Fds, MaxFdsDefault) != 0)
    {
        KFree(__Proc__->Fds);
        __Proc__->Fds = NULL;
        PError("SetDefaultFds: init failed\n");
        return -1;
    }

    const char* TtyPath  = "/dev/tty0";
    const char* NullPath = "/dev/null";

    int StdinFd  = VfsExists(TtyPath) ? PosixOpen(__Proc__->Fds, TtyPath, VFlgRDONLY, 0)
                                      : PosixOpen(__Proc__->Fds, NullPath, VFlgRDONLY, 0);
    int StdoutFd = VfsExists(TtyPath) ? PosixOpen(__Proc__->Fds, TtyPath, VFlgWRONLY, 0)
                                      : PosixOpen(__Proc__->Fds, NullPath, VFlgWRONLY, 0);
    int StderrFd = VfsExists(TtyPath) ? PosixOpen(__Proc__->Fds, TtyPath, VFlgWRONLY, 0)
                                      : PosixOpen(__Proc__->Fds, NullPath, VFlgWRONLY, 0);

    if (StdinFd < 0 || StdoutFd < 0 || StderrFd < 0)
    {
        PError("SetDefaultFds: std fds open failed\n");
        return -1;
    }

    __Proc__->Fds->StdinFd  = StdinFd;
    __Proc__->Fds->StdoutFd = StdoutFd;
    __Proc__->Fds->StderrFd = StderrFd;

    if (VfsExists(TtyPath))
    {
        __Proc__->TtyFd   = StdinFd;
        __Proc__->TtyName = "tty0";
    }
    else
    {
        __Proc__->TtyFd   = -1;
        __Proc__->TtyName = NULL;
    }

    return 0;
}

static void
__Basename__(const char* __Path__, char* __Out__, long __Cap__)
{
    long        n      = (long)StringLength(__Path__);
    const char* Str    = __Path__;
    const char* IdxUal = Str;
    for (long I = 0; I < n; I++)
    {
        if (Str[I] == '/')
        {
            IdxUal = Str + I + 1;
        }
    }
    StringCopy(__Out__, IdxUal, (uint32_t)__Cap__);
}

static int
__BuildArgsEnv__(const char* const* __Argv__,
                 const char* const* __Envp__,
                 const char*        __Path__,
                 PosixProc*         __Proc__)
{
    if (!__Proc__)
    {
        return -1;
    }

    /* Comm from argv[0] if present; otherwise basename(path) */
    if (__Argv__ && __Argv__[0])
    {
        __Basename__(__Argv__[0], __Proc__->Comm, (long)sizeof(__Proc__->Comm));
    }
    else if (__Path__)
    {
        __Basename__(__Path__, __Proc__->Comm, (long)sizeof(__Proc__->Comm));
    }
    else
    {
        StringCopy(__Proc__->Comm, "unknown", (uint32_t)sizeof(__Proc__->Comm));
    }

    /* Build NUL-separated cmdline */
    __Proc__->CmdlineLen = 0;
    if (__Argv__)
    {
        long OffSec = 0;
        for (long I = 0; __Argv__[I]; I++)
        {
            const char* Str = __Argv__[I];
            long        L   = (long)StringLength(Str);
            long        Rem = 4096 - OffSec;
            if (Rem <= 1)
            {
                break;
            }
            long C = (L < (Rem - 1)) ? L : (Rem - 1);
            strncpy(__Proc__->CmdlineBuf + OffSec, Str, (size_t)C);
            OffSec += C;
            __Proc__->CmdlineBuf[OffSec++] = '\0';
        }
        __Proc__->CmdlineLen = OffSec;
        if (OffSec < 4096)
        {
            __Proc__->CmdlineBuf[OffSec++] = '\0';
            __Proc__->CmdlineLen           = OffSec;
        }
    }

    /* Build NUL-separated environ */
    __Proc__->EnvironLen = 0;
    if (__Envp__)
    {
        long OffSec = 0;
        for (long J = 0; __Envp__[J]; J++)
        {
            const char* e   = __Envp__[J];
            long        L   = (long)StringLength(e);
            long        Rem = 8192 - OffSec;
            if (Rem <= 1)
            {
                break;
            }
            long C = (L < (Rem - 1)) ? L : (Rem - 1);
            strncpy(__Proc__->EnvironBuf + OffSec, e, (size_t)C);
            OffSec += C;
            __Proc__->EnvironBuf[OffSec++] = '\0';
        }
        __Proc__->EnvironLen = OffSec;
        if (OffSec < 8192)
        {
            __Proc__->EnvironBuf[OffSec++] = '\0';
            __Proc__->EnvironLen           = OffSec;
        }
    }

    return 0;
}

static int
__PopulateTimesStart__(PosixProc* __Proc__)
{
    __Proc__->Times.UserUsec  = 0;
    __Proc__->Times.SysUsec   = 0;
    __Proc__->Times.StartTick = GetSystemTicks();
    return 0;
}

static int
__UpdateTimesOnExit__(PosixProc* __Proc__)
{
    uint64_t now = GetSystemTicks();
    uint64_t dur = (now > __Proc__->Times.StartTick) ? (now - __Proc__->Times.StartTick) : 0;
    __Proc__->Times.SysUsec += dur * 1000; /* pretend 1 tick = 1ms */
    return 0;
}

static int
__ResolveExecFile__(const char* __Path__, File** __OutFile__)
{
    if (!__Path__ || !__OutFile__)
    {
        return -1;
    }
    File* f = VfsOpen(__Path__, VFlgRDONLY);
    if (!f)
    {
        return -1;
    }
    *__OutFile__ = f;
    return 0;
}

__attribute_unused__ static int
__EnsureCwdRoot__(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        return -1;
    }
    if (__Proc__->Cwd[0] == '\0')
    {
        StringCopy(__Proc__->Cwd, "/", MaxPathLen);
    }
    if (__Proc__->Root[0] == '\0')
    {
        StringCopy(__Proc__->Root, "/", MaxPathLen);
    }
    return 0;
}

static void
__WakeParent__(PosixProc* __Parent__, PosixProc* __Child__)
{
    if (!__Parent__ || !__Child__)
    {
        return;
    }
    /* Set SIGCHLD pending on parent */
    __Parent__->SigPending |= (1ULL << (SigChld & 63));
}

static int
__DeliverPendingSignals__(PosixProc* __Proc__)
{
    if (!__Proc__)
    {
        return -1;
    }

    uint64_t pend = __Proc__->SigPending;
    if (pend == 0)
    {
        return 0;
    }

    /* mask */
    pend &= ~__Proc__->SigMask;
    if (pend == 0)
    {
        return 0;
    }

    /* SIGCONT resumes */
    if (pend & (1ULL << (SigCont & 63)))
    {
        if (__Proc__->MainThread)
        {
            __Proc__->MainThread->State = ThreadStateReady;
        }
        __Proc__->SigPending &= ~(1ULL << (SigCont & 63));
    }

    /* SIGSTOP blocks */
    if (pend & (1ULL << (SigStop & 63)))
    {
        if (__Proc__->MainThread)
        {
            __Proc__->MainThread->State      = ThreadStateBlocked;
            __Proc__->MainThread->WaitReason = WaitReasonSignal;
        }
        __Proc__->SigPending &= ~(1ULL << (SigStop & 63));
        return 0;
    }

    /* if installed and unmasked */
    for (int S = 1; S <= 31; S++)
    {
        uint64_t bit = (1ULL << (S & 63));
        if (!(pend & bit))
        {
            continue;
        }

        if (__Proc__->MainThread && __Proc__->MainThread->SignalHandlers[S])
        {
            /* x86-64 SysV ABI: first arg RDI */
            __Proc__->MainThread->Context.Rdi = (uint64_t)S;
            __Proc__->MainThread->Context.Rip = (uint64_t)__Proc__->MainThread->SignalHandlers[S];

            __Proc__->SigPending &= ~bit;
        }
    }

    /* Default terminate for TERM/KILL/INT if still pending after handler pass */
    if (__Proc__->SigPending & (1ULL << (SigTerm & 63)))
    {
        __Proc__->SigPending &= ~(1ULL << (SigTerm & 63));
        PosixExit(__Proc__, 128 + SigTerm);
        return 0;
    }
    if (__Proc__->SigPending & (1ULL << (SigKill & 63)))
    {
        __Proc__->SigPending &= ~(1ULL << (SigKill & 63));
        PosixExit(__Proc__, 128 + SigKill);
        return 0;
    }
    if (__Proc__->SigPending & (1ULL << (SigInt & 63)))
    {
        __Proc__->SigPending &= ~(1ULL << (SigInt & 63));
        PosixExit(__Proc__, 128 + SigInt);
        return 0;
    }

    /* delivered or ignored */
    __Proc__->SigPending = 0;
    return 0;
}