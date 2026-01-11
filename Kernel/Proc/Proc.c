#include <AllTypes.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <ELFL.h>
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

#define __attribute_unused__ __attribute__((unused))

#define MaxProcs      32768
#define MaxFdsDefault 256
#define MaxPathLen    256
#define DefaultUmask  022

#define TZombie 1
#define TAlive  0

#define RlimitMaxRss (64ULL * 1024ULL * 1024ULL)

/* Atomic helpers for clarity */
#define ATOMIC_LOAD(ptr)           atomic_load(&(ptr))
#define ATOMIC_STORE(ptr, val)     atomic_store(&(ptr), (val))
#define ATOMIC_FETCH_ADD(ptr, val) atomic_fetch_add(&(ptr), (val))
#define ATOMIC_FETCH_SUB(ptr, val) atomic_fetch_sub(&(ptr), (val))
#define ATOMIC_FETCH_OR(ptr, val)  atomic_fetch_or(&(ptr), (val))
#define ATOMIC_FETCH_AND(ptr, val) atomic_fetch_and(&(ptr), (val))
#define ATOMIC_EXCHANGE(ptr, val)  atomic_exchange(&(ptr), (val))

static _Atomic long __NextPid__ = 1;
PosixProcTable      PosixProcs  = {0};

static PosixProc* __AllocProc__(void);
static void       __FreeProc__(PosixProc* __Proc__, SysErr* __Err__);
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

static void __WakeParent__(PosixProc* __Parent__, PosixProc* __Child__, SysErr* __Err__);
static int  __DeliverPendingSignals__(PosixProc* __Proc__);

static inline long
__Min__(long a, long IdxUal)
{
    return a < IdxUal ? a : IdxUal;
}

char
__ProcStateCode__(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return 'X';
    } /* dead/invalid */
    if (ATOMIC_LOAD(__Proc__->Zombie))
    {
        return 'Z';
    } /* zombie */

    Thread* T = __Proc__->MainThread;
    if (Probe_IF_Error(T) || !T)
    {
        return 'X';
    }

    switch (ATOMIC_LOAD(T->State))
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
    if (Probe_IF_Error(Thrd) || !Thrd)
    {
        return Error_TO_Pointer(-BadEntity);
    }
    return PosixFind((long)ATOMIC_LOAD(Thrd->ProcessId));
}

PosixProc*
PosixProcCreate(void)
{
    SysErr  err;
    SysErr* Error = &err;
    if (__CreateTableIfNeeded__() != SysOkay)
    {
        return Error_TO_Pointer(-NoSuch);
    }

    PosixProc* Proc = __AllocProc__();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        return Error_TO_Pointer(-BadAlloc);
    }

    Proc->Pid = __FindFreePid__();
    if (Proc->Pid <= 0)
    {
        __FreeProc__(Proc, Error);
        return Error_TO_Pointer(-Depleted);
    }

    Proc->Ppid = 0; /*set later*/
    Proc->Pgrp = Proc->Pid;
    Proc->Sid  = Proc->Pid;

    ATOMIC_STORE(Proc->Cred.Ruid, 0);
    ATOMIC_STORE(Proc->Cred.Euid, 0);
    ATOMIC_STORE(Proc->Cred.Suid, 0);
    ATOMIC_STORE(Proc->Cred.Rgid, 0);
    ATOMIC_STORE(Proc->Cred.Egid, 0);
    ATOMIC_STORE(Proc->Cred.Sgid, 0);
    ATOMIC_STORE(Proc->Cred.Umask, DefaultUmask);

    strcpy(Proc->Cwd, "/", MaxPathLen);
    strcpy(Proc->Root, "/", MaxPathLen);

    if (__SetDefaultFds__(Proc) != SysOkay)
    {
        __FreeProc__(Proc, Error);
        return Error_TO_Pointer(-NotInit);
    }

    Proc->Space = CreateVirtualSpace();
    if (Probe_IF_Error(Proc->Space) || !Proc->Space)
    {
        __FreeProc__(Proc, Error);
        return Error_TO_Pointer(-NotCanonical);
    }

    PDebug("Allocated At: %llx\n", (unsigned long long)Proc->Space->PhysicalBase);

    __PopulateTimesStart__(Proc);

    if (__TableInsert__(Proc) != SysOkay)
    {
        __FreeProc__(Proc, Error);
        return Error_TO_Pointer(-ErrReturn);
    }

    /* Mirror into /proc */
    ProcFsNotifyProcAdded(Proc);

    PSuccess("New Processes with PID=%ld\n", Proc->Pid);
    return Proc;
}

int
PosixProcExecve(PosixProc*         __Proc__,
                const char*        __Path__,
                const char* const* __Argv__,
                const char* const* __Envp__)
{
    SysErr  err;
    SysErr* Error = &err;

    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Path__) || !__Path__ ||
        __Path__[0] == '\0')
    {
        return -BadArgs;
    }

    File* F = NULL;
    if (__ResolveExecFile__(__Path__, &F) != SysOkay || !F)
    {
        return -NoSuch;
    }

    if (Probe_IF_Error(__Proc__->Space) || !__Proc__->Space || __Proc__->Space->PhysicalBase == 0)
    {
        VfsClose(F);
        return -NotCanonical;
    }

    ELFImage Img = {0};
    Img.Space    = __Proc__->Space;

    if (Elf64Load(F, __Proc__->Space, &Img) != SysOkay)
    {
        VfsClose(F);
        return -ErrReturn;
    }

    /* Build Comm/cmdline/environ buffers */
    if (__BuildArgsEnv__(__Argv__, __Envp__, __Path__, __Proc__) != SysOkay)
    {
        VfsClose(F);
        return -ErrReturn;
    }

    VfsClose(F);

    uint64_t UserSp = 0;
    if (SetStack(__Proc__->Space, __Argv__, __Envp__, /*Nx*/ 1, &UserSp) == Nothing)
    {
        return -ErrReturn;
    }

    if (Probe_IF_Error(__Proc__->MainThread) || !__Proc__->MainThread)
    {
        Thread* Th = CreateThread(ThreadTypeUser, (void*)Img.Entry, NULL, ThreadPriorityNormal);
        if (Probe_IF_Error(Th) || !Th)
        {
            return -BadEntity;
        }

        ATOMIC_STORE(Th->Context.Rip, Img.Entry);
        ATOMIC_STORE(Th->Context.Rsp, UserSp);
        ATOMIC_STORE(Th->Type, ThreadTypeUser);
        ATOMIC_STORE(Th->State, ThreadStateReady);
        ATOMIC_STORE(Th->PageDirectory, (uint64_t)__Proc__->Space->PhysicalBase);
        ATOMIC_STORE(Th->ProcessId, __Proc__->Pid);

        if (__AttachThread__(__Proc__, Th) != SysOkay)
        {
            DestroyThread(Th, Error);
            return -NotInit;
        }

        PDebug("Thread RIP=0x%llx RSP=0x%llx PD=0x%llx\n",
               (unsigned long long)ATOMIC_LOAD(Th->Context.Rip),
               (unsigned long long)ATOMIC_LOAD(Th->Context.Rsp),
               (unsigned long long)ATOMIC_LOAD(Th->PageDirectory));
    }
    else
    {
        Thread* Th = __Proc__->MainThread;
        /* thread is in a reusable state */
        if (ATOMIC_LOAD(Th->State) == ThreadStateTerminated ||
            ATOMIC_LOAD(Th->State) == ThreadStateZombie)
        {
            return -Dangling;
        }

        ATOMIC_STORE(Th->Context.Rip, Img.Entry);
        ATOMIC_STORE(Th->Context.Rsp, UserSp);
        ATOMIC_STORE(Th->Type, ThreadTypeUser);
        ATOMIC_STORE(Th->State, ThreadStateReady);
        ATOMIC_STORE(Th->PageDirectory, (uint64_t)__Proc__->Space->PhysicalBase);
        ATOMIC_STORE(Th->ProcessId, __Proc__->Pid);

        PDebug("Thread RIP=0x%llx RSP=0x%llx PD=0x%llx\n",
               (unsigned long long)ATOMIC_LOAD(Th->Context.Rip),
               (unsigned long long)ATOMIC_LOAD(Th->Context.Rsp),
               (unsigned long long)ATOMIC_LOAD(Th->PageDirectory));
    }

    /* Reset process status */
    ATOMIC_STORE(__Proc__->Zombie, 0);
    ATOMIC_STORE(__Proc__->ExitCode, 0);

    PSuccess("New Process executed with PID=%ld '%s'\n", __Proc__->Pid, __Path__);
    ThreadExecute(__Proc__->MainThread, Error);
    return SysOkay;
}

static inline int
__IsUserVa__(uint64_t __Va__)
{
    return (__Va__ >= UserVirtualBase) && (__Va__ < KernelVirtualBase);
}

long
PosixFork(PosixProc* __Parent__, PosixProc** __OutChild__)
{
    if (Probe_IF_Error(__Parent__) || !__Parent__ || Probe_IF_Error(__OutChild__) ||
        !__OutChild__ || Probe_IF_Error(__Parent__->MainThread) || !__Parent__->MainThread ||
        Probe_IF_Error(__Parent__->Space) || !__Parent__->Space)
    {
        return -BadArgs;
    }

    uint64_t __ParentRip__ = ATOMIC_LOAD(__Parent__->MainThread->Context.Rip);
    uint64_t __ParentRsp__ = ATOMIC_LOAD(__Parent__->MainThread->Context.Rsp);
    if (!__IsUserVa__(__ParentRip__) || !__IsUserVa__(__ParentRsp__))
    {
        return -NotCanonical;
    }

    PosixProc* Child = PosixProcCreate();
    if (Probe_IF_Error(Child) || !Child)
    {
        return -BadEntity;
    }

    Child->Ppid = __Parent__->Pid;
    Child->Pgrp = __Parent__->Pgrp;
    Child->Sid  = __Parent__->Sid;
    Child->Cred = __Parent__->Cred;
    strcpy(Child->Cwd, __Parent__->Cwd, MaxPathLen);
    strcpy(Child->Root, __Parent__->Root, MaxPathLen);

    if (__ForkCopyFds__(__Parent__, Child) != SysOkay)
    {
        PosixExit(Child, -1);
        return -ErrReturn;
    }

    Thread* Pth = __Parent__->MainThread;
    Thread* Cth =
        CreateThread(ThreadTypeUser, (void*)__ParentRip__, NULL, ATOMIC_LOAD(Pth->Priority));
    if (Probe_IF_Error(Cth) || !Cth)
    {
        PosixExit(Child, -1);
        return -BadEntity;
    }

    /* Copy parent context, adjust for child */
    Cth->Context = Pth->Context;
    ATOMIC_STORE(Cth->Context.Rax, 0); /* fork return value in child */
    ATOMIC_STORE(Cth->Context.Rip, __ParentRip__);
    ATOMIC_STORE(Cth->Context.Rsp, __ParentRsp__);
    ATOMIC_STORE(Cth->Context.Cs, UserCodeSelector);
    ATOMIC_STORE(Cth->Context.Ss, UserDataSelector);
    ATOMIC_STORE(Cth->Context.Rflags, 0x202);
    ATOMIC_STORE(Cth->Type, ThreadTypeUser);
    ATOMIC_STORE(Cth->State, ThreadStateReady);
    ATOMIC_STORE(Cth->PageDirectory, (uint64_t)Child->Space->PhysicalBase);
    ATOMIC_STORE(Cth->ProcessId, (uint32_t)Child->Pid);

    SysErr  err;
    SysErr* Error = &err;

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
                        PosixExit(Child, -1);
                        return -NotCanonical;
                    }

                    uint8_t* __Dst__ = (uint8_t*)PhysToVirt(__NewPhys__);
                    uint8_t* __Src__ = (uint8_t*)PhysToVirt(__SrcPhys__);
                    memcpy(__Dst__, __Src__, (size_t)PageSize);

                    uint64_t __Flags__ =
                        __Leaf__ & (PTEWRITABLE | PTEUSER | PTEPRESENT | PTEWRITETHROUGH |
                                    PTECACHEDISABLE | PTEACCESSED | PTEDIRTY | PTENOEXECUTE);

                    MapPage(Child->Space, __Va__, __NewPhys__, __Flags__);
                }
            }
        }
    }

    if (__AttachThread__(Child, Cth) != SysOkay)
    {
        DestroyThread(Cth, Error);
        PosixExit(Child, -1);
        return -NotInit;
    }

    *__OutChild__ = Child;

    PDebug("Forked child with PID=%ld and context RIP=0x%llx and RSP=0x%llx\n",
           Child->Pid,
           (unsigned long long)ATOMIC_LOAD(Cth->Context.Rip),
           (unsigned long long)ATOMIC_LOAD(Cth->Context.Rsp));

    ThreadExecute(Cth, Error);
    return Child->Pid;
}

int
PosixExit(PosixProc* __Proc__, int __Status__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadArgs;
    }

    SysErr  err;
    SysErr* Error = &err;

    ATOMIC_STORE(__Proc__->ExitCode, __Status__);
    ATOMIC_STORE(__Proc__->Zombie, 1);

    __UpdateTimesOnExit__(__Proc__);

    /* clear per-CPU current thread references */
    for (uint32_t CpuIndex = 0; CpuIndex < MaxCPUs; CpuIndex++)
    {
        Thread* Ct = CurrentThreads[CpuIndex];
        if (Ct && (long)ATOMIC_LOAD(Ct->ProcessId) == __Proc__->Pid)
        {
            CurrentThreads[CpuIndex] = NULL;
        }
    }

    __DetachThread__(__Proc__);

    AcquireSpinLock(&ThreadListLock, Error);

    Thread* ThreadPtr = ThreadList;
    while (ThreadPtr)
    {
        Thread* NextThread = ThreadPtr->Next;
        if ((long)ATOMIC_LOAD(ThreadPtr->ProcessId) == __Proc__->Pid)
        {
            ATOMIC_STORE(ThreadPtr->State, ThreadStateTerminated);
            DestroyThread(ThreadPtr, Error);
            PSuccess("Destroyed ThreadId=%u of Pid=%u\n", ThreadPtr->ThreadId, __Proc__->Pid);
        }
        ThreadPtr = NextThread;
    }

    ReleaseSpinLock(&ThreadListLock, Error);

    PosixProc* ParentProc = PosixFind(__Proc__->Ppid);
    if (ParentProc)
    {
        __WakeParent__(ParentProc, __Proc__, Error);
    }

    PSuccess("Exited with Pid=%ld Status=%d\n", __Proc__->Pid, __Status__);
    return SysOkay;
}

long
PosixWait4(PosixProc*   __Parent__,
           long         __Pid__,
           int*         __OutStatus__,
           int          __Options__,
           PosixRusage* __OutUsage__)
{
    if (Probe_IF_Error(__Parent__) || !__Parent__)
    {
        return -BadEntity;
    }

    long TargetPid = __Pid__;

    for (;;)
    {
        for (long I = 1; I <= MaxProcs; I++)
        {
            PosixProc* P = PosixFind(I);
            if (Probe_IF_Error(P) || !P || ATOMIC_LOAD(P->Ppid) != __Parent__->Pid)
            {
                continue;
            }
            if (TargetPid > 0 && P->Pid != TargetPid)
            {
                continue;
            }

            if (ATOMIC_LOAD(P->Zombie))
            {
                if (__OutStatus__)
                {
                    *__OutStatus__ = ATOMIC_LOAD(P->ExitCode);
                }
                if (__OutUsage__)
                {
                    __OutUsage__->UtimeUsec       = ATOMIC_LOAD(P->Times.UserUsec);
                    __OutUsage__->StimeUsec       = ATOMIC_LOAD(P->Times.SysUsec);
                    __OutUsage__->MaxRss          = RlimitMaxRss;
                    __OutUsage__->MinorFaults     = 0;
                    __OutUsage__->MajorFaults     = 0;
                    __OutUsage__->VoluntaryCtxt   = 0;
                    __OutUsage__->InvoluntaryCtxt = 0;
                }

                long ReapedId = P->Pid;
                ProcFsNotifyProcRemoved(P);
                __TableRemove__(P);
                SysErr  err;
                SysErr* Error = &err;
                __FreeProc__(P, Error);
                PSuccess("Reaped=%ld\n", ReapedId);
                return ReapedId;
            }
        }

        if (__Options__ & WNOHANG)
        {
            return SysOkay;
        }

        if (__Parent__->MainThread)
        {
            ATOMIC_STORE(__Parent__->MainThread->State, ThreadStateBlocked);
            ATOMIC_STORE(__Parent__->MainThread->WaitReason, WaitReasonChild);
        }
        SysErr  err;
        SysErr* Error = &err;
        ThreadYield(Error);
    }
}

int
PosixSetSid(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadArgs;
    }
    ATOMIC_STORE(__Proc__->Sid, __Proc__->Pid);
    ATOMIC_STORE(__Proc__->Pgrp, __Proc__->Pid);
    return SysOkay;
}

int
PosixSetPgrp(PosixProc* __Proc__, long __Pgid__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || __Pgid__ <= 0)
    {
        return -BadArgs;
    }
    ATOMIC_STORE(__Proc__->Pgrp, __Pgid__);
    return SysOkay;
}

int
PosixGetPid(PosixProc* __Proc__)
{
    return __Proc__ ? (int)ATOMIC_LOAD(__Proc__->Pid) : -NotCanonical;
}
int
PosixGetPpid(PosixProc* __Proc__)
{
    return __Proc__ ? (int)ATOMIC_LOAD(__Proc__->Ppid) : -NotCanonical;
}
int
PosixGetPgrp(PosixProc* __Proc__)
{
    return __Proc__ ? (int)ATOMIC_LOAD(__Proc__->Pgrp) : -NotCanonical;
}
int
PosixGetSid(PosixProc* __Proc__)
{
    return __Proc__ ? (int)ATOMIC_LOAD(__Proc__->Sid) : -NotCanonical;
}

int
PosixChdir(PosixProc* __Proc__, const char* __Path__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Path__) || !__Path__)
    {
        return -BadArgs;
    }
    if (VfsIsDir(__Path__) != SysOkay)
    {
        return -NoSuch;
    }
    strcpy(__Proc__->Cwd, __Path__, MaxPathLen);
    return SysOkay;
}

int
PosixFchdir(PosixProc* __Proc__, int __Fd__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || __Fd__ < 0 || Probe_IF_Error(__Proc__->Fds) ||
        !__Proc__->Fds)
    {
        return -BadArgs;
    }

    VfsStat St = {0};
    if (PosixFstat(__Proc__->Fds, __Fd__, &St) != SysOkay)
    {
        return -ErrReturn;
    }
    if (St.Type != VNodeDIR)
    {
        return -BadEntity;
    }

    return SysOkay;
}

int
PosixSetUmask(PosixProc* __Proc__, long __Mask__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadEntity;
    }
    ATOMIC_STORE(__Proc__->Cred.Umask, (__Mask__ & 0777));
    return SysOkay;
}

int
PosixGetTty(PosixProc* __Proc__, char* __Out__, long __Len__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Out__) || !__Out__ ||
        __Len__ <= 0)
    {
        return -BadArgs;
    }
    if (Probe_IF_Error(__Proc__->TtyName) || !__Proc__->TtyName)
    {
        strcpy(__Out__, "notty", (uint32_t)__Len__);
    }
    else
    {
        strcpy(__Out__, __Proc__->TtyName, (uint32_t)__Len__);
    }
    return SysOkay;
}

int
PosixKill(long __Pid__, int __Sig__)
{
    PosixProc* P = PosixFind(__Pid__);
    if (Probe_IF_Error(P) || !P)
    {
        return -NoSuch;
    }
    /* Enqueue signal bit */
    ATOMIC_FETCH_OR(P->SigPending, (1ULL << (__Sig__ & 63)));
    return SysOkay;
}

int
PosixTkill(long __Tid__, int __Sig__)
{
    /* Map TID to thread->ProcessId then call kill */
    Thread* Th = FindThreadById((uint32_t)__Tid__);
    if (Probe_IF_Error(Th) || !Th)
    {
        return -BadEntity;
    }
    return PosixKill((long)ATOMIC_LOAD(Th->ProcessId), __Sig__);
}

int
PosixSigaction(int __Sig__, const PosixSigAction* __Act__, PosixSigAction* __OldAct__)
{
    if (__Sig__ <= 0 || __Sig__ > 31)
    {
        return -NotCanonical;
    }

    PosixProc* P = __CurrentProc__();
    if (Probe_IF_Error(P) || !P || Probe_IF_Error(P->MainThread) || !P->MainThread)
    {
        return -BadEntity;
    }

    /* Old */
    if (__OldAct__)
    {
        __OldAct__->Handler = (PosixSigHandler)P->MainThread->SignalHandlers[__Sig__];
        __OldAct__->Mask    = ATOMIC_LOAD(P->SigMask);
        __OldAct__->Flags   = 0;
    }

    /* New */
    if (__Act__)
    {
        P->MainThread->SignalHandlers[__Sig__] = (void*)__Act__->Handler;
        ATOMIC_STORE(P->SigMask, __Act__->Mask);
    }

    return SysOkay;
}

int
PosixSigprocmask(int __How__, const uint64_t* __Set__, uint64_t* __OldSet__)
{
    PosixProc* P = __CurrentProc__();
    if (Probe_IF_Error(P) || !P)
    {
        return -BadEntity;
    }
    if (__OldSet__)
    {
        *__OldSet__ = ATOMIC_LOAD(P->SigMask);
    }
    if (Probe_IF_Error(__Set__) || !__Set__)
    {
        return SysOkay;
    }

    /* 0=BLOCK, 1=UNBLOCK, 2=SETMASK */
    if (__How__ == 0)
    {
        uint64_t cur = ATOMIC_LOAD(P->SigMask);
        ATOMIC_STORE(P->SigMask, (cur | *(__Set__)));
    }
    else if (__How__ == 1)
    {
        uint64_t cur = ATOMIC_LOAD(P->SigMask);
        ATOMIC_STORE(P->SigMask, (cur & ~(*__Set__)));
    }
    else if (__How__ == 2)
    {
        ATOMIC_STORE(P->SigMask, *(__Set__));
    }
    return SysOkay;
}

int
PosixSigpending(uint64_t* __OutMask__)
{
    if (Probe_IF_Error(__OutMask__) || !__OutMask__)
    {
        return -BadArgs;
    }
    PosixProc* P = __CurrentProc__();
    if (Probe_IF_Error(P) || !P)
    {
        *__OutMask__ = 0;
        return SysOkay;
    }
    *__OutMask__ = ATOMIC_LOAD(P->SigPending);
    return SysOkay;
}

int
PosixSigsuspend(const uint64_t* __Mask__)
{
    SysErr  err;
    SysErr* Error = &err;
    /* Yield until a signal arrives */
    ThreadYield(Error);
    return SysOkay;
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
        if (Probe_IF_Error(P) || !P)
        {
            continue;
        }
        __DeliverPendingSignals__(P);
    }
    return SysOkay;
}

PosixProc*
PosixFind(long __Pid__)
{
    if (__Pid__ <= 0 || !PosixProcs.Items)
    {
        return Error_TO_Pointer(-BadArgs);
    }
    long count = PosixProcs.Count; /* benign read */
    for (long I = 0; I < count; I++)
    {
        PosixProc* P = PosixProcs.Items[I];
        if (P && ATOMIC_LOAD(P->Pid) == __Pid__)
        {
            return P;
        }
    }
    return Error_TO_Pointer(-NoSuch);
}

static int
__CreateTableIfNeeded__(void)
{
    if (PosixProcs.Items)
    {
        return SysOkay;
    }

    PosixProcs.Cap = MaxProcs;
    ATOMIC_STORE(PosixProcs.Count, 0);
    PosixProcs.Items = (PosixProc**)KMalloc(sizeof(PosixProc*) * (size_t)PosixProcs.Cap);
    if (!PosixProcs.Items)
    {
        return -BadAlloc;
    }
    SysErr  err;
    SysErr* Error = &err;
    InitializeSpinLock(&PosixProcs.Lock, "PosixProcs", Error);
    return SysOkay;
}

static long
__FindFreePid__(void)
{
    /* Naive monotonic PID allocation */
    long pid = ATOMIC_FETCH_ADD(__NextPid__, 1);
    if (pid <= 0)
    {
        ATOMIC_STORE(__NextPid__, 1);
        pid = 1;
    }
    return pid;
}

static int
__TableInsert__(PosixProc* __Proc__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PosixProcs.Lock, Error);
    long count = ATOMIC_LOAD(PosixProcs.Count);
    if (count >= PosixProcs.Cap)
    {
        ReleaseSpinLock(&PosixProcs.Lock, Error);
        return -TooMany;
    }
    PosixProcs.Items[count] = __Proc__;
    ATOMIC_STORE(PosixProcs.Count, count + 1);
    ReleaseSpinLock(&PosixProcs.Lock, Error);
    return SysOkay;
}

static int
__TableRemove__(PosixProc* __Proc__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PosixProcs.Lock, Error);
    long idx   = -1;
    long count = ATOMIC_LOAD(PosixProcs.Count);
    for (long I = 0; I < count; I++)
    {
        if (PosixProcs.Items[I] == __Proc__)
        {
            idx = I;
            break;
        }
    }
    if (idx >= 0)
    {
        PosixProcs.Items[idx]       = PosixProcs.Items[count - 1];
        PosixProcs.Items[count - 1] = NULL;
        ATOMIC_STORE(PosixProcs.Count, count - 1);
    }
    ReleaseSpinLock(&PosixProcs.Lock, Error);
    return SysOkay;
}

static PosixProc*
__AllocProc__(void)
{
    SysErr     err;
    SysErr*    Error = &err;
    PosixProc* P     = (PosixProc*)KMalloc(sizeof(PosixProc));
    if (Probe_IF_Error(P) || !P)
    {
        return Error_TO_Pointer(-BadAlloc);
    }
    memset(P, 0, sizeof(*P));
    InitializeSpinLock(&P->Lock, "proc", Error);

    /* allocate cmdline/environ buffers */
    P->CmdlineBuf = (char*)KMalloc(4096);
    P->EnvironBuf = (char*)KMalloc(8192);
    if (Probe_IF_Error(P->CmdlineBuf) || !P->CmdlineBuf || Probe_IF_Error(P->EnvironBuf) ||
        !P->EnvironBuf)
    {
        if (P->CmdlineBuf)
        {
            KFree(P->CmdlineBuf, Error);
        }
        if (P->EnvironBuf)
        {
            KFree(P->EnvironBuf, Error);
        }
        KFree(P, Error);
        return Error_TO_Pointer(-BadAlloc);
    }
    ATOMIC_STORE(P->CmdlineLen, 0);
    ATOMIC_STORE(P->EnvironLen, 0);
    P->Comm[0] = '\0';
    return P;
}

static void
__FreeProc__(PosixProc* __Proc__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }

    SysErr  err;
    SysErr* Error = &err;

    if (__Proc__->Fds)
    {
        for (long I = 0; I < __Proc__->Fds->Cap; I++)
        {
            PosixFd* E = &__Proc__->Fds->Entries[I];
            if (ATOMIC_LOAD(E->Fd) >= 0)
            {
                PosixClose(__Proc__->Fds, (int)ATOMIC_LOAD(E->Fd));
            }
        }
        KFree(__Proc__->Fds->Entries, __Err__);
        KFree(__Proc__->Fds, __Err__);
        __Proc__->Fds = NULL;
    }

    if (__Proc__->CmdlineBuf)
    {
        KFree(__Proc__->CmdlineBuf, __Err__);
        __Proc__->CmdlineBuf = NULL;
    }
    if (__Proc__->EnvironBuf)
    {
        KFree(__Proc__->EnvironBuf, __Err__);
        __Proc__->EnvironBuf = NULL;
    }

    if (__Proc__->Space)
    {
        DestroyVirtualSpace(__Proc__->Space, __Err__);
        __Proc__->Space = NULL;
    }
    KFree(__Proc__, __Err__);
}

static int
__AttachThread__(PosixProc* __Proc__, Thread* __Th__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Th__) || !__Th__)
    {
        return -BadArgs;
    }
    __Proc__->MainThread = __Th__;
    ATOMIC_STORE(__Th__->ProcessId, (uint32_t)__Proc__->Pid);
    ATOMIC_STORE(__Th__->State, ThreadStateReady);
    return SysOkay;
}
static int
__DetachThread__(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadArgs;
    }
    Thread* Th = __Proc__->MainThread;
    if (Th)
    {
        SysErr  err;
        SysErr* Error = &err;
        ATOMIC_STORE(Th->State,
                     ThreadStateTerminated); /*Scheduler will automatically remove from ready*/
        DestroyThread(Th, Error);
        __Proc__->MainThread = NULL;
    }
    return SysOkay;
}

static int
__ForkCopyFds__(PosixProc* __Parent__, PosixProc* __Child__)
{
    if (Probe_IF_Error(__Parent__) || !__Parent__ || Probe_IF_Error(__Parent__->Fds) ||
        !__Parent__->Fds || Probe_IF_Error(__Child__) || !__Child__)
    {
        return -BadArgs;
    }

    SysErr  err;
    SysErr* Error = &err;

    ATOMIC_STORE(__Child__->SigMask, ATOMIC_LOAD(__Parent__->SigMask));
    ATOMIC_STORE(__Child__->SigPending, 0);
    __Child__->MainThread = NULL;
    ATOMIC_STORE(__Child__->Times.UserUsec, 0);
    ATOMIC_STORE(__Child__->Times.SysUsec, 0);
    ATOMIC_STORE(__Child__->Times.StartTick, ATOMIC_LOAD(__Parent__->Times.StartTick));

    __Child__->Fds = (PosixFdTable*)KMalloc(sizeof(PosixFdTable));
    if (Probe_IF_Error(__Child__->Fds) || !__Child__->Fds)
    {
        return -BadAlloc;
    }
    if (PosixFdInit(__Child__->Fds, __Parent__->Fds->Cap) != SysOkay)
    {
        KFree(__Child__->Fds, Error);
        __Child__->Fds = NULL;
        return -NotInit;
    }

    /* Duplicate entries with refcounts */
    for (long I = 0; I < __Parent__->Fds->Cap; I++)
    {
        PosixFd* E = &__Parent__->Fds->Entries[I];
        if (ATOMIC_LOAD(E->Fd) < 0)
        {
            continue;
        }

        int NewFd = __FindFreeFd__(__Child__->Fds, 0);
        if (NewFd < 0)
        {
            return -TooLess;
        }

        __Child__->Fds->Entries[NewFd] = *E;
        ATOMIC_STORE(__Child__->Fds->Entries[NewFd].Fd, NewFd);
        ATOMIC_FETCH_ADD(__Child__->Fds->Entries[NewFd].Refcnt, 1);

        if (ATOMIC_LOAD(__Child__->Fds->Entries[NewFd].IsFile) &&
            __Child__->Fds->Entries[NewFd].Obj)
        {
            ATOMIC_FETCH_ADD(((File*)__Child__->Fds->Entries[NewFd].Obj)->Refcnt, 1);
        }

        ATOMIC_FETCH_ADD(__Child__->Fds->Count, 1);
    }

    ATOMIC_STORE(__Child__->Fds->StdinFd, ATOMIC_LOAD(__Parent__->Fds->StdinFd));
    ATOMIC_STORE(__Child__->Fds->StdoutFd, ATOMIC_LOAD(__Parent__->Fds->StdoutFd));
    ATOMIC_STORE(__Child__->Fds->StderrFd, ATOMIC_LOAD(__Parent__->Fds->StderrFd));

    /* Comm, cmdline, environ (bounded copy) */
    strcpy(__Child__->Comm, __Parent__->Comm, (uint32_t)sizeof(__Child__->Comm));

    ATOMIC_STORE(__Child__->CmdlineLen, __Min__(ATOMIC_LOAD(__Parent__->CmdlineLen), 4096));
    ATOMIC_STORE(__Child__->EnvironLen, __Min__(ATOMIC_LOAD(__Parent__->EnvironLen), 8192));

    if (ATOMIC_LOAD(__Child__->CmdlineLen) > 0 && __Child__->CmdlineBuf && __Parent__->CmdlineBuf)
    {
        memcpy(__Child__->CmdlineBuf,
               __Parent__->CmdlineBuf,
               (size_t)ATOMIC_LOAD(__Child__->CmdlineLen));
    }
    if (ATOMIC_LOAD(__Child__->EnvironLen) > 0 && __Child__->EnvironBuf && __Parent__->EnvironBuf)
    {
        memcpy(__Child__->EnvironBuf,
               __Parent__->EnvironBuf,
               (size_t)ATOMIC_LOAD(__Child__->EnvironLen));
    }

    return SysOkay;
}

static int
__SetDefaultFds__(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadArgs;
    }

    __Proc__->Fds = (PosixFdTable*)KMalloc(sizeof(PosixFdTable));
    if (Probe_IF_Error(__Proc__->Fds) || !__Proc__->Fds)
    {
        return -BadAlloc;
    }

    if (PosixFdInit(__Proc__->Fds, MaxFdsDefault) != SysOkay)
    {
        SysErr  err;
        SysErr* Error = &err;
        KFree(__Proc__->Fds, Error);
        __Proc__->Fds = NULL;
        return -NotInit;
    }

    const char* TtyPath  = "/dev/tty0"; /*TODO: not be hardcoded*/
    const char* NullPath = "/dev/null";
    int         StdinFd;
    int         StdoutFd;
    int         StderrFd;

    /* stdin */
    if (VfsExists(TtyPath) == SysOkay)
    {
        StdinFd = PosixOpen(__Proc__->Fds, TtyPath, VFlgRDONLY, 0);
    }
    else
    {
        StdinFd = PosixOpen(__Proc__->Fds, NullPath, VFlgRDONLY, 0);
    }

    /* stdout */
    if (VfsExists(TtyPath) == SysOkay)
    {
        StdoutFd = PosixOpen(__Proc__->Fds, TtyPath, VFlgWRONLY, 0);
    }
    else
    {
        StdoutFd = PosixOpen(__Proc__->Fds, NullPath, VFlgWRONLY, 0);
    }

    /* stderr */
    if (VfsExists(TtyPath) == SysOkay)
    {
        StderrFd = PosixOpen(__Proc__->Fds, TtyPath, VFlgWRONLY, 0);
    }
    else
    {
        StderrFd = PosixOpen(__Proc__->Fds, NullPath, VFlgWRONLY, 0);
    }

    if (StdinFd < 0 || StdoutFd < 0 || StderrFd < 0)
    {
        return -TooLess;
    }

    ATOMIC_STORE(__Proc__->Fds->StdinFd, StdinFd);
    ATOMIC_STORE(__Proc__->Fds->StdoutFd, StdoutFd);
    ATOMIC_STORE(__Proc__->Fds->StderrFd, StderrFd);

    if (VfsExists(TtyPath))
    {
        ATOMIC_STORE(__Proc__->TtyFd, StdinFd);
        __Proc__->TtyName = "tty0";
    }
    else
    {
        ATOMIC_STORE(__Proc__->TtyFd, -1);
        __Proc__->TtyName = NULL;
    }

    return SysOkay;
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
    strcpy(__Out__, IdxUal, (uint32_t)__Cap__);
}

static int
__BuildArgsEnv__(const char* const* __Argv__,
                 const char* const* __Envp__,
                 const char*        __Path__,
                 PosixProc*         __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadEntity;
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
        strcpy(__Proc__->Comm, "unknown", (uint32_t)sizeof(__Proc__->Comm));
    }

    /* Build NUL-separated cmdline */
    ATOMIC_STORE(__Proc__->CmdlineLen, 0);
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
        ATOMIC_STORE(__Proc__->CmdlineLen, OffSec);
        if (OffSec < 4096)
        {
            __Proc__->CmdlineBuf[OffSec++] = '\0';
            ATOMIC_STORE(__Proc__->CmdlineLen, OffSec);
        }
    }

    /* Build NUL-separated environ */
    ATOMIC_STORE(__Proc__->EnvironLen, 0);
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
        ATOMIC_STORE(__Proc__->EnvironLen, OffSec);
        if (OffSec < 8192)
        {
            __Proc__->EnvironBuf[OffSec++] = '\0';
            ATOMIC_STORE(__Proc__->EnvironLen, OffSec);
        }
    }

    return SysOkay;
}

static int
__PopulateTimesStart__(PosixProc* __Proc__)
{
    ATOMIC_STORE(__Proc__->Times.UserUsec, 0);
    ATOMIC_STORE(__Proc__->Times.SysUsec, 0);
    ATOMIC_STORE(__Proc__->Times.StartTick, GetSystemTicks());
    return SysOkay;
}

static int
__UpdateTimesOnExit__(PosixProc* __Proc__)
{
    uint64_t now   = GetSystemTicks();
    uint64_t start = ATOMIC_LOAD(__Proc__->Times.StartTick);
    uint64_t dur   = (now > start) ? (now - start) : 0;
    ATOMIC_FETCH_ADD(__Proc__->Times.SysUsec, dur * 1000); /* pretend 1 tick = 1ms */
    return SysOkay;
}

static int
__ResolveExecFile__(const char* __Path__, File** __OutFile__)
{
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__OutFile__) || !__OutFile__)
    {
        return -BadArgs;
    }
    File* f = VfsOpen(__Path__, VFlgRDONLY);
    if (Probe_IF_Error(f) || !f)
    {
        return -BadEntity;
    }
    *__OutFile__ = f;
    return SysOkay;
}

__attribute_unused__ static int
__EnsureCwdRoot__(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadArgs;
    }
    if (__Proc__->Cwd[0] == '\0')
    {
        strcpy(__Proc__->Cwd, "/", MaxPathLen);
    }
    if (__Proc__->Root[0] == '\0')
    {
        strcpy(__Proc__->Root, "/", MaxPathLen);
    }
    return SysOkay;
}

static void
__WakeParent__(PosixProc* __Parent__, PosixProc* __Child__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Parent__) || !__Parent__ || Probe_IF_Error(__Child__) || !__Child__)
    {
        SlotError(__Err__, -BadArgs);
        return;
    }
    /* Set SIGCHLD pending on parent */
    ATOMIC_FETCH_OR(__Parent__->SigPending, (1ULL << (SigChld & 63)));
}

static int
__DeliverPendingSignals__(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__)
    {
        return -BadArgs;
    }

    uint64_t pend = ATOMIC_LOAD(__Proc__->SigPending);
    if (pend == 0)
    {
        return SysOkay;
    }

    /* mask */
    pend &= ~ATOMIC_LOAD(__Proc__->SigMask);
    if (pend == 0)
    {
        return SysOkay;
    }

    /* SIGCONT resumes */
    if (pend & (1ULL << (SigCont & 63)))
    {
        if (__Proc__->MainThread)
        {
            ATOMIC_STORE(__Proc__->MainThread->State, ThreadStateReady);
        }
        ATOMIC_FETCH_AND(__Proc__->SigPending, ~(1ULL << (SigCont & 63)));
    }

    /* SIGSTOP blocks */
    if (pend & (1ULL << (SigStop & 63)))
    {
        if (__Proc__->MainThread)
        {
            ATOMIC_STORE(__Proc__->MainThread->State, ThreadStateBlocked);
            ATOMIC_STORE(__Proc__->MainThread->WaitReason, WaitReasonSignal);
        }
        ATOMIC_FETCH_AND(__Proc__->SigPending, ~(1ULL << (SigStop & 63)));
        return SysOkay;
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
            ATOMIC_STORE(__Proc__->MainThread->Context.Rdi, (uint64_t)S);
            ATOMIC_STORE(__Proc__->MainThread->Context.Rip,
                         (uint64_t)__Proc__->MainThread->SignalHandlers[S]);

            ATOMIC_FETCH_AND(__Proc__->SigPending, ~bit);
        }
    }

    /* Default terminate for TERM/KILL/INT if still pending after handler pass */
    if (ATOMIC_LOAD(__Proc__->SigPending) & (1ULL << (SigTerm & 63)))
    {
        ATOMIC_FETCH_AND(__Proc__->SigPending, ~(1ULL << (SigTerm & 63)));
        PosixExit(__Proc__, 128 + SigTerm);
        return SysOkay;
    }
    if (ATOMIC_LOAD(__Proc__->SigPending) & (1ULL << (SigKill & 63)))
    {
        ATOMIC_FETCH_AND(__Proc__->SigPending, ~(1ULL << (SigKill & 63)));
        PosixExit(__Proc__, 128 + SigKill);
        return SysOkay;
    }
    if (ATOMIC_LOAD(__Proc__->SigPending) & (1ULL << (SigInt & 63)))
    {
        ATOMIC_FETCH_AND(__Proc__->SigPending, ~(1ULL << (SigInt & 63)));
        PosixExit(__Proc__, 128 + SigInt);
        return SysOkay;
    }

    /* delivered or ignored */
    ATOMIC_STORE(__Proc__->SigPending, 0);
    return SysOkay;
}