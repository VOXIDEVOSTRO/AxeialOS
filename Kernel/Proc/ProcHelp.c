#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <POSIXFd.h>
#include <POSIXProc.h>
#include <POSIXSignals.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGPROCHELPC_Debug
#    define LOGPROCHELPC_PDebug(fmt, ...) PDebug("[KERNEL>>ProcHelp.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROCHELPC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROCHELPC_Logs
#    define LOGPROCHELPC_PError(fmt, ...) PError("[KERNEL>>ProcHelp.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROCHELPC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROCHELPC_Logs
#    define LOGPROCHELPC_PWarn(fmt, ...) PWarn("[KERNEL>>ProcHelp.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROCHELPC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROCHELPC_Logs
#    define LOGPROCHELPC_PInfo(fmt, ...) PInfo("[KERNEL>>ProcHelp.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROCHELPC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROCHELPC_Logs
#    define LOGPROCHELPC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ProcHelp.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROCHELPC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

static inline long
__AppendStr__(char* __Buf__, long __Cap__, long* __Off__, const char* __Str__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || Probe_IF_Error(__Off__) || !__Off__ ||
        Probe_IF_Error(__Str__) || !__Str__ || __Cap__ <= 0)
    {
        PushError("__AppendStr__", LOGPROCHELPC_PError, "Bad args to __AppendStr__", -BadArguments);
        return -BadArguments;
    }

    long N = atomic_load_explicit((atomic_long*)__Off__, memory_order_relaxed);
    if (N < 0)
    {
        PushError("__AppendStr__",
                  LOGPROCHELPC_PError,
                  "Not enough space(Small) in __AppendStr__",
                  -TooSmall);
        return -TooSmall;
    }
    if (N >= __Cap__)
    {
        LOGPROCHELPC_PWarn("Not enough space(Big) in __AppendStr__");
        return Nothing;
    }

    long Rem = __Cap__ - N;
    long L   = (long)StringLength(__Str__);
    long C   = (L < Rem) ? L : Rem;

    if (C > 0)
    {
        memcpy(__Buf__ + N, __Str__, (size_t)C);
        long NewN = N + C;
        atomic_store_explicit((atomic_long*)__Off__, NewN, memory_order_release);
    }

    return C;
}

static inline long
__AppendChar__(char* __Buf__, long __Cap__, long* __Off__, char __Ch__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || Probe_IF_Error(__Off__) || !__Off__ || __Cap__ <= 0)
    {
        PushError(
            "__AppendChar__", LOGPROCHELPC_PError, "Bad args to __AppendChar__", -BadArguments);
        return -BadArguments;
    }

    long N = atomic_load_explicit((atomic_long*)__Off__, memory_order_relaxed);
    if (N < 0)
    {
        PushError("__AppendChar__",
                  LOGPROCHELPC_PError,
                  "Not enough space(Small) in __AppendChar__",
                  -TooSmall);
        return -TooSmall;
    }
    if (N >= __Cap__)
    {
        LOGPROCHELPC_PWarn("Not enough space(Big) in __AppendChar__");
        return Nothing;
    }

    __Buf__[N++] = __Ch__;
    atomic_store_explicit((atomic_long*)__Off__, N, memory_order_release);

    return 1; /*char is an idx of 1*/
}

static inline long
__AppendU64Dec__(char* __Buf__, long __Cap__, long* __Off__, uint64_t __V__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || Probe_IF_Error(__Off__) || !__Off__ || __Cap__ <= 0)
    {
        PushError(
            "__AppendU64Dec__", LOGPROCHELPC_PError, "Bad args to __AppendU64Dec__", -BadArguments);
        return -BadArguments;
    }

    char Num[32];
    UnsignedToStringEx(__V__, Num, 10, 0);
    Num[31] = '\0';
    return __AppendStr__(__Buf__, __Cap__, __Off__, Num);
}

static inline long
__AppendU64Hex__(char* __Buf__, long __Cap__, long* __Off__, uint64_t __V__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || Probe_IF_Error(__Off__) || !__Off__ || __Cap__ <= 0)
    {
        PushError(
            "__AppendU64Hex__", LOGPROCHELPC_PError, "Bad args to __AppendU64Hex__", -BadArguments);
        return -BadArguments;
    }
    char Num[32];
    UnsignedToStringEx(__V__, Num, 16, 0);
    Num[31] = '\0';
    return __AppendStr__(__Buf__, __Cap__, __Off__, Num);
}

static inline long
__AppendU64Oct__(char* __Buf__, long __Cap__, long* __Off__, uint64_t __V__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || Probe_IF_Error(__Off__) || !__Off__ || __Cap__ <= 0)
    {
        PushError(
            "__AppendU64Oct__", LOGPROCHELPC_PError, "Bad args to __AppendU64Oct__", -BadArguments);
        return -BadArguments;
    }
    char Num[32];
    UnsignedToStringEx(__V__, Num, 8, 0);
    Num[31] = '\0';
    return __AppendStr__(__Buf__, __Cap__, __Off__, Num);
}

long
ProcFsMakeStatus(PosixProc* __Proc__, char* __Buff__, long __Caps__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Buff__) || !__Buff__ ||
        __Caps__ <= 0)
    {
        PushError(
            "ProcFsMakeStatus", LOGPROCHELPC_PError, "Bad args to ProcFsMakeStatus", -BadArguments);
        return -BadArguments;
    }

    atomic_long N;
    atomic_store_explicit(&N, 0, memory_order_relaxed);
    long Nsnap = 0;

    char St = __ProcStateCode__(__Proc__);

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Name:\t");
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Name N=%ld", atomic_load_explicit(&N, memory_order_acquire));
    __AppendStr__(__Buff__, __Caps__, &Nsnap, (__Proc__->Comm[0] ? __Proc__->Comm : "NA"));
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Comm N=%ld", atomic_load_explicit(&N, memory_order_acquire));
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "State:\t");
    __AppendChar__(__Buff__, __Caps__, &Nsnap, St);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status State N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Pid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Pid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Pid N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "PPid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Ppid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status PPid N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Pgrp:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Pgrp);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Pgrp N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Sid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Sid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Sid N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Tty:\t");
    __AppendStr__(__Buff__, __Caps__, &Nsnap, (__Proc__->TtyName ? __Proc__->TtyName : "NA"));
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Tty N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Uid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Cred.Ruid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Cred.Euid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Cred.Suid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Uid N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Gid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Cred.Rgid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Cred.Egid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->Cred.Sgid);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Gid N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Umask:\t0");
    __AppendU64Oct__(__Buff__, __Caps__, &Nsnap, (uint64_t)(__Proc__->Cred.Umask & 0777));
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Umask N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Threads:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)1);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Threads N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "SigPnd:\t");
    __AppendU64Hex__(__Buff__, __Caps__, &Nsnap, __Proc__->SigPending);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status SigPnd N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "SigBlk:\t");
    __AppendU64Hex__(__Buff__, __Caps__, &Nsnap, __Proc__->SigMask);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status SigBlk N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "SigIgn:\t");
    __AppendStr__(__Buff__, __Caps__, &Nsnap, "NA");
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status SigIgn N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "SigCgt:\t");
    __AppendStr__(__Buff__, __Caps__, &Nsnap, "NA");
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status SigCgt N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Utime(us):\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, __Proc__->Times.UserUsec);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Utime N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "Stime(us):\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, __Proc__->Times.SysUsec);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status Stime N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "StartTick:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, __Proc__->Times.StartTick);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status StartTick N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "CmdlineLen:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->CmdlineLen);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status CmdlineLen N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendStr__(__Buff__, __Caps__, &Nsnap, "EnvironLen:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &Nsnap, (uint64_t)__Proc__->EnvironLen);
    __AppendChar__(__Buff__, __Caps__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("Status EnvironLen N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    long FinalN = atomic_load_explicit(&N, memory_order_acquire);
    if ((__Caps__ - FinalN) >= 1)
    {
        __Buff__[FinalN] = '\0';
    }

    return FinalN;
}

static inline long
__AppendField__(char* __Buff__, long __Caps__, long* __Off__, const char* __Field__)
{
    long w1 = __AppendChar__(__Buff__, __Caps__, __Off__, ' ');
    if (w1 <= 0)
    {
        PushError("__AppendField__", LOGPROCHELPC_PError, "Failed to append field space", -TooBig);
        return w1;
    }
    long w2 = __AppendStr__(__Buff__, __Caps__, __Off__, __Field__);
    return (w2 <= 0) ? w2 : (w1 + w2);
}

long
ProcFsMakeStat(PosixProc* __Proc__, char* __Buf__, long __Cap__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Cap__ <= 0)
    {
        PushError(
            "ProcFsMakeStat", LOGPROCHELPC_PError, "Bad args to ProcFsMakeStat", -BadArguments);
        return -BadArguments;
    }

    atomic_long N;
    atomic_store_explicit(&N, 0, memory_order_relaxed);
    long Nsnap = 0;

    char St = __ProcStateCode__(__Proc__);
    char Num[64];

    UnsignedToStringEx((uint64_t)__Proc__->Pid, Num, 10, 0);
    __AppendStr__(__Buf__, __Cap__, &Nsnap, Num);
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: pid N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendChar__(__Buf__, __Cap__, &Nsnap, ' ');
    __AppendChar__(__Buf__, __Cap__, &Nsnap, '(');
    __AppendStr__(__Buf__, __Cap__, &Nsnap, (__Proc__->Comm[0] ? __Proc__->Comm : "unknown"));
    __AppendChar__(__Buf__, __Cap__, &Nsnap, ')');
    __AppendChar__(__Buf__, __Cap__, &Nsnap, ' ');
    __AppendChar__(__Buf__, __Cap__, &Nsnap, St);
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: comm/state N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    UnsignedToStringEx((uint64_t)__Proc__->Ppid, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &Nsnap, Num);
    UnsignedToStringEx((uint64_t)__Proc__->Pgrp, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &Nsnap, Num);
    UnsignedToStringEx((uint64_t)__Proc__->Sid, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &Nsnap, Num);
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: ppid/pgrp/sid N=%ld",
                        atomic_load_explicit(&N, memory_order_acquire));

    for (int I = 0; I < 7; I++)
    {
        __AppendField__(__Buf__, __Cap__, &Nsnap, "0");
    }
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: zeros(7) N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    UnsignedToStringEx(__Proc__->Times.UserUsec, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &Nsnap, Num);
    UnsignedToStringEx(__Proc__->Times.SysUsec, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &Nsnap, Num);
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: utime/stime N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    for (int J = 0; J < 6; J++)
    {
        __AppendField__(__Buf__, __Cap__, &Nsnap, (J == 4) ? "1" : "0");
    }
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: six fields N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    UnsignedToStringEx(__Proc__->Times.StartTick, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &Nsnap, Num);
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: starttime N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendField__(__Buf__, __Cap__, &Nsnap, "0");
    __AppendField__(__Buf__, __Cap__, &Nsnap, "0");
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: vsize/rss N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    __AppendChar__(__Buf__, __Cap__, &Nsnap, '\n');
    atomic_store_explicit(&N, Nsnap, memory_order_release);
    LOGPROCHELPC_PDebug("stat: final N=%ld", atomic_load_explicit(&N, memory_order_acquire));

    long FinalN = atomic_load_explicit(&N, memory_order_acquire);
    if ((__Cap__ - FinalN) >= 1)
    {
        __Buf__[FinalN] = '\0';
    }
    return FinalN;
}

long
ProcFsListFds(PosixProc* __Proc__, char* __Buf__, long __Cap__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Cap__ <= 0)
    {
        PushError("ProcFsListFds", LOGPROCHELPC_PError, "Bad args to ProcFsListFds", -BadArguments);
        return -BadArguments;
    }
    if (Probe_IF_Error(__Proc__->Fds) || !__Proc__->Fds)
    {
        LOGPROCHELPC_PWarn("Proc has no FDs to list in ProcFsListFds");
        __Buf__[0] = '\0';
        return Nothing;
    }

    atomic_long N;
    atomic_store_explicit(&N, 0, memory_order_relaxed);

    for (long I = 0; I < __Proc__->Fds->Cap; I++)
    {
        PosixFd* E = &__Proc__->Fds->Entries[I];
        if (E->Fd < 0)
        {
            continue;
        }

        long Nsnap = atomic_load_explicit(&N, memory_order_relaxed);

        __AppendStr__(__Buf__, __Cap__, &Nsnap, "fd:");
        __AppendU64Dec__(__Buf__, __Cap__, &Nsnap, (uint64_t)E->Fd);

        __AppendStr__(__Buf__, __Cap__, &Nsnap, " type:");
        __AppendStr__(__Buf__,
                      __Cap__,
                      &Nsnap,
                      E->IsFile ? "file" : (E->IsChar ? "char" : (E->IsBlock ? "block" : "none")));

        __AppendStr__(__Buf__, __Cap__, &Nsnap, " flags:0x");
        __AppendU64Hex__(__Buf__, __Cap__, &Nsnap, (uint64_t)E->Flags);

        __AppendStr__(__Buf__, __Cap__, &Nsnap, " refcnt:");
        __AppendU64Dec__(__Buf__, __Cap__, &Nsnap, (uint64_t)(E->Refcnt > 0 ? E->Refcnt : 0));

        __AppendChar__(__Buf__, __Cap__, &Nsnap, '\n');

        atomic_store_explicit(&N, Nsnap, memory_order_release);
        if (Nsnap >= __Cap__)
        {
            break;
        }
    }
    long FinalN = atomic_load_explicit(&N, memory_order_acquire);
    return (FinalN > __Cap__) ? __Cap__ : FinalN;
}

long
ProcFsWriteState(PosixProc* __Proc__, const char* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        PushError(
            "ProcFsWriteState", LOGPROCHELPC_PError, "Bad args to ProcFsWriteState", -BadArguments);
        return -BadArguments;
    }

    if (strncmp(__Buf__, "stop", (size_t)__Len__) == Nothing)
    {
        if (__Proc__->MainThread)
        {
            atomic_store_explicit((atomic_int*)&__Proc__->MainThread->State,
                                  ThreadStateBlocked,
                                  memory_order_release);
        }
        return __Len__;
    }
    if (strncmp(__Buf__, "cont", (size_t)__Len__) == Nothing)
    {
        if (__Proc__->MainThread)
        {
            atomic_store_explicit(
                (atomic_int*)&__Proc__->MainThread->State, ThreadStateReady, memory_order_release);
        }
        return __Len__;
    }
    return -BadEntry;
}

long
ProcFsWriteExec(PosixProc* __Proc__, const char* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        PushError(
            "ProcFsWriteExec", LOGPROCHELPC_PError, "Bad args to ProcFsWriteExec", -BadArguments);
        return -BadArguments;
    }

    char Path[256];
    long Copy = (__Len__ < 255) ? __Len__ : 255;
    strncpy(Path, __Buf__, (size_t)Copy);
    Path[Copy] = '\0';

    const char* const Argv[] = {Path, NULL};
    const char* const Envp[] = {NULL};

    return (PosixProcExecve(__Proc__, Path, Argv, Envp) == SysOkay) ? __Len__ : -NotCanonical;
}

long
ProcFsWriteSignal(PosixProc* __Proc__, const char* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        PushError("ProcFsWriteSignal",
                  LOGPROCHELPC_PError,
                  "Bad args to ProcFsWriteSignal",
                  -BadArguments);
        return -BadArguments;
    }

    if (strncmp(__Buf__, "TERM", (size_t)__Len__) == Nothing)
    {
        return PosixKill(__Proc__->Pid, SigTerm) == SysOkay ? __Len__ : -BadReturn;
    }
    if (strncmp(__Buf__, "KILL", (size_t)__Len__) == Nothing)
    {
        return PosixKill(__Proc__->Pid, SigKill) == SysOkay ? __Len__ : -BadReturn;
    }
    if (strncmp(__Buf__, "INT", (size_t)__Len__) == Nothing)
    {
        return PosixKill(__Proc__->Pid, SigInt) == SysOkay ? __Len__ : -BadReturn;
    }
    if (strncmp(__Buf__, "STOP", (size_t)__Len__) == Nothing)
    {
        return PosixKill(__Proc__->Pid, SigStop) == SysOkay ? __Len__ : -BadReturn;
    }
    if (strncmp(__Buf__, "CONT", (size_t)__Len__) == Nothing)
    {
        return PosixKill(__Proc__->Pid, SigCont) == SysOkay ? __Len__ : -BadReturn;
    }

    PushError(
        "ProcFsWriteSignal", LOGPROCHELPC_PError, "Unknown signal in ProcFsWriteSignal", -BadEntry);
    return -BadEntry;
}