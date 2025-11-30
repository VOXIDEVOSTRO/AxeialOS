#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <POSIXFd.h>
#include <POSIXProc.h>
#include <POSIXSignals.h>
#include <String.h>

static inline long
__AppendStr__(char* __Buf__, long __Cap__, long* __Off__, const char* __Str__)
{
    if (!__Buf__ || !__Off__ || !__Str__ || __Cap__ <= 0)
    {
        PError("__AppendStr__: bad args\n");
        return -1;
    }

    long N = *__Off__;
    if (N < 0)
    {
        PError("__AppendStr__: negative N=%ld\n", N);
        return -1;
    }
    if (N >= __Cap__)
    {
        PDebug("__AppendStr__: full N=%ld Cap=%ld\n", N, __Cap__);
        return 0;
    }

    long Rem = __Cap__ - N;
    long L   = (long)StringLength(__Str__);
    long C   = (L < Rem) ? L : Rem;

    if (C > 0)
    {
        __builtin_memcpy(__Buf__ + N, __Str__, (size_t)C);
        N += C;
        *__Off__ = N;
    }

    PDebug("__AppendStr__: wrote=%ld newN=%ld RemNow=%ld\n", C, N, (__Cap__ - N));
    return C;
}

static inline long
__AppendChar__(char* __Buf__, long __Cap__, long* __Off__, char __Ch__)
{
    if (!__Buf__ || !__Off__ || __Cap__ <= 0)
    {
        PError("__AppendChar__: bad args\n");
        return -1;
    }

    long N = *__Off__;
    if (N < 0)
    {
        PError("__AppendChar__: negative N=%ld\n", N);
        return -1;
    }
    if (N >= __Cap__)
    {
        PDebug("__AppendChar__: full N=%ld Cap=%ld\n", N, __Cap__);
        return 0;
    }

    __Buf__[N++] = __Ch__;
    *__Off__     = N;

    PDebug("__AppendChar__: wrote=1 newN=%ld RemNow=%ld\n", N, (__Cap__ - N));
    return 1;
}

static inline long
__AppendU64Dec__(char* __Buf__, long __Cap__, long* __Off__, uint64_t __V__)
{
    if (!__Buf__ || !__Off__ || __Cap__ <= 0)
    {
        PError("__AppendU64Dec__: bad args\n");
        return -1;
    }
    char Num[32];
    UnsignedToStringEx(__V__, Num, 10, 0);
    Num[31] = '\0'; /* belt-and-suspenders */
    return __AppendStr__(__Buf__, __Cap__, __Off__, Num);
}

static inline long
__AppendU64Hex__(char* __Buf__, long __Cap__, long* __Off__, uint64_t __V__)
{
    if (!__Buf__ || !__Off__ || __Cap__ <= 0)
    {
        PError("__AppendU64Hex__: bad args\n");
        return -1;
    }
    char Num[32];
    UnsignedToStringEx(__V__, Num, 16, 0);
    Num[31] = '\0';
    return __AppendStr__(__Buf__, __Cap__, __Off__, Num);
}

static inline long
__AppendU64Oct__(char* __Buf__, long __Cap__, long* __Off__, uint64_t __V__)
{
    if (!__Buf__ || !__Off__ || __Cap__ <= 0)
    {
        PError("__AppendU64Oct__: bad args\n");
        return -1;
    }
    char Num[32];
    UnsignedToStringEx(__V__, Num, 8, 0);
    Num[31] = '\0';
    return __AppendStr__(__Buf__, __Cap__, __Off__, Num);
}

long
ProcFsMakeStatus(PosixProc* __Proc__, char* __Buff__, long __Caps__)
{
    if (!__Proc__ || !__Buff__ || __Caps__ <= 0)
    {
        PError("ProcFsMakeStatus: bad args\n");
        return -1;
    }

    long N  = 0;
    char St = __ProcStateCode__(__Proc__);

    __AppendStr__(__Buff__, __Caps__, &N, "Name:\t");
    PDebug("Status Name N=%ld", N);
    __AppendStr__(__Buff__, __Caps__, &N, (__Proc__->Comm[0] ? __Proc__->Comm : "NA"));
    PDebug("Status Comm N=%ld", N);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');

    __AppendStr__(__Buff__, __Caps__, &N, "State:\t");
    __AppendChar__(__Buff__, __Caps__, &N, St);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status State N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Pid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Pid);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Pid N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "PPid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Ppid);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status PPid N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Pgrp:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Pgrp);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Pgrp N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Sid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Sid);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Sid N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Tty:\t");
    __AppendStr__(__Buff__, __Caps__, &N, (__Proc__->TtyName ? __Proc__->TtyName : "NA"));
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Tty N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Uid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Cred.Ruid);
    __AppendChar__(__Buff__, __Caps__, &N, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Cred.Euid);
    __AppendChar__(__Buff__, __Caps__, &N, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Cred.Suid);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Uid N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Gid:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Cred.Rgid);
    __AppendChar__(__Buff__, __Caps__, &N, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Cred.Egid);
    __AppendChar__(__Buff__, __Caps__, &N, '\t');
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->Cred.Sgid);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Gid N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Umask:\t0");
    __AppendU64Oct__(__Buff__, __Caps__, &N, (uint64_t)(__Proc__->Cred.Umask & 0777));
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Umask N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Threads:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)1);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Threads N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "SigPnd:\t");
    __AppendU64Hex__(__Buff__, __Caps__, &N, __Proc__->SigPending);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status SigPnd N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "SigBlk:\t");
    __AppendU64Hex__(__Buff__, __Caps__, &N, __Proc__->SigMask);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status SigBlk N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "SigIgn:\t");
    __AppendStr__(__Buff__, __Caps__, &N, "NA");
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status SigIgn N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "SigCgt:\t");
    __AppendStr__(__Buff__, __Caps__, &N, "NA");
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status SigCgt N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Utime(us):\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, __Proc__->Times.UserUsec);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Utime N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "Stime(us):\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, __Proc__->Times.SysUsec);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status Stime N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "StartTick:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, __Proc__->Times.StartTick);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status StartTick N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "CmdlineLen:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->CmdlineLen);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status CmdlineLen N=%ld", N);

    __AppendStr__(__Buff__, __Caps__, &N, "EnvironLen:\t");
    __AppendU64Dec__(__Buff__, __Caps__, &N, (uint64_t)__Proc__->EnvironLen);
    __AppendChar__(__Buff__, __Caps__, &N, '\n');
    PDebug("Status EnvironLen N=%ld", N);

    /* terminate if room remains */
    if ((__Caps__ - N) >= 1)
    {
        __Buff__[N] = '\0';
    }

    return N;
}

static inline long
__AppendField__(char* __Buff__, long __Caps__, long* __Off__, const char* __Field__)
{
    long w1 = __AppendChar__(__Buff__, __Caps__, __Off__, ' ');
    if (w1 <= 0)
    {
        return w1;
    }
    long w2 = __AppendStr__(__Buff__, __Caps__, __Off__, __Field__);
    return (w2 <= 0) ? w2 : (w1 + w2);
}

long
ProcFsMakeStat(PosixProc* __Proc__, char* __Buf__, long __Cap__)
{
    if (!__Proc__ || !__Buf__ || __Cap__ <= 0)
    {
        PError("ProcFsMakeStat: bad args\n");
        return -1;
    }

    long N  = 0;
    char St = __ProcStateCode__(__Proc__);
    char Num[64];

    UnsignedToStringEx((uint64_t)__Proc__->Pid, Num, 10, 0);
    __AppendStr__(__Buf__, __Cap__, &N, Num);
    PDebug("stat: pid N=%ld", N);

    __AppendChar__(__Buf__, __Cap__, &N, ' ');
    __AppendChar__(__Buf__, __Cap__, &N, '(');
    __AppendStr__(__Buf__, __Cap__, &N, (__Proc__->Comm[0] ? __Proc__->Comm : "unknown"));
    __AppendChar__(__Buf__, __Cap__, &N, ')');
    __AppendChar__(__Buf__, __Cap__, &N, ' ');
    __AppendChar__(__Buf__, __Cap__, &N, St);
    PDebug("stat: comm/state N=%ld", N);

    UnsignedToStringEx((uint64_t)__Proc__->Ppid, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &N, Num);
    UnsignedToStringEx((uint64_t)__Proc__->Pgrp, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &N, Num);
    UnsignedToStringEx((uint64_t)__Proc__->Sid, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &N, Num);
    PDebug("stat: ppid/pgrp/sid N=%ld", N);

    for (int I = 0; I < 7; I++)
    {
        __AppendField__(__Buf__, __Cap__, &N, "0");
    }
    PDebug("stat: zeros(7) N=%ld", N);

    UnsignedToStringEx(__Proc__->Times.UserUsec, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &N, Num);
    UnsignedToStringEx(__Proc__->Times.SysUsec, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &N, Num);
    PDebug("stat: utime/stime N=%ld", N);

    for (int J = 0; J < 6; J++)
    {
        __AppendField__(__Buf__, __Cap__, &N, (J == 4) ? "1" : "0");
    }
    PDebug("stat: six fields N=%ld", N);

    UnsignedToStringEx(__Proc__->Times.StartTick, Num, 10, 0);
    __AppendField__(__Buf__, __Cap__, &N, Num);
    PDebug("stat: starttime N=%ld", N);

    __AppendField__(__Buf__, __Cap__, &N, "0");
    __AppendField__(__Buf__, __Cap__, &N, "0");
    PDebug("stat: vsize/rss N=%ld", N);

    __AppendChar__(__Buf__, __Cap__, &N, '\n');
    PDebug("stat: final N=%ld", N);

    if ((__Cap__ - N) >= 1)
    {
        __Buf__[N] = '\0';
    }
    return N;
}

long
ProcFsListFds(PosixProc* __Proc__, char* __Buf__, long __Cap__)
{
    if (!__Proc__ || !__Buf__ || __Cap__ <= 0)
    {
        return -1;
    }
    if (!__Proc__->Fds)
    {
        __Buf__[0] = '\0';
        return 0;
    }

    long N = 0;
    for (long I = 0; I < __Proc__->Fds->Cap; I++)
    {
        PosixFd* E = &__Proc__->Fds->Entries[I];
        if (E->Fd < 0)
        {
            continue;
        }

        __AppendStr__(__Buf__, __Cap__, &N, "fd:");
        __AppendU64Dec__(__Buf__, __Cap__, &N, (uint64_t)E->Fd);

        __AppendStr__(__Buf__, __Cap__, &N, " type:");
        __AppendStr__(__Buf__,
                      __Cap__,
                      &N,
                      E->IsFile ? "file" : (E->IsChar ? "char" : (E->IsBlock ? "block" : "none")));

        __AppendStr__(__Buf__, __Cap__, &N, " flags:0x");
        __AppendU64Hex__(__Buf__, __Cap__, &N, (uint64_t)E->Flags);

        __AppendStr__(__Buf__, __Cap__, &N, " refcnt:");
        __AppendU64Dec__(__Buf__, __Cap__, &N, (uint64_t)(E->Refcnt > 0 ? E->Refcnt : 0));

        __AppendChar__(__Buf__, __Cap__, &N, '\n');
        if (N >= __Cap__)
        {
            break;
        }
    }
    return (N > __Cap__) ? __Cap__ : N;
}

long
ProcFsWriteState(PosixProc* __Proc__, const char* __Buf__, long __Len__)
{
    if (!__Proc__ || !__Buf__ || __Len__ <= 0)
    {
        return -1;
    }

    if (strncmp(__Buf__, "stop", (size_t)__Len__) == 0)
    {
        if (__Proc__->MainThread)
        {
            __Proc__->MainThread->State = ThreadStateBlocked;
        }
        return __Len__;
    }
    if (strncmp(__Buf__, "cont", (size_t)__Len__) == 0)
    {
        if (__Proc__->MainThread)
        {
            __Proc__->MainThread->State = ThreadStateReady;
        }
        return __Len__;
    }
    return -1;
}

long
ProcFsWriteExec(PosixProc* __Proc__, const char* __Buf__, long __Len__)
{
    if (!__Proc__ || !__Buf__ || __Len__ <= 0)
    {
        return -1;
    }

    char Path[256];
    long Copy = (__Len__ < 255) ? __Len__ : 255;
    strncpy(Path, __Buf__, (size_t)Copy);
    Path[Copy] = '\0';

    const char* const Argv[] = {Path, NULL};
    const char* const Envp[] = {NULL};

    return (PosixProcExecve(__Proc__, Path, Argv, Envp) == 0) ? __Len__ : -1;
}
long
ProcFsWriteSignal(PosixProc* __Proc__, const char* __Buf__, long __Len__)
{
    if (!__Proc__ || !__Buf__ || __Len__ <= 0)
    {
        return -1;
    }

    if (strncmp(__Buf__, "TERM", (size_t)__Len__) == 0)
    {
        return PosixKill(__Proc__->Pid, SigTerm) == 0 ? __Len__ : -1;
    }
    if (strncmp(__Buf__, "KILL", (size_t)__Len__) == 0)
    {
        return PosixKill(__Proc__->Pid, SigKill) == 0 ? __Len__ : -1;
    }
    if (strncmp(__Buf__, "INT", (size_t)__Len__) == 0)
    {
        return PosixKill(__Proc__->Pid, SigInt) == 0 ? __Len__ : -1;
    }
    if (strncmp(__Buf__, "STOP", (size_t)__Len__) == 0)
    {
        return PosixKill(__Proc__->Pid, SigStop) == 0 ? __Len__ : -1;
    }
    if (strncmp(__Buf__, "CONT", (size_t)__Len__) == 0)
    {
        return PosixKill(__Proc__->Pid, SigCont) == 0 ? __Len__ : -1;
    }
    return -1;
}