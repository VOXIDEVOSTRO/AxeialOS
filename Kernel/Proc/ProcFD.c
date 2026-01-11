#include <AllTypes.h>
#include <DevFS.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <POSIXFd.h>
#include <String.h>
#include <Sync.h>
#include <VFS.h>

/*Most of all POSIX Shimming live here,
    as well as on the Proc.c*/

typedef struct PosixPipeT
{
    char*       Buf;
    long        Cap;
    atomic_long Head;
    atomic_long Tail;
    atomic_long Len;
} PosixPipeT;

static int
__IsValidFd__(PosixFdTable* __Tab__, int __Fd__)
{
    return (__Fd__ >= 0 && (long)__Fd__ < __Tab__->Cap);
}

static PosixFd*
__GetEntry__(PosixFdTable* __Tab__, int __Fd__)
{
    if (!__IsValidFd__(__Tab__, __Fd__))
    {
        return Error_TO_Pointer(-NotCanonical);
    }
    return &__Tab__->Entries[__Fd__];
}

int
__FindFreeFd__(PosixFdTable* __Tab__, int __Start__)
{
    long I = (__Start__ < 0) ? 0 : (long)__Start__;
    for (; I < __Tab__->Cap; I++)
    {
        if (atomic_load_explicit(&__Tab__->Entries[I].Fd, memory_order_acquire) < 0)
        {
            return (int)I;
        }
    }
    return -NoSuch;
}

static void
__InitEntry__(PosixFd* __E__)
{
    atomic_store_explicit(&__E__->Fd, -1, memory_order_release);
    __E__->Flags = 0;
    __E__->Obj   = NULL;
    atomic_store_explicit(&__E__->Refcnt, 0, memory_order_release);
    __E__->IsFile  = 0;
    __E__->IsChar  = 0;
    __E__->IsBlock = 0;
}

static long
__PipeWrite__(PosixPipeT* __P__, const void* __Buf__, long __Len__)
{
    long W = 0;
    while (W < __Len__)
    {
        long len = atomic_load_explicit(&__P__->Len, memory_order_acquire);
        if (len >= __P__->Cap)
        {
            break;
        }
        long tail = atomic_load_explicit(&__P__->Tail, memory_order_relaxed);
        long head = atomic_load_explicit(&__P__->Head, memory_order_relaxed);
        long cap  = __P__->Cap;

        long next_tail = (tail + 1) % cap;
        if (next_tail == head)
        {
            break;
        }

        __P__->Buf[tail] = ((const char*)__Buf__)[W];

        bool tail_ok = atomic_compare_exchange_weak_explicit(
            &__P__->Tail, &tail, next_tail, memory_order_acq_rel, memory_order_relaxed);

        if (!tail_ok)
        {
            continue;
        }

        long expected_len = len;
        if (atomic_compare_exchange_weak_explicit(
                &__P__->Len, &expected_len, len + 1, memory_order_acq_rel, memory_order_relaxed))
        {
            W++;
        }
    }
    return W;
}

static long
__PipeRead__(PosixPipeT* __P__, void* __Buf__, long __Len__)
{
    long R = 0;
    while (R < __Len__)
    {
        long len = atomic_load_explicit(&__P__->Len, memory_order_acquire);
        if (len <= 0)
        {
            break;
        }
        long head = atomic_load_explicit(&__P__->Head, memory_order_relaxed);
        long tail = atomic_load_explicit(&__P__->Tail, memory_order_relaxed);
        long cap  = __P__->Cap;

        if (head == tail)
        {
            break;
        }

        ((char*)__Buf__)[R] = __P__->Buf[head];

        long next_head = (head + 1) % cap;
        bool head_ok   = atomic_compare_exchange_weak_explicit(
            &__P__->Head, &head, next_head, memory_order_acq_rel, memory_order_relaxed);

        if (!head_ok)
        {
            continue;
        }

        long expected_len = len;
        if (atomic_compare_exchange_weak_explicit(
                &__P__->Len, &expected_len, len - 1, memory_order_acq_rel, memory_order_relaxed))
        {
            R++;
        }
    }
    return R;
}

int
PosixFdInit(PosixFdTable* __Tab__, long __Cap__)
{
    __Tab__->Entries = (PosixFd*)KMalloc(sizeof(PosixFd) * (size_t)__Cap__);
    atomic_store_explicit(&__Tab__->Count, 0, memory_order_release);
    __Tab__->Cap      = __Cap__;
    __Tab__->StdinFd  = -1;
    __Tab__->StdoutFd = -1;
    __Tab__->StderrFd = -1;

    long I = 0;
    for (I = 0; I < __Cap__; I++)
    {
        __InitEntry__(&__Tab__->Entries[I]);
    }
    return SysOkay;
}

int
PosixOpen(PosixFdTable* __Tab__, const char* __Path__, long __Flags__, long __Mode__)
{
    if (Probe_IF_Error(__Tab__) || !__Tab__ || Probe_IF_Error(__Path__) || !__Path__)
    {
        return -NotCanonical;
    }

    int NewFd;
    for (;;)
    {
        NewFd = __FindFreeFd__(__Tab__, 0);
        if (NewFd < 0)
        {
            return -TooLess;
        }
        long expected = SysErro;
        if (atomic_compare_exchange_weak_explicit(&__Tab__->Entries[NewFd].Fd,
                                                  &expected,
                                                  NewFd,
                                                  memory_order_acq_rel,
                                                  memory_order_relaxed))
        {
            break;
        }
    }

    File* F = VfsOpen(__Path__, __Flags__);
    if (Probe_IF_Error(F) || !F)
    {
        atomic_store_explicit(&__Tab__->Entries[NewFd].Fd, -1, memory_order_release);
        return -BadEntity;
    }

    PosixFd* E = &__Tab__->Entries[NewFd];
    E->Flags   = __Flags__;
    E->Obj     = (void*)F;
    atomic_store_explicit(&E->Refcnt, 1, memory_order_release);
    E->IsFile  = 1;
    E->IsChar  = 0;
    E->IsBlock = 0;

    atomic_fetch_add_explicit(&__Tab__->Count, 1, memory_order_acq_rel);
    return NewFd;
}

int
PosixClose(PosixFdTable* __Tab__, int __Fd__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0)
    {
        return -BadEntry;
    }

    int old = atomic_fetch_sub_explicit(&E->Refcnt, 1, memory_order_acq_rel);
    if (old <= 1)
    {
        if (E->IsFile && E->Obj)
        {
            VfsClose((File*)E->Obj);
        }
        if (E->IsChar && E->Obj)
        {
            PosixPipeT* P = (PosixPipeT*)E->Obj;
            KFree(P->Buf, NULL);
            KFree(P, NULL);
        }
        __InitEntry__(E);
        atomic_fetch_sub_explicit(&__Tab__->Count, 1, memory_order_acq_rel);
    }
    return SysOkay;
}

long
PosixRead(PosixFdTable* __Tab__, int __Fd__, void* __Buf__, long __Len__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0)
    {
        return -BadEntry;
    }
    if (E->IsFile)
    {
        return VfsRead((File*)E->Obj, __Buf__, __Len__);
    }
    if (E->IsChar)
    {
        return __PipeRead__((PosixPipeT*)E->Obj, __Buf__, __Len__);
    }
    return -NoRead;
}

long
PosixWrite(PosixFdTable* __Tab__, int __Fd__, const void* __Buf__, long __Len__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0)
    {
        return -BadEntry;
    }

    if (E->IsFile)
    {
        return VfsWrite((File*)E->Obj, __Buf__, __Len__);
    }

    if (E->IsChar)
    {
        return __PipeWrite__((PosixPipeT*)E->Obj, __Buf__, __Len__);
    }

    return -NoWrite;
}

long
PosixLseek(PosixFdTable* __Tab__, int __Fd__, long __Off__, int __Wh__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0 ||
        Probe_IF_Error(E->IsFile) || !E->IsFile)
    {
        return -BadEntry;
    }
    return VfsLseek((File*)E->Obj, __Off__, __Wh__);
}

int
PosixDup(PosixFdTable* __Tab__, int __Fd__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0)
    {
        return -BadEntry;
    }

    int NewFd;
    for (;;)
    {
        NewFd = __FindFreeFd__(__Tab__, 0);
        if (NewFd < 0)
        {
            return -TooLess;
        }
        long expected = SysErro;
        if (atomic_compare_exchange_weak_explicit(&__Tab__->Entries[NewFd].Fd,
                                                  &expected,
                                                  NewFd,
                                                  memory_order_acq_rel,
                                                  memory_order_relaxed))
        {
            break;
        }
    }

    PosixFd* N = &__Tab__->Entries[NewFd];
    *N         = *E;
    atomic_store_explicit(&N->Fd, NewFd, memory_order_release);
    atomic_fetch_add_explicit(&N->Refcnt, 1, memory_order_acq_rel);
    if (N->IsFile && N->Obj)
    {
        atomic_fetch_add_explicit(&((File*)N->Obj)->Refcnt, 1, memory_order_acq_rel);
    }
    atomic_fetch_add_explicit(&__Tab__->Count, 1, memory_order_acq_rel);
    return NewFd;
}

int
PosixDup2(PosixFdTable* __Tab__, int __OldFd__, int __NewFd__)
{
    PosixFd* E = __GetEntry__(__Tab__, __OldFd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0 ||
        !__IsValidFd__(__Tab__, __NewFd__))
    {
        return -BadEntry;
    }
    if (__OldFd__ == __NewFd__)
    {
        return __NewFd__;
    }

    PosixFd* D = &__Tab__->Entries[__NewFd__];
    if (atomic_load_explicit(&D->Fd, memory_order_acquire) >= 0)
    {
        int rc = PosixClose(__Tab__, __NewFd__);
        if (rc != SysOkay)
        {
            return -ErrReturn;
        }
    }

    *D = *E;
    atomic_store_explicit(&D->Fd, __NewFd__, memory_order_release);
    atomic_fetch_add_explicit(&D->Refcnt, 1, memory_order_acq_rel);
    if (D->IsFile && D->Obj)
    {
        atomic_fetch_add_explicit(&((File*)D->Obj)->Refcnt, 1, memory_order_acq_rel);
    }
    atomic_fetch_add_explicit(&__Tab__->Count, 1, memory_order_acq_rel);
    return __NewFd__;
}

int
PosixPipe(PosixFdTable* __Tab__, int __Pipefd__[2])
{
    int Rd, Wr;

    for (;;)
    {
        Rd = __FindFreeFd__(__Tab__, 0);
        if (Rd < 0)
        {
            return -NoOperations;
        }
        long expected = SysErro;
        if (atomic_compare_exchange_weak_explicit(&__Tab__->Entries[Rd].Fd,
                                                  &expected,
                                                  Rd,
                                                  memory_order_acq_rel,
                                                  memory_order_relaxed))
        {
            break;
        }
    }

    for (;;)
    {
        Wr = __FindFreeFd__(__Tab__, Rd + 1);
        if (Wr < 0)
        {
            atomic_store_explicit(&__Tab__->Entries[Rd].Fd, -1, memory_order_release);
            return -NoOperations;
        }
        long expected = SysErro;
        if (atomic_compare_exchange_weak_explicit(&__Tab__->Entries[Wr].Fd,
                                                  &expected,
                                                  Wr,
                                                  memory_order_acq_rel,
                                                  memory_order_relaxed))
        {
            break;
        }
    }

    PosixPipeT* P = (PosixPipeT*)KMalloc(sizeof(PosixPipeT));
    P->Cap        = 4096;
    P->Buf        = (char*)KMalloc((size_t)P->Cap);
    atomic_store_explicit(&P->Head, 0, memory_order_release);
    atomic_store_explicit(&P->Tail, 0, memory_order_release);
    atomic_store_explicit(&P->Len, 0, memory_order_release);

    PosixFd* ER = &__Tab__->Entries[Rd];
    PosixFd* EW = &__Tab__->Entries[Wr];
    __InitEntry__(ER);
    __InitEntry__(EW);

    atomic_store_explicit(&ER->Fd, Rd, memory_order_release);
    ER->Flags = VFlgRDONLY;
    ER->Obj   = (void*)P;
    atomic_store_explicit(&ER->Refcnt, 1, memory_order_release);
    ER->IsFile  = 0;
    ER->IsChar  = 1;
    ER->IsBlock = 0;

    atomic_store_explicit(&EW->Fd, Wr, memory_order_release);
    EW->Flags = VFlgWRONLY;
    EW->Obj   = (void*)P;
    atomic_store_explicit(&EW->Refcnt, 1, memory_order_release);
    EW->IsFile  = 0;
    EW->IsChar  = 1;
    EW->IsBlock = 0;

    atomic_fetch_add_explicit(&__Tab__->Count, 2, memory_order_acq_rel);
    __Pipefd__[0] = Rd;
    __Pipefd__[1] = Wr;
    return SysOkay;
}

int
PosixFcntl(PosixFdTable* __Tab__, int __Fd__, int __Cmd__, long __Arg__ __attribute__((unused)))
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0)
    {
        return -BadEntry;
    }
    if (__Cmd__ == 0)
    {
        return E->Flags;
    }
    if (__Cmd__ == 1)
    {
        int NewFd;
        for (;;)
        {
            NewFd = __FindFreeFd__(__Tab__, 0);
            if (NewFd < 0)
            {
                return -TooLess;
            }
            long expected = SysErro;
            if (atomic_compare_exchange_weak_explicit(&__Tab__->Entries[NewFd].Fd,
                                                      &expected,
                                                      NewFd,
                                                      memory_order_acq_rel,
                                                      memory_order_relaxed))
            {
                break;
            }
        }
        PosixFd* N = &__Tab__->Entries[NewFd];
        *N         = *E;
        atomic_store_explicit(&N->Fd, NewFd, memory_order_release);
        atomic_fetch_add_explicit(&N->Refcnt, 1, memory_order_acq_rel);
        if (N->IsFile && N->Obj)
        {
            atomic_fetch_add_explicit(&((File*)N->Obj)->Refcnt, 1, memory_order_acq_rel);
        }
        atomic_fetch_add_explicit(&__Tab__->Count, 1, memory_order_acq_rel);
        return NewFd;
    }
    return -NotCanonical;
}

int
PosixIoctl(PosixFdTable* __Tab__, int __Fd__, unsigned long __Cmd__, void* __Arg__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0 ||
        Probe_IF_Error(E->IsFile) || !E->IsFile)
    {
        return -BadEntry;
    }
    return VfsIoctl((File*)E->Obj, __Cmd__, __Arg__);
}

int
PosixAccess(PosixFdTable* __Tab__ __attribute__((unused)), const char* __Path__, long __Mode__)
{
    return VfsAccess(__Path__, __Mode__);
}

int
PosixStatPath(const char* __Path__, VfsStat* __Out__)
{
    return VfsStats(__Path__, __Out__);
}

int
PosixFstat(PosixFdTable* __Tab__, int __Fd__, VfsStat* __Out__)
{
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (Probe_IF_Error(E) || !E || atomic_load_explicit(&E->Fd, memory_order_acquire) < 0 ||
        Probe_IF_Error(E->IsFile) || !E->IsFile)
    {
        return -BadEntry;
    }
    return VfsFstats((File*)E->Obj, __Out__);
}

int
PosixMkdir(const char* __Path__, long __Mode__)
{
    VfsPerm P;
    P.Mode = __Mode__;
    P.Uid  = 0;
    P.Gid  = 0;
    return VfsMkdir(__Path__, P);
}

int
PosixRmdir(const char* __Path__)
{
    return VfsRmdir(__Path__);
}

int
PosixUnlink(const char* __Path__)
{
    return VfsUnlink(__Path__);
}

int
PosixRename(const char* __Old__, const char* __New__)
{
    return VfsRename(__Old__, __New__, 0);
}