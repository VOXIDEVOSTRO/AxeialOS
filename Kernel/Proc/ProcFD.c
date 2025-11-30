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
    char*    Buf;
    long     Cap;
    long     Head;
    long     Tail;
    long     Len;
    SpinLock Lock;
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
        return NULL;
    }
    return &__Tab__->Entries[__Fd__];
}

int
__FindFreeFd__(PosixFdTable* __Tab__, int __Start__)
{
    long I = (__Start__ < 0) ? 0 : (long)__Start__;
    for (; I < __Tab__->Cap; I++)
    {
        if (__Tab__->Entries[I].Fd < 0)
        {
            return (int)I;
        }
    }
    return -1;
}

static void
__InitEntry__(PosixFd* __E__)
{
    __E__->Fd      = -1;
    __E__->Flags   = 0;
    __E__->Obj     = NULL;
    __E__->Refcnt  = 0;
    __E__->IsFile  = 0;
    __E__->IsChar  = 0;
    __E__->IsBlock = 0;
}

static long
__PipeWrite__(PosixPipeT* __P__, const void* __Buf__, long __Len__)
{
    long W = 0;
    AcquireSpinLock(&__P__->Lock);
    while (W < __Len__ && __P__->Len < __P__->Cap)
    {
        __P__->Buf[__P__->Tail] = ((const char*)__Buf__)[W];
        __P__->Tail             = (__P__->Tail + 1) % __P__->Cap;
        __P__->Len++;
        W++;
    }
    ReleaseSpinLock(&__P__->Lock);
    return W;
}

static long
__PipeRead__(PosixPipeT* __P__, void* __Buf__, long __Len__)
{
    long R = 0;
    AcquireSpinLock(&__P__->Lock);
    while (R < __Len__ && __P__->Len > 0)
    {
        ((char*)__Buf__)[R] = __P__->Buf[__P__->Head];
        __P__->Head         = (__P__->Head + 1) % __P__->Cap;
        __P__->Len--;
        R++;
    }
    ReleaseSpinLock(&__P__->Lock);
    return R;
}

int
PosixFdInit(PosixFdTable* __Tab__, long __Cap__)
{
    __Tab__->Entries  = (PosixFd*)KMalloc(sizeof(PosixFd) * (size_t)__Cap__);
    __Tab__->Count    = 0;
    __Tab__->Cap      = __Cap__;
    __Tab__->StdinFd  = -1;
    __Tab__->StdoutFd = -1;
    __Tab__->StderrFd = -1;
    InitializeSpinLock(&__Tab__->Lock, "PosixFdTable");
    long I = 0;
    for (I = 0; I < __Cap__; I++)
    {
        __InitEntry__(&__Tab__->Entries[I]);
    }
    return 0;
}

int
PosixOpen(PosixFdTable* __Tab__, const char* __Path__, long __Flags__, long __Mode__)
{
    if (!__Tab__ || !__Path__)
    {
        return -1;
    }

    AcquireSpinLock(&__Tab__->Lock);
    int NewFd = __FindFreeFd__(__Tab__, 0);
    if (NewFd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }

    File* F = VfsOpen(__Path__, __Flags__);
    if (!F)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }

    PosixFd* E = &__Tab__->Entries[NewFd];
    E->Fd      = NewFd;
    E->Flags   = __Flags__;
    E->Obj     = (void*)F;
    E->Refcnt  = 1;
    E->IsFile  = 1;
    E->IsChar  = 0;
    E->IsBlock = 0;
    __Tab__->Count++;
    ReleaseSpinLock(&__Tab__->Lock);
    return NewFd;
}

int
PosixClose(PosixFdTable* __Tab__, int __Fd__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    if (--E->Refcnt <= 0)
    {
        if (E->IsFile && E->Obj)
        {
            VfsClose((File*)E->Obj);
        }
        if (E->IsChar && E->Obj)
        {
            PosixPipeT* P = (PosixPipeT*)E->Obj;
            KFree(P->Buf);
            KFree(P);
        }
        __InitEntry__(E);
        __Tab__->Count--;
    }
    ReleaseSpinLock(&__Tab__->Lock);
    return 0;
}

long
PosixRead(PosixFdTable* __Tab__, int __Fd__, void* __Buf__, long __Len__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    if (E->IsFile)
    {
        long R = VfsRead((File*)E->Obj, __Buf__, __Len__);
        ReleaseSpinLock(&__Tab__->Lock);
        return R;
    }
    if (E->IsChar)
    {
        long R = __PipeRead__((PosixPipeT*)E->Obj, __Buf__, __Len__);
        ReleaseSpinLock(&__Tab__->Lock);
        return R;
    }
    ReleaseSpinLock(&__Tab__->Lock);
    return -1;
}

long
PosixWrite(PosixFdTable* __Tab__, int __Fd__, const void* __Buf__, long __Len__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        PError("PosixWrite: bad fd=%d\n", __Fd__);
        return -1;
    }

    PDebug("PosixWrite: fd=%d IsFile=%d IsChar=%d IsBlock=%d\n",
           __Fd__,
           E->IsFile,
           E->IsChar,
           E->IsBlock);

    if (E->IsFile)
    {
        PDebug("PosixWrite: dispatching to VfsWrite, len=%ld\n", __Len__);
        long W = VfsWrite((File*)E->Obj, __Buf__, __Len__);
        PDebug("PosixWrite: VfsWrite returned %ld\n", W);
        ReleaseSpinLock(&__Tab__->Lock);
        return W;
    }

    if (E->IsChar)
    {
        PDebug("PosixWrite: dispatching to __PipeWrite__, len=%ld\n", __Len__);
        long W = __PipeWrite__((PosixPipeT*)E->Obj, __Buf__, __Len__);
        PDebug("PosixWrite: __PipeWrite__ returned %ld\n", W);
        ReleaseSpinLock(&__Tab__->Lock);
        return W;
    }

    ReleaseSpinLock(&__Tab__->Lock);
    PError("PosixWrite: fd=%d not file/char, returning -1\n", __Fd__);
    return -1;
}

long
PosixLseek(PosixFdTable* __Tab__, int __Fd__, long __Off__, int __Wh__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0 || !E->IsFile)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    long R = VfsLseek((File*)E->Obj, __Off__, __Wh__);
    ReleaseSpinLock(&__Tab__->Lock);
    return R;
}

int
PosixDup(PosixFdTable* __Tab__, int __Fd__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    int NewFd = __FindFreeFd__(__Tab__, 0);
    if (NewFd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    PosixFd* N = &__Tab__->Entries[NewFd];
    *N         = *E;
    N->Fd      = NewFd;
    N->Refcnt++;
    if (N->IsFile && N->Obj)
    {
        ((File*)N->Obj)->Refcnt++;
    }
    __Tab__->Count++;
    ReleaseSpinLock(&__Tab__->Lock);
    return NewFd;
}

int
PosixDup2(PosixFdTable* __Tab__, int __OldFd__, int __NewFd__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __OldFd__);
    if (!E || E->Fd < 0 || !__IsValidFd__(__Tab__, __NewFd__))
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    if (__OldFd__ == __NewFd__)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return __NewFd__;
    }
    PosixFd* D = &__Tab__->Entries[__NewFd__];
    if (D->Fd >= 0)
    {
        int rc = PosixClose(__Tab__, __NewFd__);
        if (rc != 0)
        {
            ReleaseSpinLock(&__Tab__->Lock);
            return -1;
        }
    }
    *D    = *E;
    D->Fd = __NewFd__;
    D->Refcnt++;
    if (D->IsFile && D->Obj)
    {
        ((File*)D->Obj)->Refcnt++;
    }
    __Tab__->Count++;
    ReleaseSpinLock(&__Tab__->Lock);
    return __NewFd__;
}

int
PosixPipe(PosixFdTable* __Tab__, int __Pipefd__[2])
{
    AcquireSpinLock(&__Tab__->Lock);
    int Rd = __FindFreeFd__(__Tab__, 0);
    int Wr = __FindFreeFd__(__Tab__, Rd + 1);
    if (Rd < 0 || Wr < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    PosixPipeT* P = (PosixPipeT*)KMalloc(sizeof(PosixPipeT));
    P->Cap        = 4096;
    P->Buf        = (char*)KMalloc((size_t)P->Cap);
    P->Head       = 0;
    P->Tail       = 0;
    P->Len        = 0;
    InitializeSpinLock(&P->Lock, "PosixPipeT");

    PosixFd* ER = &__Tab__->Entries[Rd];
    PosixFd* EW = &__Tab__->Entries[Wr];
    __InitEntry__(ER);
    __InitEntry__(EW);

    ER->Fd      = Rd;
    ER->Flags   = VFlgRDONLY;
    ER->Obj     = (void*)P;
    ER->Refcnt  = 1;
    ER->IsFile  = 0;
    ER->IsChar  = 1;
    ER->IsBlock = 0;

    EW->Fd      = Wr;
    EW->Flags   = VFlgWRONLY;
    EW->Obj     = (void*)P;
    EW->Refcnt  = 1;
    EW->IsFile  = 0;
    EW->IsChar  = 1;
    EW->IsBlock = 0;

    __Tab__->Count += 2;
    __Pipefd__[0] = Rd;
    __Pipefd__[1] = Wr;
    ReleaseSpinLock(&__Tab__->Lock);
    return 0;
}

int
PosixFcntl(PosixFdTable* __Tab__, int __Fd__, int __Cmd__, long __Arg__ __attribute__((unused)))
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    if (__Cmd__ == 0)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return E->Flags;
    }
    if (__Cmd__ == 1)
    {
        int NewFd = __FindFreeFd__(__Tab__, 0);
        if (NewFd < 0)
        {
            ReleaseSpinLock(&__Tab__->Lock);
            return -1;
        }
        PosixFd* N = &__Tab__->Entries[NewFd];
        *N         = *E;
        N->Fd      = NewFd;
        N->Refcnt++;
        if (N->IsFile && N->Obj)
        {
            ((File*)N->Obj)->Refcnt++;
        }
        __Tab__->Count++;
        ReleaseSpinLock(&__Tab__->Lock);
        return NewFd;
    }
    ReleaseSpinLock(&__Tab__->Lock);
    return -1;
}

int
PosixIoctl(PosixFdTable* __Tab__, int __Fd__, unsigned long __Cmd__, void* __Arg__)
{
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0 || !E->IsFile)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    int R = VfsIoctl((File*)E->Obj, __Cmd__, __Arg__);
    ReleaseSpinLock(&__Tab__->Lock);
    return R;
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
    AcquireSpinLock(&__Tab__->Lock);
    PosixFd* E = __GetEntry__(__Tab__, __Fd__);
    if (!E || E->Fd < 0 || !E->IsFile)
    {
        ReleaseSpinLock(&__Tab__->Lock);
        return -1;
    }
    int R = VfsFstats((File*)E->Obj, __Out__);
    ReleaseSpinLock(&__Tab__->Lock);
    return R;
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