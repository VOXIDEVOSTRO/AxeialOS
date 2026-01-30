#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <String.h>
#include <VFS.h>
#include <__AXEKCONF__.h>

#ifdef LOGVFSC_Debug
#    define LOGVFSC_PDebug(fmt, ...) PDebug("[KERNEL>>VFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSC_PDebug(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSC_Logs
#    define LOGVFSC_PError(fmt, ...) PError("[KERNEL>>VFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSC_PError(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSC_Logs
#    define LOGVFSC_PWarn(fmt, ...) PWarn("[KERNEL>>VFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSC_PWarn(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSC_Logs
#    define LOGVFSC_PInfo(fmt, ...) PInfo("[KERNEL>>VFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSC_PInfo(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSC_Logs
#    define LOGVFSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>VFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSC_PSuccess(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*extremely unix-like VFS*/

static const long __MaxFsTypes__ = 32;
static const long __MaxMounts__  = 64;

static const FsType* __FsReg__[32];
static long          __FsCount__ = 0;

typedef struct __MountEntry__
{
    Superblock* Sb;
    char        Path[1024];

} __MountEntry__;

static __MountEntry__ __Mounts__[64];
static long           __MountCount__ = 0;

static Vnode*  __RootNode__ = 0;
static Dentry* __RootDe__   = 0;

static long  __Umask__          = 0;
static long  __MaxName__        = 256;
static long  __MaxPath__        = 1024;
static long  __DirCacheLimit__  = 0;
static long  __FileCacheLimit__ = 0;
static long  __IoBlockSize__    = 0;
static char  __DefaultFs__[64]  = {0};
static Mutex VfsLock;

static int
__is_sep__(char c)
{
    return c == '/';
}
static const char*
__skip_sep__(const char* __Path)
{
    while (__Path && __is_sep__(*__Path))
    {
        __Path++;
    }
    return __Path;
}
static long
__next_comp__(const char* __Path, char* __Output, long __Cap)
{
    if (Probe_IF_Error(__Path) || !__Path || !*__Path)
    {
        PushError("__next_comp__", LOGVFSC_PError, "no more components in path", Nothing);
        return Nothing;
    }
    const char* s = __Path;
    long        N = 0;
    while (*s && !__is_sep__(*s))
    {
        if (N + 1 < __Cap)
        {
            __Output[N++] = *s;
        }
        s++;
    }
    __Output[N] = 0;
    return N;
}

static Dentry*
__alloc_dentry__(const char* __Name__, Dentry* __Parent__, Vnode* __Node__)
{
    Dentry* De = (Dentry*)KMalloc(sizeof(Dentry));
    if (Probe_IF_Error(De) || !De)
    {
        PushError("__alloc_dentry__", LOGVFSC_PError, "failed to allocate dentry", -BadAllocation);
        return Error_TO_Pointer(-BadAllocation);
    }

    De->Name   = __Name__;
    De->Parent = __Parent__;
    De->Node   = __Node__;
    De->Flags  = 0;
    return De;
}

static Dentry*
__walk__(Vnode* __StartNode__, Dentry* __StartDe__, const char* __Path__)
{
    if (Probe_IF_Error(__StartNode__) || !__StartNode__ || Probe_IF_Error(__Path__) || !__Path__)
    {
        PushError("__walk__", LOGVFSC_PError, "bad arguments", -NotCanonical);
        return Error_TO_Pointer(-NotCanonical);
    }
    const char* __Path = __Path__;
    if (__is_sep__(*__Path))
    {
        __Path = __skip_sep__(__Path);
    }
    Vnode*  Cur    = __StartNode__;
    Dentry* Parent = __StartDe__;
    char    Comp[256];
    while (*__Path)
    {
        long N = __next_comp__(__Path, Comp, sizeof(Comp));
        if (N <= 0)
        {
            break;
        }
        while (*__Path && !__is_sep__(*__Path))
        {
            __Path++;
        }
        __Path = __skip_sep__(__Path);
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            PushError("__walk__", LOGVFSC_PError, "cannot lookup on current vnode", -NoOperations);
            return Error_TO_Pointer(-NoOperations);
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Comp);
        if (Probe_IF_Error(Next) || !Next)
        {
            PushError(
                "__walk__", LOGVFSC_PError, "failed to lookup component in path", -CannotLookup);
            return Error_TO_Pointer(-CannotLookup);
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            PushError("__walk__",
                      LOGVFSC_PError,
                      "failed to allocate memory for component duplicate",
                      -BadAllocation);
            return Error_TO_Pointer(-BadAllocation);
        }
        memcpy(Dup, Comp, (size_t)(N + 1));
        Dentry* De = __alloc_dentry__(Dup, Parent, Next);
        if (Probe_IF_Error(De) || !De)
        {
            PushError("__walk__",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return Error_TO_Pointer(-BadAllocation);
        }

        Parent = De;
        Cur    = Next;
    }
    return Parent;
}

static __MountEntry__*
__find_mount__(const char* __Path__)
{
    long Best    = SysErro;
    long BestLen = SysErro;
    for (long I = 0; I < __MountCount__; I++)
    {
        const char* Mp = __Mounts__[I].Path;
        long        Ml = (long)strlen(Mp);
        if (Ml <= 0)
        {
            continue;
        }
        if (strncmp(__Path__, Mp, (size_t)Ml) == 0)
        {
            if (Ml > BestLen)
            {
                Best    = I;
                BestLen = Ml;
            }
        }
    }
    return Best >= Nothing ? &__Mounts__[Best] : Nothing;
}

int
VfsInit(void)
{
    SysErr  err;
    SysErr* Error = &err;

    AcquireMutex(&VfsLock, Error);
    InitializeMutex(&VfsLock, "vfs-central", Error);

    __FsCount__        = 0;
    __MountCount__     = 0;
    __RootNode__       = 0;
    __RootDe__         = 0;
    __Umask__          = 0;
    __MaxName__        = 256;
    __MaxPath__        = 1024;
    __DirCacheLimit__  = 0;
    __FileCacheLimit__ = 0;
    __IoBlockSize__    = 0;
    __DefaultFs__[0]   = 0;

    LOGVFSC_PDebug("Init\n");
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsShutdown(void)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    for (long I = 0; I < __MountCount__; I++)
    {
        Superblock* Sb = __Mounts__[I].Sb;
        if (Sb && Sb->Ops && Sb->Ops->Umount)
        {
            Sb->Ops->Umount(Sb);
        }
        if (Sb && Sb->Ops && Sb->Ops->Release)
        {
            SysErr  err;
            SysErr* Error = &err;
            Sb->Ops->Release(Sb, Error);
        }
        __Mounts__[I].Sb      = 0;
        __Mounts__[I].Path[0] = 0;
    }
    __MountCount__ = 0;
    __FsCount__    = 0;
    __RootNode__   = 0;
    __RootDe__     = 0;

    LOGVFSC_PDebug("Shutdown\n");

    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsRegisterFs(const FsType* __FsType__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    if (Probe_IF_Error(__FsType__) || !__FsType__ || Probe_IF_Error(__FsType__->Name) ||
        !__FsType__->Name || Probe_IF_Error(__FsType__->Mount) || !__FsType__->Mount)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError(
            "VfsRegisterFs", LOGVFSC_PError, "bad filesystem type to register", -BadArguments);
        return -BadArguments;
    }

    if (__FsCount__ >= __MaxFsTypes__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRegisterFs", LOGVFSC_PError, "too many filesystems registered", -TooMany);
        return -TooMany;
    }

    for (long I = 0; I < __FsCount__; I++)
    {
        if (strcmp(__FsReg__[I]->Name, __FsType__->Name) == 0)
        {
            ReleaseMutex(&VfsLock, Error);
            LOGVFSC_PWarn("FileSystem exists %s\n", __FsType__->Name);
            PushError("VfsRegisterFs",
                      LOGVFSC_PError,
                      "filesystem already registered",
                      -Redefined); /*We don't need this ig*/
            return -Redefined;
        }
    }

    __FsReg__[__FsCount__++] = __FsType__;
    LOGVFSC_PDebug("FileSystem registered %s\n", __FsType__->Name);
    ReleaseMutex(&VfsLock, Error);

    return SysOkay;
}

int
VfsUnregisterFs(const char* __Name__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError(
            "VfsUnregisterFs", LOGVFSC_PError, "bad filesystem name to unregister", -BadArguments);
        return -BadArguments;
    }

    for (long I = 0; I < __FsCount__; I++)
    {
        if (strcmp(__FsReg__[I]->Name, __Name__) == 0)
        {
            for (long J = I; J < __FsCount__ - 1; J++)
            {
                __FsReg__[J] = __FsReg__[J + 1];
            }
            __FsReg__[--__FsCount__] = 0;
            LOGVFSC_PDebug("FileSystem unregistered %s\n", __Name__);
            return SysOkay;
        }
    }

    ReleaseMutex(&VfsLock, Error);
    PushError("VfsUnregisterFs", LOGVFSC_PError, "filesystem not found to unregister", -NoSuch);
    return -NoSuch;
}

const FsType*
VfsFindFs(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("VfsFindFs", LOGVFSC_PError, "bad filesystem name to find", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    for (long I = 0; I < __FsCount__; I++)
    {
        if (strcmp(__FsReg__[I]->Name, __Name__) == 0)
        {
            return __FsReg__[I];
        }
    }

    PushError("VfsFindFs", LOGVFSC_PError, "filesystem not found", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

long
VfsListFs(const char** __Out__, long __Cap__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Out__) || !__Out__ || __Cap__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsListFs", LOGVFSC_PError, "bad arguments to VfsListFs", -BadArguments);
        return -BadArguments;
    }

    long N = (__FsCount__ < __Cap__) ? __FsCount__ : __Cap__;
    for (long I = 0; I < N; I++)
    {
        __Out__[I] = __FsReg__[I]->Name;
    }

    ReleaseMutex(&VfsLock, Error);
    PushError("VfsListFs", LOGVFSC_PError, "listed filesystems", SysOkay);
    return N;
}

Superblock*
VfsMount(const char*    __Dev__,
         const char*    __Path__,
         const char*    __Type__,
         long __Flags__ _unused,
         const char*    __Opts__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    const FsType* Fs = VfsFindFs(__Type__);
    if (Probe_IF_Error(Fs) || !Fs)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMount", LOGVFSC_PError, "filesystem type not found", -BadEntity);
        return Error_TO_Pointer(-BadEntity);
    }

    if (Probe_IF_Error(__Path__) || !__Path__ || !*__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMount", LOGVFSC_PError, "bad mount path", -NotCanonical);
        return Error_TO_Pointer(-NotCanonical);
    }

    long Plen = (long)strlen(__Path__);
    if (Plen <= 0 || Plen >= __MaxPath__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMount", LOGVFSC_PError, "mount path too long", -Limits);
        return Error_TO_Pointer(-Limits);
    }

    if (__MountCount__ >= __MaxMounts__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMount", LOGVFSC_PError, "too many mounts", -TooMany);
        return Error_TO_Pointer(-TooMany);
    }

    Superblock* Sb = Fs->Mount(__Dev__, __Opts__);
    if (Probe_IF_Error(Sb) || !Sb || Probe_IF_Error(Sb->Root) || !Sb->Root)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMount", LOGVFSC_PError, "failed to mount filesystem", -NotRooted);
        return Error_TO_Pointer(-NotRooted);
    }

    __MountEntry__* M = &__Mounts__[__MountCount__++];
    M->Sb             = Sb;
    memcpy(M->Path, __Path__, (size_t)(Plen + 1));

    if (!__RootNode__ && strcmp(__Path__, "/") == 0)
    {
        __RootNode__ = Sb->Root;
        __RootDe__   = __alloc_dentry__("/", 0, __RootNode__);
        LOGVFSC_PDebug("Root mounted /\n");
    }

    LOGVFSC_PDebug("Mounted %s at %s\n", __Type__, __Path__);

    ReleaseMutex(&VfsLock, Error);
    return Sb;
}

int
VfsUnmount(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsUnmount", LOGVFSC_PError, "bad unmount path", -NotCanonical);
        return -NotCanonical;
    }

    for (long I = 0; I < __MountCount__; I++)
    {
        if (strcmp(__Mounts__[I].Path, __Path__) == 0)
        {
            Superblock* Sb = __Mounts__[I].Sb;
            if (Sb && Sb->Ops && Sb->Ops->Umount)
            {
                Sb->Ops->Umount(Sb);
            }
            if (Sb && Sb->Ops && Sb->Ops->Release)
            {
                SysErr  err;
                SysErr* Error = &err;
                Sb->Ops->Release(Sb, Error);
            }
            for (long J = I; J < __MountCount__ - 1; J++)
            {
                __Mounts__[J] = __Mounts__[J + 1];
            }
            __Mounts__[--__MountCount__].Sb    = 0;
            __Mounts__[__MountCount__].Path[0] = 0;

            if (strcmp(__Path__, "/") == 0)
            {
                __RootNode__ = 0;
                __RootDe__   = 0;
            }
            LOGVFSC_PDebug("Unmounted %s\n", __Path__);
            return SysOkay;
        }
    }

    ReleaseMutex(&VfsLock, Error);
    PushError("VfsUnmount", LOGVFSC_PError, "filesystem not found", -NoSuch);
    return -NoSuch;
}

int /*chroot???*/
VfsSwitchRoot(const char* __NewRoot__)
{
    SysErr  err;
    SysErr* Error = &err;

    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__NewRoot__) || !__NewRoot__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsSwitchRoot", LOGVFSC_PError, "bad chroot path", -NotRooted);
        return -NotRooted;
    }

    Dentry* De = VfsResolve(__NewRoot__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError(
            "VfsSwitchRoot", LOGVFSC_PError, "failed to resolve new root path", -CannotLookup);
        return -CannotLookup;
    }

    __RootNode__ = De->Node;
    __RootDe__   = De;
    LOGVFSC_PDebug("Chrooted to %s\n", __NewRoot__);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsBindMount(const char* __Src__, const char* __Dst__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Src__) || !__Src__ || Probe_IF_Error(__Dst__) || !__Dst__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsBindMount", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    __MountEntry__* M = __find_mount__(__Src__);
    if (Probe_IF_Error(M) || !M || Probe_IF_Error(M->Sb) || !M->Sb)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsBindMount", LOGVFSC_PError, "filesystem not found", -NoSuch);
        return -NoSuch;
    }

    if (__MountCount__ >= __MaxMounts__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsBindMount", LOGVFSC_PError, "too many mounts", -TooMany);
        return -TooMany;
    }

    long N = (long)strlen(__Dst__);
    if (N <= 0 || N >= __MaxPath__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsBindMount", LOGVFSC_PError, "destination path too long", -Limits);
        return -Limits;
    }

    __MountEntry__* New = &__Mounts__[__MountCount__++];
    New->Sb             = M->Sb;
    memcpy(New->Path, __Dst__, (size_t)(N + 1));

    LOGVFSC_PDebug("Bind mount %s -> %s\n", __Src__, __Dst__);
    ReleaseMutex(&VfsLock, Error);

    return SysOkay;
}

int
VfsMoveMount(const char* __Src__, const char* __Dst__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Src__) || !__Src__ || Probe_IF_Error(__Dst__) || !__Dst__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMoveMount", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    __MountEntry__* M = __find_mount__(__Src__);
    if (Probe_IF_Error(M) || !M || Probe_IF_Error(M->Sb) || !M->Sb)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMoveMount", LOGVFSC_PError, "filesystem not found", -NoSuch);
        return -NoSuch;
    }

    long N = (long)strlen(__Dst__);
    if (N <= 0 || N >= __MaxPath__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMoveMount", LOGVFSC_PError, "destination path too long", -Limits);
        return -Dangling;
    }

    memcpy(M->Path, __Dst__, (size_t)(N + 1));
    LOGVFSC_PDebug("Move mount %s -> %s\n", __Src__, __Dst__);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsRemount(const char* __Path__, long __Flags__ _unused, const char* __Opts__ _unused)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    __MountEntry__* M = __find_mount__(__Path__);
    if (Probe_IF_Error(M) || !M || Probe_IF_Error(M->Sb) || !M->Sb)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRemount", LOGVFSC_PError, "filesystem not found", -NoSuch);
        return -NoSuch;
    }

    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

Dentry*
VfsResolve(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;

    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsResolve", LOGVFSC_PError, "bad resolve path", -NotCanonical);
        return Error_TO_Pointer(-NotCanonical);
    }

    if (Probe_IF_Error(__RootNode__) || !__RootNode__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsResolve", LOGVFSC_PError, "no root filesystem mounted", -NotRooted);
        return Error_TO_Pointer(-NotRooted);
    }

    if (strcmp(__Path__, "/") == 0)
    {
        return __RootDe__;
    }

    /*explaining this section*/

    __MountEntry__* M = __find_mount__(__Path__);
    if (Probe_IF_Error(M) || !M)
    {
        /*Walk from the global root for non-mounted prefixes*/
        return __walk__(__RootNode__, __RootDe__, __Path__);
    }

    /*Strip the mount path prefix before walking from the mount root*/
    const char* Mp = M->Path;
    long        Ml = (long)strlen(Mp);

    /*If the path is exactly the mount point, return a dentry for the mount root*/
    if (strncmp(__Path__, Mp, (size_t)Ml) == 0 && __Path__[Ml] == '\0')
    {
        /*Construct a dentry anchored at mount root*/
        Dentry* De = __alloc_dentry__(Mp, __RootDe__, M->Sb->Root);
        return De ? De : Error_TO_Pointer(-NoSuch);
    }

    /*Otherwise, walk the subpath tail from the mount's root*/
    const char* Tail = __Path__ + Ml;
    /*Skip extra slashes to normalize*/
    while (*Tail == '/')
    {
        Tail++;
    }

    /*if tail is empty after stripping, we are at mount root*/
    if (!*Tail)
    {
        Dentry* De = __alloc_dentry__(Mp, __RootDe__, M->Sb->Root);
        return De ? De : Error_TO_Pointer(-BadAllocation);
    }

    ReleaseMutex(&VfsLock, Error);
    return __walk__(M->Sb->Root, __RootDe__, Tail);
}

Dentry*
VfsResolveAt(Dentry* __Base__, const char* __Rel__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    if (Probe_IF_Error(__Base__) || !__Base__ || Probe_IF_Error(__Base__->Node) ||
        !__Base__->Node || Probe_IF_Error(__Rel__) || !__Rel__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsResolveAt", LOGVFSC_PError, "bad arguments", -BadArguments);
        return Error_TO_Pointer(-Dangling);
    }

    if (!*__Rel__)
    {
        return __Base__;
    }

    if (__is_sep__(*__Rel__))
    {
        return VfsResolve(__Rel__);
    }

    ReleaseMutex(&VfsLock, Error);
    return __walk__(__Base__->Node, __Base__, __Rel__);
}

Vnode*
VfsLookup(Dentry* __Base__, const char* __Name__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Base__) || !__Base__ || Probe_IF_Error(__Base__->Node) ||
        !__Base__->Node || Probe_IF_Error(__Name__) || !__Name__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLookup", LOGVFSC_PError, "bad arguments", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    if (Probe_IF_Error(__Base__->Node->Ops) || !__Base__->Node->Ops ||
        Probe_IF_Error(__Base__->Node->Ops->Lookup) || !__Base__->Node->Ops->Lookup)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLookup", LOGVFSC_PError, "operation not supported", -NoOperations);
        return Error_TO_Pointer(-NoOperations);
    }

    ReleaseMutex(&VfsLock, Error);
    return __Base__->Node->Ops->Lookup(__Base__->Node, __Name__);
}

int
VfsMkpath(const char* __Path__, long __Perm__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMkpath", LOGVFSC_PError, "bad makepath path", -NotCanonical);
        return -NotCanonical;
    }
    const char* p = __Path__;
    if (__is_sep__(*p))
    {
        p = __skip_sep__(p);
    }

    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    char    Comp[256];

    while (*p)
    {
        long N = __next_comp__(p, Comp, sizeof(Comp));
        if (N <= 0)
        {
            break;
        }
        while (*p && !__is_sep__(*p))
        {
            p++;
        }
        p = __skip_sep__(p);

        Vnode* Next = Cur->Ops ? Cur->Ops->Lookup(Cur, Comp) : Nothing;
        if (Probe_IF_Error(Next) || !Next)
        {
            if (Probe_IF_Error(Cur->Ops) || !Cur->Ops || Probe_IF_Error(Cur->Ops->Mkdir) ||
                !Cur->Ops->Mkdir)
            {
                ReleaseMutex(&VfsLock, Error);
                PushError("VfsMkpath", LOGVFSC_PError, "operation not supported", -NoOperations);
                return -NoOperations;
            }
            VfsPerm perm = {.Mode = __Perm__, .Uid = 0, .Gid = 0};
            if (Cur->Ops->Mkdir(Cur, Comp, perm) != SysOkay)
            {
                ReleaseMutex(&VfsLock, Error);
                PushError(
                    "VfsMkpath", LOGVFSC_PError, "failed to create directory in path", -BadReturn);
                return -BadReturn;
            }
            Next = Cur->Ops->Lookup(Cur, Comp);
            if (Probe_IF_Error(Next) || !Next)
            {
                ReleaseMutex(&VfsLock, Error);
                PushError("VfsMkpath",
                          LOGVFSC_PError,
                          "failed to lookup newly created directory",
                          -CannotLookup);
                return -CannotLookup;
            }
        }
        char* Dup = (char*)KMalloc(N + 1);
        memcpy(Dup, Comp, N + 1);
        De  = __alloc_dentry__(Dup, De, Next);
        Cur = Next;
    }
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsRealpath(const char* __Path__, char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRealpath", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    long L = (long)strlen(__Path__);
    if (L >= __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRealpath", LOGVFSC_PError, "buffer too small for realpath", -TooBig);
        return -TooBig;
    }
    memcpy(__Buf__, __Path__, (size_t)(L + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

File*
VfsOpen(const char* __Path__, long __Flags__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpen", LOGVFSC_PError, "failed to resolve path for open", -BadEntity);
        return Error_TO_Pointer(-BadEntity);
    }

    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops || Probe_IF_Error(De->Node->Ops->Open) ||
        !De->Node->Ops->Open)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpen", LOGVFSC_PError, "operation not supported", -NoOperations);
        return Error_TO_Pointer(-NoOperations);
    }

    File* F = (File*)KMalloc(sizeof(File));
    if (Probe_IF_Error(F) || !F)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpen", LOGVFSC_PError, "failed to allocate file structure", -BadAllocation);
        return Error_TO_Pointer(-BadAllocation);
    }

    F->Node   = De->Node;
    F->Offset = 0;
    F->Flags  = __Flags__;
    F->Refcnt = 1;
    F->Priv   = 0;

    if (De->Node->Ops->Open(De->Node, F) != SysOkay)
    {
        KFree(F, Error);
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpen", LOGVFSC_PError, "failed to open file", -BadReturn);
        return Error_TO_Pointer(-BadReturn);
    }

    LOGVFSC_PDebug("Open %s\n", __Path__);
    ReleaseMutex(&VfsLock, Error);
    return F;
}

File*
VfsOpenAt(Dentry* __Base__, const char* __Rel__, long __Flags__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolveAt(__Base__, __Rel__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpenAt", LOGVFSC_PError, "failed to resolve path", -BadEntity);
        return Error_TO_Pointer(-BadEntity);
    }

    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops || Probe_IF_Error(De->Node->Ops->Open) ||
        !De->Node->Ops->Open)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpenAt", LOGVFSC_PError, "operation not supported", -NoOperations);
        return Error_TO_Pointer(-NoOperations);
    }

    File* F = (File*)KMalloc(sizeof(File));
    if (Probe_IF_Error(F) || !F)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpenAt", LOGVFSC_PError, "failed to allocate file structure", -BadAllocation);
        return Error_TO_Pointer(-BadAllocation);
    }

    F->Node   = De->Node;
    F->Offset = 0;
    F->Flags  = __Flags__;
    F->Refcnt = 1;
    F->Priv   = 0;

    if (De->Node->Ops->Open(De->Node, F) != SysOkay)
    {
        KFree(F, Error);
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsOpenAt", LOGVFSC_PError, "failed to open file", -BadReturn);
        return Error_TO_Pointer(-BadReturn);
    }

    ReleaseMutex(&VfsLock, Error);
    return F;
}

int
VfsClose(File* __File__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    if (Probe_IF_Error(__File__) || !__File__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsClose", LOGVFSC_PError, "bad file to close", -BadArguments);
        return -BadArguments;
    }

    if (__File__->Node && __File__->Node->Ops && __File__->Node->Ops->Close)
    {
        __File__->Node->Ops->Close(__File__);
    }

    KFree(__File__, Error);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsRead(File* __File__, void* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRead", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__File__->Node) || !__File__->Node || Probe_IF_Error(__File__->Node->Ops) ||
        !__File__->Node->Ops || Probe_IF_Error(__File__->Node->Ops->Read) ||
        !__File__->Node->Ops->Read)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRead", LOGVFSC_PError, "read operation not supported", -NoOperations);
        return -NoOperations;
    }

    long Got = __File__->Node->Ops->Read(__File__, __Buf__, __Len__);
    if (Got > 0)
    {
        __File__->Offset += Got;
    }
    ReleaseMutex(&VfsLock, Error);
    return Got;
}

long
VfsWrite(File* __File__, const void* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsWrite", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__File__->Node) || !__File__->Node || Probe_IF_Error(__File__->Node->Ops) ||
        !__File__->Node->Ops || Probe_IF_Error(__File__->Node->Ops->Write) ||
        !__File__->Node->Ops->Write)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsWrite", LOGVFSC_PError, "write operation not supported", -NoOperations);
        return -NoOperations;
    }

    long Put = __File__->Node->Ops->Write(__File__, __Buf__, __Len__);
    if (Put > 0)
    {
        __File__->Offset += Put;
    }
    ReleaseMutex(&VfsLock, Error);
    return Put;
}

long
VfsLseek(File* __File__, long __Off__, int __Whence__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__File__) || !__File__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLseek", LOGVFSC_PError, "bad file", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__File__->Node) || !__File__->Node || Probe_IF_Error(__File__->Node->Ops) ||
        !__File__->Node->Ops || Probe_IF_Error(__File__->Node->Ops->Lseek) ||
        !__File__->Node->Ops->Lseek)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLseek", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    long New = __File__->Node->Ops->Lseek(__File__, __Off__, __Whence__);
    if (New >= 0)
    {
        __File__->Offset = New;
    }
    ReleaseMutex(&VfsLock, Error);
    return New;
}

int
VfsIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__File__) || !__File__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsIoctl", LOGVFSC_PError, "bad file", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__File__->Node) || !__File__->Node || Probe_IF_Error(__File__->Node->Ops) ||
        !__File__->Node->Ops || Probe_IF_Error(__File__->Node->Ops->Ioctl) ||
        !__File__->Node->Ops->Ioctl)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsIoctl", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    ReleaseMutex(&VfsLock, Error);
    return __File__->Node->Ops->Ioctl(__File__, __Cmd__, __Arg__);
}

int
VfsFsync(File* __File__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__File__->Node) ||
        !__File__->Node || Probe_IF_Error(__File__->Node->Ops) || !__File__->Node->Ops)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsFsync", LOGVFSC_PError, "bad file", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__File__->Node->Ops->Sync) || !__File__->Node->Ops->Sync)
    {
        ReleaseMutex(&VfsLock, Error);
        return SysOkay; /*Its fine*/
    }

    ReleaseMutex(&VfsLock, Error);
    return __File__->Node->Ops->Sync(__File__->Node);
}

int
VfsFstats(File* __File__, VfsStat* __Buf__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsFstats", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__File__->Node) || !__File__->Node || Probe_IF_Error(__File__->Node->Ops) ||
        !__File__->Node->Ops || Probe_IF_Error(__File__->Node->Ops->Stat) ||
        !__File__->Node->Ops->Stat)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsFstats", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    ReleaseMutex(&VfsLock, Error);
    return __File__->Node->Ops->Stat(__File__->Node, __Buf__);
}

int
VfsStats(const char* __Path__, VfsStat* __Buf__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Buf__) || !__Buf__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsStats", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsStats", LOGVFSC_PError, "failed to resolve path for stats", -Dangling);
        return -Dangling;
    }

    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops || Probe_IF_Error(De->Node->Ops->Stat) ||
        !De->Node->Ops->Stat)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsStats", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    ReleaseMutex(&VfsLock, Error);
    return De->Node->Ops->Stat(De->Node, __Buf__);
}

long
VfsReaddir(const char* __Path__, void* __Buf__, long __BufLen__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __BufLen__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReaddir", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReaddir", LOGVFSC_PError, "failed to resolve path", -Dangling);
        return -Dangling;
    }

    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops || Probe_IF_Error(De->Node->Ops->Readdir) ||
        !De->Node->Ops->Readdir)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReaddir", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    ReleaseMutex(&VfsLock, Error);
    return De->Node->Ops->Readdir(De->Node, __Buf__, __BufLen__);
}

long
VfsReaddirF(File* __Dir__, void* __Buf__, long __BufLen__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __BufLen__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReaddirF", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    if (Probe_IF_Error(__Dir__->Node) || !__Dir__->Node || Probe_IF_Error(__Dir__->Node->Ops) ||
        !__Dir__->Node->Ops || Probe_IF_Error(__Dir__->Node->Ops->Readdir) ||
        !__Dir__->Node->Ops->Readdir)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReaddirF", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    ReleaseMutex(&VfsLock, Error);
    return __Dir__->Node->Ops->Readdir(__Dir__->Node, __Buf__, __BufLen__);
}

/*PART1*/

int
VfsCreate(const char* __Path__, long __Flags__, VfsPerm __Perm__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* Parent = 0;
    char    Name[256];
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsCreate", LOGVFSC_PError, "bad create path", -NotCanonical);
        return -NotCanonical;
    }
    const char* __Path = __Path__;
    if (__is_sep__(*__Path))
    {
        __Path = __skip_sep__(__Path);
    }
    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    while (*__Path)
    {
        long N = __next_comp__(__Path, Name, sizeof(Name));
        if (N <= 0)
        {
            break;
        }
        while (*__Path && !__is_sep__(*__Path))
        {
            __Path++;
        }
        __Path = __skip_sep__(__Path);
        Parent = De;
        if (*__Path == 0)
        {
            break;
        }
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsCreate", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Name);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsCreate", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsCreate",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, Name, (size_t)(N + 1));
        De = __alloc_dentry__(Dup, De, Next);
        if (Probe_IF_Error(De) || !De)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsCreate",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        Cur = Next;
    }
    if (Probe_IF_Error(Parent) || !Parent || Probe_IF_Error(Parent->Node) || !Parent->Node ||
        Probe_IF_Error(Parent->Node->Ops) || !Parent->Node->Ops ||
        Probe_IF_Error(Parent->Node->Ops->Create) || !Parent->Node->Ops->Create)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsCreate", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return Parent->Node->Ops->Create(Parent->Node, Name, __Flags__, __Perm__);
}

int
VfsUnlink(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* Base = 0;
    char    Name[256];
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsUnlink", LOGVFSC_PError, "bad unlink path", -NotCanonical);
        return -NotCanonical;
    }
    const char* __Path = __Path__;
    if (__is_sep__(*__Path))
    {
        __Path = __skip_sep__(__Path);
    }
    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    while (*__Path)
    {
        long N = __next_comp__(__Path, Name, sizeof(Name));
        if (N <= 0)
        {
            break;
        }
        while (*__Path && !__is_sep__(*__Path))
        {
            __Path++;
        }
        __Path = __skip_sep__(__Path);
        if (*__Path == 0)
        {
            Base = De;
            break;
        }
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsUnlink", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Name);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsUnlink", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsUnlink",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, Name, (size_t)(N + 1));
        De = __alloc_dentry__(Dup, De, Next);
        if (Probe_IF_Error(De) || !De)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsUnlink",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        Cur = Next;
    }
    if (Probe_IF_Error(Base) || !Base || Probe_IF_Error(Base->Node) || !Base->Node ||
        Probe_IF_Error(Base->Node->Ops) || !Base->Node->Ops ||
        Probe_IF_Error(Base->Node->Ops->Unlink) || !Base->Node->Ops->Unlink)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsUnlink", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return Base->Node->Ops->Unlink(Base->Node, Name);
}

int
VfsMkdir(const char* __Path__, VfsPerm __Perm__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* Base = 0;
    char    Name[256];
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMkdir", LOGVFSC_PError, "bad mkdir path", -NotCanonical);
        return -NotCanonical;
    }
    const char* __PathCur = __Path__;
    if (__is_sep__(*__PathCur))
    {
        __PathCur = __skip_sep__(__PathCur);
    }
    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    while (*__PathCur)
    {
        long N = __next_comp__(__PathCur, Name, sizeof(Name));
        if (N <= 0)
        {
            break;
        }
        while (*__PathCur && !__is_sep__(*__PathCur))
        {
            __PathCur++;
        }
        __PathCur = __skip_sep__(__PathCur);
        if (*__PathCur == 0)
        {
            Base = De;
            break;
        }
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsMkdir", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Name);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsMkdir", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsMkdir",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, Name, (size_t)(N + 1));
        De = __alloc_dentry__(Dup, De, Next);
        if (Probe_IF_Error(De) || !De)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsMkdir",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        Cur = Next;
    }
    if (Probe_IF_Error(Base) || !Base || Probe_IF_Error(Base->Node) || !Base->Node ||
        Probe_IF_Error(Base->Node->Ops) || !Base->Node->Ops ||
        Probe_IF_Error(Base->Node->Ops->Mkdir) || !Base->Node->Ops->Mkdir)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMkdir", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return Base->Node->Ops->Mkdir(Base->Node, Name, __Perm__);
}

int
VfsRmdir(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* Base = 0;
    char    Name[256];
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRmdir", LOGVFSC_PError, "bad rmdir path", -NotCanonical);
        return -NotCanonical;
    }
    const char* p = __Path__;
    if (__is_sep__(*p))
    {
        p = __skip_sep__(p);
    }
    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    while (*p)
    {
        long N = __next_comp__(p, Name, sizeof(Name));
        if (N <= 0)
        {
            break;
        }
        while (*p && !__is_sep__(*p))
        {
            p++;
        }
        p = __skip_sep__(p);
        if (*p == 0)
        {
            Base = De;
            break;
        }
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRmdir", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Name);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRmdir", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc(N + 1);
        memcpy(Dup, Name, N + 1);
        De  = __alloc_dentry__(Dup, De, Next);
        Cur = Next;
    }
    if (Probe_IF_Error(Base) || !Base || Probe_IF_Error(Base->Node) || !Base->Node ||
        Probe_IF_Error(Base->Node->Ops) || !Base->Node->Ops ||
        Probe_IF_Error(Base->Node->Ops->Rmdir) || !Base->Node->Ops->Rmdir)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRmdir", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return Base->Node->Ops->Rmdir(Base->Node, Name);
}

int
VfsSymlink(const char* __Target__, const char* __LinkPath__, VfsPerm __Perm__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* Base = 0;
    char    Name[256];
    if (Probe_IF_Error(__LinkPath__) || !__LinkPath__ || Probe_IF_Error(__Target__) || !__Target__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsSymlink", LOGVFSC_PError, "bad symlink path", -NotCanonical);
        return -NotCanonical;
    }
    const char* __Path = __LinkPath__;
    if (__is_sep__(*__Path))
    {
        __Path = __skip_sep__(__Path);
    }
    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    while (*__Path)
    {
        long N = __next_comp__(__Path, Name, sizeof(Name));
        if (N <= 0)
        {
            break;
        }
        while (*__Path && !__is_sep__(*__Path))
        {
            __Path++;
        }
        __Path = __skip_sep__(__Path);
        if (*__Path == 0)
        {
            Base = De;
            break;
        }
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsSymlink", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Name);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsSymlink", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsSymlink",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, Name, (size_t)(N + 1));
        De = __alloc_dentry__(Dup, De, Next);
        if (Probe_IF_Error(De) || !De)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsSymlink",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        Cur = Next;
    }
    if (Probe_IF_Error(Base) || !Base || Probe_IF_Error(Base->Node) || !Base->Node ||
        Probe_IF_Error(Base->Node->Ops) || !Base->Node->Ops ||
        Probe_IF_Error(Base->Node->Ops->Symlink) || !Base->Node->Ops->Symlink)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsSymlink", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return Base->Node->Ops->Symlink(Base->Node, Name, __Target__, __Perm__);
}

int
VfsReadlink(const char* __Path__, char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReadlink", LOGVFSC_PError, "bad arguments to VfsReadlink", -BadArguments);
        return -BadArguments;
    }

    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReadlink", LOGVFSC_PError, "failed to resolve path for readlink", -Dangling);
        return -Dangling;
    }
    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops ||
        Probe_IF_Error(De->Node->Ops->Readlink) || !De->Node->Ops->Readlink)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReadlink", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }

    VfsNameBuf NB;
    NB.Buf = __Buf__;
    NB.Len = __Len__;
    ReleaseMutex(&VfsLock, Error);
    return De->Node->Ops->Readlink(De->Node, &NB);
}

int
VfsLink(const char* __OldPath__, const char* __NewPath__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__OldPath__) || !__OldPath__ || Probe_IF_Error(__NewPath__) || !__NewPath__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLink", LOGVFSC_PError, "bad link paths", -NotCanonical);
        return -NotCanonical;
    }

    Dentry* OldDe   = VfsResolve(__OldPath__);
    Dentry* NewBase = 0;
    char    Name[256];

    if (Probe_IF_Error(OldDe) || !OldDe || Probe_IF_Error(OldDe->Node) || !OldDe->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLink", LOGVFSC_PError, "failed to resolve old path", -Dangling);
        return -Dangling;
    }

    const char* __Path = __NewPath__;
    if (__is_sep__(*__Path))
    {
        __Path = __skip_sep__(__Path);
    }
    Vnode*  Cur = __RootNode__;
    Dentry* De  = __RootDe__;
    while (*__Path)
    {
        long N = __next_comp__(__Path, Name, sizeof(Name));
        if (N <= 0)
        {
            break;
        }
        while (*__Path && !__is_sep__(*__Path))
        {
            __Path++;
        }
        __Path = __skip_sep__(__Path);
        if (*__Path == 0)
        {
            NewBase = De;
            break;
        }
        if (Probe_IF_Error(Cur) || !Cur || Probe_IF_Error(Cur->Ops) || !Cur->Ops ||
            Probe_IF_Error(Cur->Ops->Lookup) || !Cur->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsLink", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = Cur->Ops->Lookup(Cur, Name);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsLink", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsLink",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, Name, (size_t)(N + 1));
        De = __alloc_dentry__(Dup, De, Next);
        if (Probe_IF_Error(De) || !De)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsLink",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        Cur = Next;
    }

    if (Probe_IF_Error(NewBase) || !NewBase || Probe_IF_Error(NewBase->Node) || !NewBase->Node ||
        Probe_IF_Error(NewBase->Node->Ops) || !NewBase->Node->Ops ||
        Probe_IF_Error(NewBase->Node->Ops->Link) || !NewBase->Node->Ops->Link)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsLink", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return NewBase->Node->Ops->Link(NewBase->Node, OldDe->Node, Name);
}

int
VfsRename(const char* __OldPath__, const char* __NewPath__, long __Flags__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* OldBase = 0;
    Dentry* NewBase = 0;
    char    OldName[256];
    char    NewName[256];

    if (Probe_IF_Error(__OldPath__) || !__OldPath__ || Probe_IF_Error(__NewPath__) || !__NewPath__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRename", LOGVFSC_PError, "bad rename paths", -NotCanonical);
        return -NotCanonical;
    }

    const char* po = __OldPath__;
    if (__is_sep__(*po))
    {
        po = __skip_sep__(po);
    }
    Vnode*  CurO = __RootNode__;
    Dentry* DeO  = __RootDe__;
    while (*po)
    {
        long N = __next_comp__(po, OldName, sizeof(OldName));
        if (N <= 0)
        {
            break;
        }
        while (*po && !__is_sep__(*po))
        {
            po++;
        }
        po = __skip_sep__(po);
        if (*po == 0)
        {
            OldBase = DeO;
            break;
        }
        if (Probe_IF_Error(CurO) || !CurO || Probe_IF_Error(CurO->Ops) || !CurO->Ops ||
            Probe_IF_Error(CurO->Ops->Lookup) || !CurO->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRename", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = CurO->Ops->Lookup(CurO, OldName);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsRename", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRename",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, OldName, (size_t)(N + 1));
        DeO = __alloc_dentry__(Dup, DeO, Next);
        if (Probe_IF_Error(DeO) || !DeO)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRename",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        CurO = Next;
    }

    const char* pn = __NewPath__;
    if (__is_sep__(*pn))
    {
        pn = __skip_sep__(pn);
    }
    Vnode*  CurN = __RootNode__;
    Dentry* DeN  = __RootDe__;
    while (*pn)
    {
        long N = __next_comp__(pn, NewName, sizeof(NewName));
        if (N <= 0)
        {
            break;
        }
        while (*pn && !__is_sep__(*pn))
        {
            pn++;
        }
        pn = __skip_sep__(pn);
        if (*pn == 0)
        {
            NewBase = DeN;
            break;
        }
        if (Probe_IF_Error(CurN) || !CurN || Probe_IF_Error(CurN->Ops) || !CurN->Ops ||
            Probe_IF_Error(CurN->Ops->Lookup) || !CurN->Ops->Lookup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRename", LOGVFSC_PError, "operation not supported", -NoOperations);
            return -NoOperations;
        }
        Vnode* Next = CurN->Ops->Lookup(CurN, NewName);
        if (Probe_IF_Error(Next) || !Next)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsRename", LOGVFSC_PError, "cannot lookup component in path", -CannotLookup);
            return -CannotLookup;
        }
        char* Dup = (char*)KMalloc((size_t)(N + 1));
        if (Probe_IF_Error(Dup) || !Dup)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRename",
                      LOGVFSC_PError,
                      "failed to allocate memory for component name",
                      -BadAllocation);
            return -BadAllocation;
        }
        memcpy(Dup, NewName, (size_t)(N + 1));
        DeN = __alloc_dentry__(Dup, DeN, Next);
        if (Probe_IF_Error(DeN) || !DeN)
        {
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsRename",
                      LOGVFSC_PError,
                      "failed to allocate dentry for component",
                      -BadAllocation);
            return -BadAllocation;
        }
        CurN = Next;
    }

    if (Probe_IF_Error(OldBase) || !OldBase || Probe_IF_Error(NewBase) || !NewBase)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRename", LOGVFSC_PError, "failed to resolve paths for rename", -Dangling);
        return -Dangling;
    }
    if (Probe_IF_Error(OldBase->Node) || !OldBase->Node || Probe_IF_Error(NewBase->Node) ||
        !NewBase->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRename", LOGVFSC_PError, "failed to resolve nodes for rename", -Dangling);
        return -Dangling;
    }
    if (Probe_IF_Error(OldBase->Node->Ops) || !OldBase->Node->Ops ||
        Probe_IF_Error(OldBase->Node->Ops->Rename) || !OldBase->Node->Ops->Rename)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRename", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return OldBase->Node->Ops->Rename(OldBase->Node, OldName, NewBase->Node, NewName, __Flags__);
}

int
VfsChmod(const char* __Path__, long __Mode__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsChmod", LOGVFSC_PError, "failed to resolve path for chmod", -Dangling);
        return -Dangling;
    }
    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops || Probe_IF_Error(De->Node->Ops->Chmod) ||
        !De->Node->Ops->Chmod)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsChmod", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return De->Node->Ops->Chmod(De->Node, __Mode__);
}

int
VfsChown(const char* __Path__, long __Uid__, long __Gid__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsChown", LOGVFSC_PError, "failed to resolve path", -Dangling);
        return -Dangling;
    }
    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops || Probe_IF_Error(De->Node->Ops->Chown) ||
        !De->Node->Ops->Chown)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsChown", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return De->Node->Ops->Chown(De->Node, __Uid__, __Gid__);
}

int
VfsTruncate(const char* __Path__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsTruncate", LOGVFSC_PError, "failed to resolve path", -Dangling);
        return -Dangling;
    }
    if (Probe_IF_Error(De->Node->Ops) || !De->Node->Ops ||
        Probe_IF_Error(De->Node->Ops->Truncate) || !De->Node->Ops->Truncate)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsTruncate", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return De->Node->Ops->Truncate(De->Node, __Len__);
}

int
VnodeRefInc(Vnode* __Node__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Node__) || !__Node__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VnodeRefInc", LOGVFSC_PError, "bad vnode for ref increment", -BadArguments);
        return -BadArguments;
    }
    __Node__->Refcnt++;
    ReleaseMutex(&VfsLock, Error);
    return (int)__Node__->Refcnt;
}

int
VnodeRefDec(Vnode* __Node__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Node__) || !__Node__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VnodeRefDec", LOGVFSC_PError, "bad vnode for ref decrement", -BadArguments);
        return -BadArguments;
    }
    if (__Node__->Refcnt > 0)
    {
        __Node__->Refcnt--;
    }
    ReleaseMutex(&VfsLock, Error);
    return (int)__Node__->Refcnt;
}

int
VnodeGetAttr(Vnode* __Node__, VfsStat* __Buf__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__Buf__) || !__Buf__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VnodeGetAttr", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    if (Probe_IF_Error(__Node__->Ops) || !__Node__->Ops || Probe_IF_Error(__Node__->Ops->Stat) ||
        !__Node__->Ops->Stat)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VnodeGetAttr", LOGVFSC_PError, "operation not supported", -NoOperations);
        return -NoOperations;
    }
    ReleaseMutex(&VfsLock, Error);
    return __Node__->Ops->Stat(__Node__, __Buf__);
}

int
VnodeSetAttr(Vnode* __Node__ _unused, const VfsStat* __Buf__ _unused)
{
    PushError("VnodeSetAttr", LOGVFSC_PError, "operation not supported", -Impilict);
    return -Impilict;
}

int
DentryInvalidate(Dentry* __De__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__De__) || !__De__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("DentryInvalidate", LOGVFSC_PError, "bad dentry for invalidate", -BadArguments);
        return -BadArguments;
    }
    __De__->Flags |= 1;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
DentryRevalidate(Dentry* __De__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__De__) || !__De__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("DentryRevalidate", LOGVFSC_PError, "bad dentry for revalidate", -BadArguments);
        return -BadArguments;
    }
    __De__->Flags &= ~1;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
DentryAttach(Dentry* __De__, Vnode* __Node__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__De__) || !__De__ || Probe_IF_Error(__Node__) || !__Node__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("DentryAttach", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    __De__->Node = __Node__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
DentryDetach(Dentry* __De__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__De__) || !__De__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("DentryDetach", LOGVFSC_PError, "bad dentry for detach", -BadArguments);
        return -BadArguments;
    }
    __De__->Node = 0;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
DentryName(Dentry* __De__, char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__De__) || !__De__ || Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("DentryName", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    long N = (long)strlen(__De__->Name);
    if (N >= __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("DentryName", LOGVFSC_PError, "buffer too small for dentry name", -TooBig);
        return -TooBig;
    }
    memcpy(__Buf__, __De__->Name, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsSetCwd(const char* __Path__ _unused)
{
    return SysOkay;
}

int
VfsGetCwd(char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsGetCwd", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    const char* __Path = "/";
    long        N      = (long)strlen(__Path);
    if (N >= __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsGetCwd", LOGVFSC_PError, "buffer too small for cwd path", -TooBig);
        return -TooBig;
    }
    memcpy(__Buf__, __Path, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsSetRoot(const char* __Path__)
{
    return VfsSwitchRoot(__Path__);
}

int
VfsGetRoot(char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsGetRoot", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    const char* __Path = "/";
    long        N      = (long)strlen(__Path);
    if (N >= __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsGetRoot", LOGVFSC_PError, "buffer too small for root path", -TooBig);
        return -TooBig;
    }
    memcpy(__Buf__, __Path, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsSetUmask(long __Mode__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    __Umask__ = __Mode__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsGetUmask(void)
{
    return __Umask__;
}

int
VfsNotifySubscribe(const char* __Path__ _unused, long __Mask__ _unused)
{
    return SysOkay;
}

int
VfsNotifyUnsubscribe(const char* __Path__ _unused)
{
    return SysOkay;
}

int
VfsNotifyPoll(const char* __Path__ _unused, long* __OutMask__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__OutMask__) || !__OutMask__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsNotifyPoll", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    *__OutMask__ = 0;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsAccess(const char* __Path__, long __Mode__ _unused)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    ReleaseMutex(&VfsLock, Error);

    if (Probe_IF_Error(De) || !De)
    {
        PushError("VfsAccess", LOGVFSC_PError, "failed to resolve path for access", -Dangling);
        return -Dangling;
    }

    return SysOkay;
}

int
VfsExists(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    ReleaseMutex(&VfsLock, Error);

    if (Probe_IF_Error(De) || !De)
    {
        PushError("VfsExists", LOGVFSC_PError, "failed to resolve path for exists", -NoSuch);
        return -NoSuch;
    }
    return SysOkay;
}

int
VfsIsDir(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    ReleaseMutex(&VfsLock, Error);

    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        PushError("VfsIsDir", LOGVFSC_PError, "failed to resolve path for isdir", -NoSuch);
        return -NoSuch;
    }
    return (De->Node->Type == VNodeDIR) ? SysOkay : -NoSuch;
}

int
VfsIsFile(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    ReleaseMutex(&VfsLock, Error);

    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        PushError("VfsIsFile", LOGVFSC_PError, "failed to resolve path for isfile", -NoSuch);
        return -NoSuch;
    }
    return (De->Node->Type == VNodeFILE) ? SysOkay : -NoSuch;
}

int
VfsIsSymlink(const char* __Path__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    Dentry* De = VfsResolve(__Path__);
    ReleaseMutex(&VfsLock, Error);

    if (Probe_IF_Error(De) || !De || Probe_IF_Error(De->Node) || !De->Node)
    {
        PushError("VfsIsSymlink", LOGVFSC_PError, "failed to resolve path for issymlink", -NoSuch);
        return -NoSuch;
    }
    return (De->Node->Type == VNodeSYM) ? SysOkay : -NoSuch;
}

int
VfsCopy(const char* __Src__, const char* __Dst__, long __Flags__ _unused)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);

    File* S = VfsOpen(__Src__, VFlgRDONLY);
    if (Probe_IF_Error(S) || !S)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsCopy", LOGVFSC_PError, "failed to open source file for copy", -BadEntity);
        return -BadEntity;
    }
    File* D = VfsOpen(__Dst__, VFlgCREATE | VFlgWRONLY | VFlgTRUNC);
    if (Probe_IF_Error(D) || !D)
    {
        VfsClose(S);
        ReleaseMutex(&VfsLock, Error);
        PushError(
            "VfsCopy", LOGVFSC_PError, "failed to open destination file for copy", -BadEntity);
        return -BadEntity;
    }

    char Buf[4096];
    for (;;)
    {
        long r = VfsRead(S, Buf, sizeof(Buf));
        if (r < 0)
        {
            VfsClose(S);
            VfsClose(D);
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsCopy", LOGVFSC_PError, "failed to read from source file during copy", -BadRead);
            return -BadRead;
        }
        if (r == 0)
        {
            break;
        }
        long w = VfsWrite(D, Buf, r);
        if (w != r)
        {
            VfsClose(S);
            VfsClose(D);
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsCopy",
                      LOGVFSC_PError,
                      "failed to write to destination file during copy",
                      -BadWrite);
            return -BadWrite;
        }
    }

    VfsClose(S);
    VfsClose(D);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsMove(const char* __Src__, const char* __Dst__, long __Flags__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    int rc = VfsRename(__Src__, __Dst__, __Flags__);
    if (rc == SysOkay)
    {
        ReleaseMutex(&VfsLock, Error);
        return SysOkay;
    }
    rc = VfsCopy(__Src__, __Dst__, __Flags__);
    if (rc != SysOkay)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMove", LOGVFSC_PError, "failed to copy file during move", -BadReturn);
        return -BadReturn;
    }
    ReleaseMutex(&VfsLock, Error);
    return VfsUnlink(__Src__);
}

int
VfsReadAll(const char* __Path__, void* __Buf__, long __BufLen__, long* __OutLen__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    File* F = VfsOpen(__Path__, VFlgRDONLY);
    if (Probe_IF_Error(F) || !F)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsReadAll", LOGVFSC_PError, "failed to open file for readall", -BadEntity);
        return -BadEntity;
    }
    long total = 0;
    while (total < __BufLen__)
    {
        long r = VfsRead(F, (char*)__Buf__ + total, __BufLen__ - total);
        if (r < 0)
        {
            VfsClose(F);
            ReleaseMutex(&VfsLock, Error);
            PushError(
                "VfsReadAll", LOGVFSC_PError, "failed to read from file during readall", -BadRead);
            return -BadRead;
        }
        if (r == 0)
        {
            break;
        }
        total += r;
    }
    if (__OutLen__)
    {
        *__OutLen__ = total;
    }
    VfsClose(F);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsWriteAll(const char* __Path__, const void* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    File* F = VfsOpen(__Path__, VFlgCREATE | VFlgWRONLY | VFlgTRUNC);
    if (Probe_IF_Error(F) || !F)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsWriteAll", LOGVFSC_PError, "failed to open file for writeall", -BadEntity);
        return -BadEntity;
    }
    long total = 0;
    while (total < __Len__)
    {
        long w = VfsWrite(F, (const char*)__Buf__ + total, __Len__ - total);
        if (w <= 0)
        {
            VfsClose(F);
            ReleaseMutex(&VfsLock, Error);
            PushError("VfsWriteAll",
                      LOGVFSC_PError,
                      "failed to write to file during writeall",
                      -BadWrite);
            return -BadWrite;
        }
        total += w;
    }
    VfsClose(F);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsMountTableEnumerate(char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMountTableEnumerate", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    long off = 0;
    for (long I = 0; I < __MountCount__; I++)
    {
        const char* __Path = __Mounts__[I].Path;
        long        N      = (long)strlen(__Path);
        if (off + N + 2 >= __Len__)
        {
            break;
        }
        memcpy(__Buf__ + off, __Path, (size_t)N);
        off += N;
        __Buf__[off++] = '\n';
    }
    if (off < __Len__)
    {
        __Buf__[off] = 0;
    }
    ReleaseMutex(&VfsLock, Error);
    return (int)off;
}

int
VfsMountTableFind(const char* __Path__, char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsMountTableFind", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    for (long I = 0; I < __MountCount__; I++)
    {
        if (strcmp(__Mounts__[I].Path, __Path__) == 0)
        {
            long N = (long)strlen(__Mounts__[I].Path);
            if (N >= __Len__)
            {
                ReleaseMutex(&VfsLock, Error);
                PushError("VfsMountTableFind",
                          LOGVFSC_PError,
                          "buffer too small for mount path",
                          -TooBig);
                return -TooBig;
            }
            memcpy(__Buf__, __Mounts__[I].Path, (size_t)(N + 1));
            ReleaseMutex(&VfsLock, Error);
            return SysOkay;
        }
    }
    ReleaseMutex(&VfsLock, Error);
    PushError("VfsMountTableFind", LOGVFSC_PError, "mount point not found", -NoSuch);
    return -NoSuch;
}

int
VfsNodePath(Vnode* __Node__ _unused, char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsNodePath", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    const char* __Path = "/";
    long        N      = (long)strlen(__Path);
    if (N >= __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsNodePath", LOGVFSC_PError, "buffer too small for node path", -TooBig);
        return -TooBig;
    }
    memcpy(__Buf__, __Path, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsNodeName(Vnode* __Node__ _unused, char* __Buf__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsNodeName", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    const char* __Path = "";
    long        N      = (long)strlen(__Path);
    if (N >= __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsNodeName", LOGVFSC_PError, "buffer too small for node name", -TooBig);
        return -TooBig;
    }
    memcpy(__Buf__, __Path, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsAllocName(char** __Out__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Out__) || !__Out__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsAllocName", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    *__Out__ = (char*)KMalloc((size_t)__Len__);
    ReleaseMutex(&VfsLock, Error);
    return *__Out__ ? Nothing : -NotCanonical;
}

int
VfsFreeName(char* __Name__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsFreeName", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    KFree(__Name__, Error);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsJoinPath(const char* __A__, const char* __B__, char* __Out__, long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__A__) || !__A__ || Probe_IF_Error(__B__) || !__B__ ||
        Probe_IF_Error(__Out__) || !__Out__ || __Len__ <= 0)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsJoinPath", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    long la   = (long)strlen(__A__);
    long lb   = (long)strlen(__B__);
    long need = la + 1 + lb + 1;
    if (need > __Len__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsJoinPath", LOGVFSC_PError, "buffer too small for joined path", -TooBig);
        return -TooBig;
    }
    memcpy(__Out__, __A__, (size_t)la);
    __Out__[la] = '/';
    memcpy(__Out__ + la + 1, __B__, (size_t)lb);
    __Out__[la + 1 + lb] = 0;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsSetFlag(const char* __Path__ _unused, long __Flag__ _unused)
{
    return SysOkay;
}

int
VfsClearFlag(const char* __Path__ _unused, long __Flag__ _unused)
{
    return SysOkay;
}

long
VfsGetFlags(const char* __Path__ _unused)
{
    return SysOkay;
}

int
VfsSyncAll(void)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    for (long I = 0; I < __MountCount__; I++)
    {
        Superblock* Sb = __Mounts__[I].Sb;
        if (Sb && Sb->Ops && Sb->Ops->Sync)
        {
            Sb->Ops->Sync(Sb);
        }
    }
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsPruneCaches(void)
{
    return SysOkay;
}

int
VfsRegisterDevNode(const char* __Path__, void* __Priv__, long __Flags__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Priv__) || !__Priv__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRegisterDevNode", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    /* Ensure parent directory exists */
    char Buf[1024];
    VfsRealpath(__Path__, Buf, sizeof(Buf));
    const char* Name = strrchr(Buf, '/');
    if (Probe_IF_Error(Name) || !Name)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRegisterDevNode", LOGVFSC_PError, "bad device node path", -NotCanonical);
        return -NotCanonical;
    }
    long nlen = (long)strlen(Name + 1);

    char Parent[1024];
    long plen = (long)(Name - Buf);
    memcpy(Parent, Buf, plen);
    Parent[plen] = 0;
    VfsMkpath(Parent, 0);

    /* Create vnode for device */
    Vnode* Node = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(Node) || !Node)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRegisterDevNode",
                  LOGVFSC_PError,
                  "failed to allocate vnode for device node",
                  -BadAllocation);
        return -BadAllocation;
    }
    Node->Type   = VNodeDEV;
    Node->Ops    = (VnodeOps*)__Priv__; /* device ops table */
    Node->Sb     = __RootNode__->Sb;
    Node->Priv   = __Priv__;
    Node->Refcnt = 1;

    char* Dup = (char*)KMalloc(nlen + 1);
    memcpy(Dup, Name + 1, nlen + 1);
    Dentry* De = __alloc_dentry__(Dup, __RootDe__, Node);
    if (Probe_IF_Error(De) || !De)
    {
        KFree(Node, Error);
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRegisterDevNode",
                  LOGVFSC_PError,
                  "failed to allocate dentry for device node",
                  -BadAllocation);
        return -BadAllocation;
    }

    LOGVFSC_PDebug("Registered devnode %s\n", __Path__);
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsUnregisterDevNode(const char* __Path__ _unused)
{
    return SysOkay;
}

int
VfsRegisterPseudoFs(const char* __Path__, Superblock* __Sb__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Path__) || !__Path__ || Probe_IF_Error(__Sb__) || !__Sb__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsRegisterPseudoFs", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    if (__MountCount__ >= __MaxMounts__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError(
            "VfsRegisterPseudoFs", LOGVFSC_PError, "maximum number of mounts reached", -TooMany);
        return -TooMany;
    }
    long            N = (long)strlen(__Path__);
    __MountEntry__* M = &__Mounts__[__MountCount__++];
    M->Sb             = __Sb__;
    memcpy(M->Path, __Path__, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

int
VfsUnregisterPseudoFs(const char* __Path__)
{
    return VfsUnmount(__Path__);
}

int
VfsSetDefaultFs(const char* __Name__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsSetDefaultFs", LOGVFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    long N = (long)strlen(__Name__);
    if (N >= (long)sizeof(__DefaultFs__))
    {
        ReleaseMutex(&VfsLock, Error);
        PushError(
            "VfsSetDefaultFs", LOGVFSC_PError, "filesystem name too long for default fs", -TooBig);
        return -TooBig;
    }
    memcpy(__DefaultFs__, __Name__, (size_t)(N + 1));
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

const char*
VfsGetDefaultFs(void)
{
    return __DefaultFs__;
}

int
VfsSetMaxName(long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (__Len__ < 1)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsSetMaxName", LOGVFSC_PError, "maximum name length too small", -TooSmall);
        return -TooSmall;
    }
    __MaxName__ = __Len__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsGetMaxName(void)
{
    return __MaxName__;
}

int
VfsSetMaxPath(long __Len__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    if (__Len__ < 1)
    {
        ReleaseMutex(&VfsLock, Error);
        PushError("VfsSetMaxPath", LOGVFSC_PError, "maximum path length too small", -TooSmall);
        return -TooSmall;
    }
    __MaxPath__ = __Len__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsGetMaxPath(void)
{
    return __MaxPath__;
}

int
VfsSetDirCacheLimit(long __Val__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    __DirCacheLimit__ = __Val__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsGetDirCacheLimit(void)
{
    return __DirCacheLimit__;
}

int
VfsSetFileCacheLimit(long __Val__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    __FileCacheLimit__ = __Val__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsGetFileCacheLimit(void)
{
    return __FileCacheLimit__;
}

int
VfsSetIoBlockSize(long __Val__)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireMutex(&VfsLock, Error);
    __IoBlockSize__ = __Val__;
    ReleaseMutex(&VfsLock, Error);
    return SysOkay;
}

long
VfsGetIoBlockSize(void)
{
    return __IoBlockSize__;
}