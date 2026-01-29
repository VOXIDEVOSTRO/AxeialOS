#include <DevFS.h>
#include <Errnos.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <String.h>
#include <VFS.h>
#include <__AXEKCONF__.h>

#ifdef LOGDEVFSC_Debug
#    define LOGDEVFSC_PDebug(fmt, ...) PDebug("[KERNEL>>DevFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVFSC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVFSC_Logs
#    define LOGDEVFSC_PError(fmt, ...) PError("[KERNEL>>DevFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVFSC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVFSC_Logs
#    define LOGDEVFSC_PWarn(fmt, ...) PWarn("[KERNEL>>DevFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVFSC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVFSC_Logs
#    define LOGDEVFSC_PInfo(fmt, ...) PInfo("[KERNEL>>DevFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVFSC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVFSC_Logs
#    define LOGDEVFSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>DevFS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVFSC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

static const long            __MaxDevices__ = 256;
static _Atomic(DeviceEntry*) __DevTable__[256];
static atomic_long           __DevCount__ = 0;
static _Atomic(Superblock*)  __DevSuper__ = 0;

/* Forwards */
static int    DevVfsOpen(Vnode* __Node__, File* __File__);
static int    DevVfsClose(File* __File__);
static long   DevVfsRead(File* __File__, void* __Buf__, long __Len__);
static long   DevVfsWrite(File* __File__, const void* __Buf__, long __Len__);
static long   DevVfsLseek(File* __File__, long __Off__, int __Whence__);
static int    DevVfsIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__);
static int    DevVfsStat(Vnode* __Node__, VfsStat* __Out__);
static long   DevVfsReaddir(Vnode* __Dir__, void* __Buf__, long __BufLen__);
static Vnode* DevVfsLookup(Vnode* __Dir__, const char* __Name__);
static int    DevVfsCreate(Vnode* __Dir__, const char* __Name__, long __Flags__, VfsPerm __Perm__);
static int    DevVfsMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__);
static int    DevVfsSync(Vnode* __Node__);
static int    DevVfsSuperSync(Superblock* __Sb__);
static int    DevVfsSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__);
static void   DevVfsSuperRelease(Superblock* __Sb__, SysErr* __Err__);
static int    DevVfsSuperUmount(Superblock* __Sb__);

/* Ops tables */
static const VnodeOps __DevVfsOps__ = {.Open     = DevVfsOpen,
                                       .Close    = DevVfsClose,
                                       .Read     = DevVfsRead,
                                       .Write    = DevVfsWrite,
                                       .Lseek    = DevVfsLseek,
                                       .Ioctl    = DevVfsIoctl,
                                       .Stat     = DevVfsStat,
                                       .Readdir  = DevVfsReaddir,
                                       .Lookup   = DevVfsLookup,
                                       .Create   = DevVfsCreate,
                                       .Unlink   = 0,
                                       .Mkdir    = DevVfsMkdir,
                                       .Rmdir    = 0,
                                       .Symlink  = 0,
                                       .Readlink = 0,
                                       .Link     = 0,
                                       .Rename   = 0,
                                       .Chmod    = 0,
                                       .Chown    = 0,
                                       .Truncate = 0,
                                       .Sync     = DevVfsSync,
                                       .Map      = 0,
                                       .Unmap    = 0};

static const SuperOps __DevVfsSuperOps__ = {.Sync    = DevVfsSuperSync,
                                            .StatFs  = DevVfsSuperStatFs,
                                            .Release = DevVfsSuperRelease,
                                            .Umount  = DevVfsSuperUmount};

typedef struct DevFsRootPriv
{
    int __Unused__;
} DevFsRootPriv;

typedef struct DevFsNodePriv
{
    const DeviceEntry* Dev;
} DevFsNodePriv;

static long
__dev_index__(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError(
            "__dev_index__", LOGDEVFSC_PError, "bad arguments to __dev_index__", -BadArguments);
        return -BadArguments;
    }

    long Count = atomic_load_explicit(&__DevCount__, memory_order_acquire);
    for (long I = 0; I < Count; I++)
    {
        DeviceEntry* E = atomic_load_explicit(&__DevTable__[I], memory_order_acquire);
        if (E && strcmp(E->Name, __Name__) == 0)
        {
            return I;
        }
    }
    PushError("__dev_index__", LOGDEVFSC_PError, "device not found", -NoSuch);
    return -NoSuch;
}

static DeviceEntry*
__dev_find__(const char* __Name__)
{
    long Idx = __dev_index__(__Name__);
    return (Idx >= 0) ? atomic_load_explicit(&__DevTable__[Idx], memory_order_acquire) : Nothing;
}

static char*
__dup_name__(const char* __Name__)
{
    const long CapName = 255;
    char*      S       = (char*)KMalloc((size_t)(CapName + 1));
    if (Probe_IF_Error(S) || !S)
    {
        PushError("__dup_name__", LOGDEVFSC_PError, "cannot allocate name", -BadAllocation);
        return Nothing;
    }
    strncpy(S, __Name__, CapName);
    S[CapName] = '\0';
    return S;
}

static int
__publish_device__(DeviceEntry* __E__)
{
    long Count = atomic_load_explicit(&__DevCount__, memory_order_relaxed);
    for (;;)
    {
        if (Count >= __MaxDevices__)
        {
            PushError("__publish_device__", LOGDEVFSC_PError, "too many devices", -TooMany);
            return -TooMany;
        }
        /* CAS reserve slot */
        DeviceEntry* expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &__DevTable__[Count], &expected, __E__, memory_order_release, memory_order_relaxed))
        {
            /* increment count after slot publish */
            atomic_compare_exchange_strong_explicit(
                &__DevCount__, &Count, Count + 1, memory_order_release, memory_order_relaxed);
            return SysOkay;
        }
        /* someone raced; reload count and retry */
        Count = atomic_load_explicit(&__DevCount__, memory_order_relaxed);
    }
}

static void
__compact_after__(long __From__)
{
    long Count = atomic_load_explicit(&__DevCount__, memory_order_acquire);
    for (long J = __From__; J < Count - 1; J++)
    {
        DeviceEntry* Next = atomic_load_explicit(&__DevTable__[J + 1], memory_order_acquire);
        atomic_store_explicit(&__DevTable__[J], Next, memory_order_release);
    }
    atomic_store_explicit(&__DevTable__[Count - 1], 0, memory_order_release);
    atomic_store_explicit(&__DevCount__, Count - 1, memory_order_release);
}

int
DevFsInit(void)
{
    long Count = atomic_load_explicit(&__DevCount__, memory_order_relaxed);
    for (long I = 0; I < Count; I++)
    {
        atomic_store_explicit(&__DevTable__[I], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&__DevCount__, 0, memory_order_relaxed);
    atomic_store_explicit(&__DevSuper__, 0, memory_order_relaxed);
    LOGDEVFSC_PDebug("Init for DevFs registry\n");
    return SysOkay;
}

int
DevFsRegisterCharDevice(const char* __Name__,
                        uint32_t    __Major__,
                        uint32_t    __Minor__,
                        CharDevOps  __Ops__,
                        void*       __Context__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("DevFsRegisterCharDevice",
                  LOGDEVFSC_PError,
                  "bad arguments to DevFsRegisterCharDevice",
                  -BadArguments);
        return -BadArguments;
    }

    if (__dev_find__(__Name__))
    {
        PushError(
            "DevFsRegisterCharDevice", LOGDEVFSC_PError, "device already registered", -Redefined);
        return -Redefined;
    }

    DeviceEntry* E = (DeviceEntry*)KMalloc(sizeof(DeviceEntry));
    if (Probe_IF_Error(E) || !E)
    {
        PushError("DevFsRegisterCharDevice",
                  LOGDEVFSC_PError,
                  "cannot allocate device entry",
                  Pointer_TO_Error(E));
        return -BadAllocation;
    }

    char* NameStore = __dup_name__(__Name__);
    if (!NameStore)
    {
        SysErr  err;
        SysErr* Error = &err;
        KFree(E, Error);
        PushError(
            "DevFsRegisterCharDevice", LOGDEVFSC_PError, "cannot allocate name", -BadAllocation);
        return -BadAllocation;
    }

    memset(E, 0, sizeof(*E));
    E->Name    = NameStore;
    E->Type    = DevChar;
    E->Major   = __Major__;
    E->Minor   = __Minor__;
    E->Context = __Context__;
    memcpy(&E->Ops.C, &__Ops__, sizeof(CharDevOps));

    int RetC = __publish_device__(E);
    if (RetC != SysOkay)
    {
        SysErr  err;
        SysErr* Error = &err;
        KFree((void*)E->Name, Error);
        KFree(E, Error);
        PushError("DevFsRegisterCharDevice", LOGDEVFSC_PError, "cannot publish device", RetC);
        return RetC;
    }

    return SysOkay;
}

int
DevFsRegisterBlockDevice(const char* __Name__,
                         uint32_t    __Major__,
                         uint32_t    __Minor__,
                         BlockDevOps __Ops__,
                         void*       __Context__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("DevFsRegisterBlockDevice",
                  LOGDEVFSC_PError,
                  "bad arguments to DevFsRegisterBlockDevice",
                  -BadArguments);
        return -NotCanonical;
    }

    if (__dev_find__(__Name__))
    {
        PushError(
            "DevFsRegisterBlockDevice", LOGDEVFSC_PError, "device already registered", -Redefined);
        return -Redefined;
    }

    DeviceEntry* E = (DeviceEntry*)KMalloc(sizeof(DeviceEntry));
    if (Probe_IF_Error(E) || !E)
    {
        PushError("DevFsRegisterBlockDevice",
                  LOGDEVFSC_PError,
                  "cannot allocate device entry",
                  Pointer_TO_Error(E));
        return -BadAllocation;
    }

    char* NameStore = __dup_name__(__Name__);
    if (!NameStore)
    {
        SysErr  err;
        SysErr* Error = &err;
        KFree(E, Error);
        PushError(
            "DevFsRegisterBlockDevice", LOGDEVFSC_PError, "cannot allocate name", -BadAllocation);
        return -BadAllocation;
    }

    memset(E, 0, sizeof(*E));
    E->Name    = NameStore;
    E->Type    = DevBlock;
    E->Major   = __Major__;
    E->Minor   = __Minor__;
    E->Context = __Context__;
    memcpy(&E->Ops.B, &__Ops__, sizeof(BlockDevOps));

    int RetC = __publish_device__(E);
    if (RetC != SysOkay)
    {
        SysErr  err;
        SysErr* Error = &err;
        KFree((void*)E->Name, Error);
        KFree(E, Error);
        PushError("DevFsRegisterBlockDevice", LOGDEVFSC_PError, "cannot publish device", RetC);
        return RetC;
    }

    LOGDEVFSC_PDebug("Block registered %s (blk=%ld)\n", __Name__, (long)__Ops__.BlockSize);
    return SysOkay;
}

int
DevFsUnregisterDevice(const char* __Name__)
{
    long Idx = __dev_index__(__Name__);
    if (Idx < 0)
    {
        PushError("DevFsUnregisterDevice",
                  LOGDEVFSC_PError,
                  "bad arguments to DevFsUnregisterDevice",
                  -BadArguments);
        return -NotCanonical;
    }

    DeviceEntry* E = atomic_load_explicit(&__DevTable__[Idx], memory_order_acquire);
    if (!E)
    {
        PushError(
            "DevFsUnregisterDevice", LOGDEVFSC_PError, "device already unregistered", -Dangling);
        return -Dangling;
    }

    /* Remove entry from table first */
    __compact_after__(Idx);

    /* Free owned resources */
    SysErr  err;
    SysErr* Error = &err;
    if (E->Name)
    {
        KFree((void*)E->Name, Error);
    }
    KFree(E, Error);

    LOGDEVFSC_PDebug("Unregistered %s\n", __Name__);
    return SysOkay;
}

int
DevFsRegister(void)
{
    static FsType __DevFsType__ = {.Name = "devfs", .Mount = DevFsMountImpl, .Priv = 0};

    if (VfsRegisterFs(&__DevFsType__) != SysOkay)
    {
        PushError("DevFsRegister",
                  LOGDEVFSC_PError,
                  "cannot register devfs filesystem type",
                  -NotInitilized);
        return -NotInitilized;
    }

    return SysOkay;
}

Superblock*
DevFsMountImpl(const char* __Dev__ __attribute__((unused)),
               const char* __Opts__ __attribute__((unused)))
{
    SysErr  err;
    SysErr* Error = &err;

    Superblock* Sb = (Superblock*)KMalloc(sizeof(Superblock));
    if (Probe_IF_Error(Sb) || !Sb)
    {
        PushError(
            "DevFsMountImpl", LOGDEVFSC_PError, "cannot allocate superblock", Pointer_TO_Error(Sb));
        return Error_TO_Pointer(-BadAllocation);
    }

    Vnode* Root = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(Root) || !Root)
    {
        KFree(Sb, Error);
        PushError("DevFsMountImpl",
                  LOGDEVFSC_PError,
                  "cannot allocate root vnode",
                  Pointer_TO_Error(Root));
        return Error_TO_Pointer(-BadAllocation);
    }

    DevFsRootPriv* RPriv = (DevFsRootPriv*)KMalloc(sizeof(DevFsRootPriv));
    if (Probe_IF_Error(RPriv) || !RPriv)
    {
        KFree(Root, Error);
        KFree(Sb, Error);
        PushError("DevFsMountImpl",
                  LOGDEVFSC_PError,
                  "cannot allocate root private data",
                  Pointer_TO_Error(RPriv));
        return Error_TO_Pointer(-BadAllocation);
    }

    RPriv->__Unused__ = 0;
    Root->Type        = VNodeDIR;
    Root->Ops         = &__DevVfsOps__;
    Root->Sb          = Sb;
    Root->Priv        = RPriv;
    Root->Refcnt      = 1;

    Sb->Type  = 0;
    Sb->Dev   = 0;
    Sb->Flags = 0;
    Sb->Root  = Root;
    Sb->Ops   = &__DevVfsSuperOps__;
    Sb->Priv  = 0;

    atomic_store_explicit(&__DevSuper__, Sb, memory_order_release);
    LOGDEVFSC_PDebug("Superblock created\n");
    return Sb;
}

static int
DevVfsOpen(Vnode* __Node__, File* __File__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__File__) || !__File__)
    {
        PushError("DevVfsOpen", LOGDEVFSC_PError, "bad arguments to DevVfsOpen", -BadArguments);
        return -BadArguments;
    }

    __File__->Node   = __Node__;
    __File__->Offset = 0;
    __File__->Refcnt = 1;
    __File__->Priv   = 0;

    if (__Node__->Type == VNodeDIR)
    {
        return SysOkay;
    }

    if (__Node__->Type == VNodeDEV)
    {
        DevFsNodePriv* NPriv = (DevFsNodePriv*)__Node__->Priv;
        if (Probe_IF_Error(NPriv) || !NPriv || Probe_IF_Error(NPriv->Dev) || !NPriv->Dev)
        {
            PushError("DevVfsOpen", LOGDEVFSC_PError, "bad device in node", -Dangling);
            return -Dangling;
        }

        DevFsFileCtx* FC = (DevFsFileCtx*)KMalloc(sizeof(DevFsFileCtx));
        if (Probe_IF_Error(FC) || !FC)
        {
            PushError("DevVfsOpen",
                      LOGDEVFSC_PError,
                      "cannot allocate file context",
                      Pointer_TO_Error(FC));
            return -BadAllocation;
        }

        FC->Dev = NPriv->Dev;
        atomic_store_explicit(&FC->Lba, 0, memory_order_relaxed);
        atomic_store_explicit(&FC->Offset, 0, memory_order_relaxed);

        __File__->Priv = FC;

        /* Call device open if provided */
        if (NPriv->Dev->Type == DevChar && NPriv->Dev->Ops.C.Open)
        {
            int RetC = NPriv->Dev->Ops.C.Open(NPriv->Dev->Context);
            if (RetC != SysOkay)
            {
                SysErr  err;
                SysErr* Error = &err;
                KFree(FC, Error);
                __File__->Priv = 0;
                PushError("DevVfsOpen", LOGDEVFSC_PError, "device open failed", RetC);
                return RetC;
            }
        }
        else if (NPriv->Dev->Type == DevBlock && NPriv->Dev->Ops.B.Open)
        {
            int RetC = NPriv->Dev->Ops.B.Open(NPriv->Dev->Context);
            if (RetC != SysOkay)
            {
                SysErr  err;
                SysErr* Error = &err;
                KFree(FC, Error);
                __File__->Priv = 0;
                PushError("DevVfsOpen", LOGDEVFSC_PError, "device open failed", RetC);
                return RetC;
            }
        }

        return SysOkay;
    }

    PushError("DevVfsOpen", LOGDEVFSC_PError, "unknown node type", -NotCanonical);
    return -NoSuch;
}

static int
DevVfsClose(File* __File__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        PushError("DevVfsClose", LOGDEVFSC_PError, "bad arguments to DevVfsClose", -BadArguments);
        return -BadArguments;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (FC && FC->Dev)
    {
        if (FC->Dev->Type == DevChar && FC->Dev->Ops.C.Close)
        {
            FC->Dev->Ops.C.Close(FC->Dev->Context);
        }
        else if (FC->Dev->Type == DevBlock && FC->Dev->Ops.B.Close)
        {
            FC->Dev->Ops.B.Close(FC->Dev->Context);
        }
    }

    if (__File__->Priv)
    {
        SysErr  err;
        SysErr* Error = &err;
        KFree(__File__->Priv, Error);
        __File__->Priv = 0;
    }
    return SysOkay;
}

static long
DevVfsRead(File* __File__, void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        PushError("DevVfsRead", LOGDEVFSC_PError, "bad arguments to DevVfsRead", -BadArguments);
        return -BadArguments;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        PushError("DevVfsRead", LOGDEVFSC_PError, "bad device in node", -Dangling);
        return -Dangling;
    }

    if (FC->Dev->Type == DevChar)
    {
        if (!FC->Dev->Ops.C.Read)
        {
            PushError("DevVfsRead", LOGDEVFSC_PError, "no read operation", -NoOperations);
            return -NoOperations;
        }
        long r = FC->Dev->Ops.C.Read(FC->Dev->Context, __Buf__, __Len__);
        if (r > 0)
        {
            __File__->Offset += r;
            atomic_fetch_add_explicit(&FC->Offset, r, memory_order_relaxed);
        }
        return r;
    }

    if (FC->Dev->Type == DevBlock)
    {
        if (!FC->Dev->Ops.B.ReadBlocks)
        {
            PushError("DevVfsRead", LOGDEVFSC_PError, "no read operation", -NoOperations);
            return -NoOperations;
        }

        long Blk = FC->Dev->Ops.B.BlockSize;
        if (Blk <= 0)
        {
            PushError("DevVfsRead", LOGDEVFSC_PError, "bad block size", -Limits);
            return -Limits;
        }

        uint8_t* Dst       = (uint8_t*)__Buf__;
        long     Remaining = __Len__;
        long     Total     = 0;

        SysErr  err;
        SysErr* Error = &err;

        while (Remaining > 0)
        {
            long     CurOff = atomic_load_explicit(&FC->Offset, memory_order_relaxed);
            uint64_t CurLba = atomic_load_explicit(&FC->Lba, memory_order_relaxed);

            long ToRead = Remaining;
            if (ToRead > Blk - CurOff)
            {
                ToRead = Blk - CurOff;
            }

            void* Tmp = KMalloc((size_t)Blk);
            if (Probe_IF_Error(Tmp) || !Tmp)
            {
                return (Total > 0) ? Total : -BadAllocation;
            }

            long rb = FC->Dev->Ops.B.ReadBlocks(FC->Dev->Context, CurLba, Tmp, 1);
            if (rb != 1)
            {
                KFree(Tmp, Error);
                break;
            }

            memcpy(Dst + Total, (uint8_t*)Tmp + CurOff, (size_t)ToRead);
            KFree(Tmp, Error);

            Total += ToRead;
            Remaining -= ToRead;

            long NewOff = CurOff + ToRead;
            if (NewOff >= Blk)
            {
                atomic_store_explicit(&FC->Offset, 0, memory_order_relaxed);
                atomic_store_explicit(&FC->Lba, CurLba + 1, memory_order_relaxed);
            }
            else
            {
                atomic_store_explicit(&FC->Offset, NewOff, memory_order_relaxed);
            }
        }

        __File__->Offset += Total;
        return Total;
    }

    PushError("DevVfsRead", LOGDEVFSC_PError, "unknown device type", -NotCanonical);
    return -BadRead;
}

static long
DevVfsWrite(File* __File__, const void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        PushError("DevVfsWrite", LOGDEVFSC_PError, "bad arguments to DevVfsWrite", -BadArguments);
        return -BadArguments;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        PushError("DevVfsWrite", LOGDEVFSC_PError, "bad device in node", -Dangling);
        return -Dangling;
    }

    if (FC->Dev->Type == DevChar)
    {
        if (!FC->Dev->Ops.C.Write)
        {
            PushError("DevVfsWrite", LOGDEVFSC_PError, "no write operation", -NoOperations);
            return -NoOperations;
        }
        long w = FC->Dev->Ops.C.Write(FC->Dev->Context, __Buf__, __Len__);
        if (w > 0)
        {
            __File__->Offset += w;
            atomic_fetch_add_explicit(&FC->Offset, w, memory_order_relaxed);
        }
        return w;
    }

    if (FC->Dev->Type == DevBlock)
    {
        if (!FC->Dev->Ops.B.WriteBlocks)
        {
            PushError("DevVfsWrite", LOGDEVFSC_PError, "no write operation", -NoOperations);
            return -NoOperations;
        }

        long Blk = FC->Dev->Ops.B.BlockSize;
        if (Blk <= 0)
        {
            PushError("DevVfsWrite", LOGDEVFSC_PError, "bad block size", -Limits);
            return -Limits;
        }

        const uint8_t* Src       = (const uint8_t*)__Buf__;
        long           Remaining = __Len__;
        long           Total     = 0;

        SysErr  err;
        SysErr* Error = &err;

        while (Remaining > 0)
        {
            long     CurOff = atomic_load_explicit(&FC->Offset, memory_order_relaxed);
            uint64_t CurLba = atomic_load_explicit(&FC->Lba, memory_order_relaxed);

            long ToWrite = Remaining;
            if (ToWrite > Blk - CurOff)
            {
                ToWrite = Blk - CurOff;
            }

            void* Tmp = KMalloc((size_t)Blk);
            if (Probe_IF_Error(Tmp) || !Tmp)
            {
                return (Total > 0) ? Total : -BadAllocation;
            }

            long rb = FC->Dev->Ops.B.ReadBlocks(FC->Dev->Context, CurLba, Tmp, 1);
            if (rb != 1)
            {
                __builtin_memset(Tmp, 0, (size_t)Blk);
            }

            memcpy((uint8_t*)Tmp + CurOff, Src + Total, (size_t)ToWrite);

            long wb = FC->Dev->Ops.B.WriteBlocks(FC->Dev->Context, CurLba, Tmp, 1);
            KFree(Tmp, Error);
            if (wb != 1)
            {
                break;
            }

            Total += ToWrite;
            Remaining -= ToWrite;

            long NewOff = CurOff + ToWrite;
            if (NewOff >= Blk)
            {
                atomic_store_explicit(&FC->Offset, 0, memory_order_relaxed);
                atomic_store_explicit(&FC->Lba, CurLba + 1, memory_order_relaxed);
            }
            else
            {
                atomic_store_explicit(&FC->Offset, NewOff, memory_order_relaxed);
            }
        }

        __File__->Offset += Total;
        return Total;
    }

    PushError("DevVfsWrite", LOGDEVFSC_PError, "unknown device type", -NotCanonical);
    return -BadWrite;
}

static long
DevVfsLseek(File* __File__, long __Off__, int __Whence__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        PushError("DevVfsLseek", LOGDEVFSC_PError, "bad arguments to DevVfsLseek", -BadArguments);
        return -BadArguments;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        PushError("DevVfsLseek", LOGDEVFSC_PError, "bad device in node", -Dangling);
        return -Dangling;
    }

    long Base = 0;
    if (__Whence__ == VSeekSET)
    {
        Base = 0;
    }
    else if (__Whence__ == VSeekCUR)
    {
        Base = __File__->Offset;
    }
    else if (__Whence__ == VSeekEND)
    {
        if (FC->Dev->Type == DevBlock && FC->Dev->Ops.B.BlockSize > 0)
        {
            long Blk = FC->Dev->Ops.B.BlockSize;
            Base     = (long)(__File__->Offset - (__File__->Offset % Blk) + Blk);
        }
        else
        {
            PushError(
                "DevVfsLseek", LOGDEVFSC_PError, "device does not support seeking", -NotCanonical);
            return -NotCanonical;
        }
    }
    else
    {
        PushError("DevVfsLseek", LOGDEVFSC_PError, "unknown whence", -NoSuch);
        return -NoSuch;
    }

    long New = Base + __Off__;
    if (New < 0)
    {
        New = 0;
    }

    __File__->Offset = New;

    if (FC->Dev->Type == DevBlock)
    {
        long     Blk = FC->Dev->Ops.B.BlockSize;
        uint64_t L   = (uint64_t)(New / Blk);
        long     O   = (long)(New % Blk);
        atomic_store_explicit(&FC->Lba, L, memory_order_relaxed);
        atomic_store_explicit(&FC->Offset, O, memory_order_relaxed);
    }
    else
    {
        atomic_store_explicit(&FC->Offset, New, memory_order_relaxed);
    }

    return New;
}

static int
DevVfsIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        PushError("DevVfsIoctl", LOGDEVFSC_PError, "bad arguments to DevVfsIoctl", -BadArguments);
        return -BadArguments;
    }
    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        PushError("DevVfsIoctl", LOGDEVFSC_PError, "bad device in node", -Dangling);
        return -Dangling;
    }

    if (FC->Dev->Type == DevChar)
    {
        if (!FC->Dev->Ops.C.Ioctl)
        {
            PushError("DevVfsIoctl", LOGDEVFSC_PError, "no ioctl operation", -NoOperations);
            return -NoOperations;
        }
        return FC->Dev->Ops.C.Ioctl(FC->Dev->Context, __Cmd__, __Arg__);
    }

    if (FC->Dev->Type == DevBlock)
    {
        if (!FC->Dev->Ops.B.Ioctl)
        {
            PushError("DevVfsIoctl", LOGDEVFSC_PError, "no ioctl operation", -NoOperations);
            return -NoOperations;
        }
        return FC->Dev->Ops.B.Ioctl(FC->Dev->Context, __Cmd__, __Arg__);
    }

    PushError("DevVfsIoctl", LOGDEVFSC_PError, "unknown device type", -NotCanonical);
    return -NoSuch;
}

static int
DevVfsStat(Vnode* __Node__, VfsStat* __Out__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        PushError("DevVfsStat", LOGDEVFSC_PError, "bad arguments to DevVfsStat", -BadArguments);
        return -BadArguments;
    }

    memset(__Out__, 0, sizeof(*__Out__));
    __Out__->Ino   = (long)(uintptr_t)__Node__;
    __Out__->Nlink = 1;

    if (__Node__->Type == VNodeDIR)
    {
        __Out__->Type = VNodeDIR;
        return SysOkay;
    }

    if (__Node__->Type == VNodeDEV)
    {
        DevFsNodePriv* NPriv = (DevFsNodePriv*)__Node__->Priv;
        __Out__->Type        = VNodeDEV;
        if (NPriv && NPriv->Dev && NPriv->Dev->Type == DevBlock)
        {
            __Out__->BlkSize = NPriv->Dev->Ops.B.BlockSize;
        }
        return SysOkay;
    }

    PushError("DevVfsStat", LOGDEVFSC_PError, "unknown node type", -NotCanonical);
    return -NoSuch;
}

static long
DevVfsReaddir(Vnode* __Dir__, void* __Buf__, long __BufLen__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __BufLen__ <= 0)
    {
        PushError(
            "DevVfsReaddir", LOGDEVFSC_PError, "bad arguments to DevVfsReaddir", -BadArguments);
        return -BadArguments;
    }

    if (__Dir__->Type != VNodeDIR)
    {
        PushError("DevVfsReaddir", LOGDEVFSC_PError, "not a directory", -BadEntity);
        return -BadEntity;
    }

    VfsDirEnt* DE    = (VfsDirEnt*)__Buf__;
    long       Cap   = __BufLen__;
    long       Wrote = 0;

    /* . */
    if (Wrote < Cap)
    {
        DE[Wrote].Name[0] = '.';
        DE[Wrote].Name[1] = '\0';
        DE[Wrote].Type    = VNodeDIR;
        DE[Wrote].Ino     = (long)(uintptr_t)__Dir__;
        Wrote++;
    }

    /* .. */
    if (Wrote < Cap)
    {
        DE[Wrote].Name[0] = '.';
        DE[Wrote].Name[1] = '.';
        DE[Wrote].Name[2] = '\0';
        DE[Wrote].Type    = VNodeDIR;
        DE[Wrote].Ino     = (long)(uintptr_t)__Dir__;
        Wrote++;
    }

    /* Snapshot count to avoid races */
    long Count = atomic_load_explicit(&__DevCount__, memory_order_acquire);

    for (long I = 0; I < Count && Wrote < Cap; I++)
    {
        DeviceEntry* E = atomic_load_explicit(&__DevTable__[I], memory_order_acquire);
        if (!E)
        {
            continue;
        }

        long        N  = 0;
        const char* Nm = E->Name;
        while (Nm[N] && N < 255)
        {
            DE[Wrote].Name[N] = Nm[N];
            N++;
        }
        DE[Wrote].Name[N] = '\0';

        DE[Wrote].Type = VNodeDEV;
        DE[Wrote].Ino  = (long)I; /* synthetic inode index */

        Wrote++;
    }

    return Wrote;
}

static Vnode*
DevVfsLookup(Vnode* __Dir__, const char* __Name__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("DevVfsLookup", LOGDEVFSC_PError, "bad arguments to DevVfsLookup", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }
    if (__Dir__->Type != VNodeDIR)
    {
        PushError("DevVfsLookup", LOGDEVFSC_PError, "not a directory", -BadEntity);
        return Error_TO_Pointer(-BadEntity);
    }

    DeviceEntry* E = __dev_find__(__Name__);
    if (Probe_IF_Error(E) || !E)
    {
        PushError("DevVfsLookup", LOGDEVFSC_PError, "no such device", Pointer_TO_Error(E));
        return Error_TO_Pointer(-NoSuch);
    }

    SysErr  err;
    SysErr* Error = &err;

    Vnode* V = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(V) || !V)
    {
        PushError(
            "DevVfsLookup", LOGDEVFSC_PError, "cannot allocate the vnode", Pointer_TO_Error(V));
        return Error_TO_Pointer(-BadAllocation);
    }

    DevFsNodePriv* NPriv = (DevFsNodePriv*)KMalloc(sizeof(DevFsNodePriv));
    if (Probe_IF_Error(NPriv) || !NPriv)
    {
        KFree(V, Error);
        PushError("DevVfsLookup",
                  LOGDEVFSC_PError,
                  "cannot allocate the node private",
                  Pointer_TO_Error(NPriv));
        return Error_TO_Pointer(-BadAllocation);
    }

    NPriv->Dev = E;
    V->Type    = VNodeDEV;
    V->Ops     = &__DevVfsOps__;
    V->Sb      = __Dir__->Sb;
    V->Priv    = NPriv;
    V->Refcnt  = 1;

    return V;
}

static int
DevVfsCreate(Vnode* __Dir__, const char* __Name__, long __Flags__, VfsPerm __Perm__)
{
    PushError("DevVfsCreate", LOGDEVFSC_PError, "not implemented", -Impilict);
    return -Impilict;
}

static int
DevVfsMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__)
{
    PushError("DevVfsMkdir", LOGDEVFSC_PError, "not implemented", -Impilict);
    return -Impilict;
}

static int
DevVfsSync(Vnode* __Node__)
{
    if (Probe_IF_Error(__Node__) || !__Node__)
    {
        PushError("DevVfsSync", LOGDEVFSC_PError, "bad arguments to DevVfsSync", -BadArguments);
        return -BadArguments;
    }
    return SysOkay;
}

static int
DevVfsSuperSync(Superblock* __Sb__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__)
    {
        PushError(
            "DevVfsSuperSync", LOGDEVFSC_PError, "bad arguments to DevVfsSuperSync", -BadArguments);
        return -BadArguments;
    }
    return SysOkay;
}

static int
DevVfsSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        PushError("DevVfsSuperStatFs",
                  LOGDEVFSC_PError,
                  "bad arguments to DevVfsSuperStatFs",
                  -BadArguments);
        return -BadArguments;
    }
    __Out__->TypeId  = 0x64657666; /* 'devf' magic */
    __Out__->Bsize   = 0;
    __Out__->Blocks  = 0;
    __Out__->Bfree   = 0;
    __Out__->Bavail  = 0;
    __Out__->Files   = atomic_load_explicit(&__DevCount__, memory_order_acquire);
    __Out__->Ffree   = 0;
    __Out__->Namelen = 255;
    __Out__->Flags   = 0;
    return SysOkay;
}

static void
DevVfsSuperRelease(Superblock* __Sb__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__)
    {
        SlotError(__Err__, -BadArguments);
        PushError(
            "DevVfsSuperRelease", LOGDEVFSC_PError, "bad superblock in argument", -BadArguments);
        return;
    }
    if (__Sb__->Root)
    {
        DevFsRootPriv* RPriv = (DevFsRootPriv*)__Sb__->Root->Priv;
        if (RPriv)
        {
            KFree(RPriv, __Err__);
        }
        KFree(__Sb__->Root, __Err__);
        __Sb__->Root = 0;
    }
    KFree(__Sb__, __Err__);
    atomic_store_explicit(&__DevSuper__, 0, memory_order_release);
}

static int
DevVfsSuperUmount(Superblock* __Sb__ _unused)
{
    return SysOkay;
}

/* Seed devices */

static long
__null_read__(void* __Ctx__ _unused, void* __Buf__ _unused, long __Len__ _unused)
{
    return 0; /* EOF */
}

static long
__null_write__(void* __Ctx__ _unused, const void* __Buf__ _unused, long __Len__)
{
    return __Len__; /* discard */
}

static int
__null_open__(void* __Ctx__ _unused)
{
    return SysOkay;
}

static int
__null_close__(void* __Ctx__ _unused)
{
    return SysOkay;
}

static int
__null_ioctl__(void* __Ctx__ _unused, unsigned long __Cmd__ _unused, void* __Arg__ _unused)
{
    PushError("__null_ioctl__", LOGDEVFSC_PError, "not implemented", -Impilict);
    return -Impilict;
}

static long
__zero_read__(void* __Ctx__ _unused, void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        PushError(
            "__zero_read__", LOGDEVFSC_PError, "bad arguments to __zero_read__", -BadArguments);
        return -BadArguments;
    }
    __builtin_memset(__Buf__, 0, (size_t)__Len__);
    return __Len__;
}

static long
__zero_write__(void* __Ctx__ _unused, const void* __Buf__ _unused, long __Len__)
{
    return __Len__;
}

int
DevFsRegisterSeedDevices(void)
{
    /* /dev/null */
    CharDevOps NullOps = {.Open  = __null_open__,
                          .Close = __null_close__,
                          .Read  = __null_read__,
                          .Write = __null_write__,
                          .Ioctl = __null_ioctl__};
    if (DevFsRegisterCharDevice("null", 1, 3, NullOps, 0) != SysOkay)
    {
        LOGDEVFSC_PWarn("cannot seed /dev/null\n");
    }

    /* /dev/zero */
    CharDevOps ZeroOps = {.Open  = __null_open__,
                          .Close = __null_close__,
                          .Read  = __zero_read__,
                          .Write = __zero_write__,
                          .Ioctl = __null_ioctl__};
    if (DevFsRegisterCharDevice("zero", 1, 5, ZeroOps, 0) != SysOkay)
    {
        LOGDEVFSC_PWarn("cannot seed /dev/zero\n");
    }

    LOGDEVFSC_PSuccess("Seed devices present\n");
    return SysOkay;
}