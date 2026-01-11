
#include <DevFS.h>
#include <Errnos.h>

/* Registry limits */
static const long __MaxDevices__ = 256;

/* Registry store */
static DeviceEntry* __DevTable__[256];
static long         __DevCount__ = 0;

/* Root superblock and vnode (constructed at mount) */
static Superblock* __DevSuper__ = 0;

/* Forward declarations of VnodeOps and SuperOps */
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

/* Root vnode carrier (directory) */
typedef struct DevFsRootPriv
{
    int __Unused__; /* root uses registry globally, no per-root state */

} DevFsRootPriv;

/* Device node private carrier */
typedef struct DevFsNodePriv
{
    const DeviceEntry* Dev;

} DevFsNodePriv;

static long
__dev_index__(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        return -BadArgs;
    }
    for (long I = 0; I < __DevCount__; I++)
    {
        if (__DevTable__[I] && strcmp(__DevTable__[I]->Name, __Name__) == 0)
        {
            return I;
        }
    }
    return -NoSuch;
}

static DeviceEntry*
__dev_find__(const char* __Name__)
{
    long idx = __dev_index__(__Name__);
    return (idx >= 0) ? __DevTable__[idx] : Nothing;
}

int
DevFsInit(void)
{
    __DevCount__ = 0;
    __DevSuper__ = 0;
    PDebug("Init for DevFs registry\n");
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
        return -NotCanonical;
    }

    if (__DevCount__ >= __MaxDevices__)
    {
        return -TooMany;
    }

    if (__dev_find__(__Name__))
    {
        return -NoSuch;
    }

    DeviceEntry* E = (DeviceEntry*)KMalloc(sizeof(DeviceEntry));
    if (Probe_IF_Error(E) || !E)
    {
        return -BadAlloc;
    }

    memset(E, 0, sizeof(*E));

    SysErr  err;
    SysErr* Error = &err;

    const long CapName   = 255; /*uint8 Max*/
    char*      NameStore = (char*)KMalloc(CapName + 1);
    if (Probe_IF_Error(NameStore) || !NameStore)
    {
        KFree(E, Error);
        return -BadAlloc;
    }
    strncpy(NameStore, __Name__, CapName);
    NameStore[CapName] = '\0';

    E->Name    = NameStore;
    E->Type    = DevChar;
    E->Major   = __Major__;
    E->Minor   = __Minor__;
    E->Context = __Context__;
    memcpy(&E->Ops.C, &__Ops__, sizeof(CharDevOps));

    __DevTable__[__DevCount__] = E;
    __DevCount__++;

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
        return -NotCanonical;
    }
    if (__DevCount__ >= __MaxDevices__)
    {
        return -TooMany;
    }

    if (__dev_find__(__Name__))
    {
        PWarn("Device exists %s\n", __Name__);
        return -NoSuch;
    }

    DeviceEntry* E = (DeviceEntry*)KMalloc(sizeof(DeviceEntry));
    if (Probe_IF_Error(E) || !E)
    {
        return -BadAlloc;
    }

    E->Name    = __Name__;
    E->Type    = DevBlock;
    E->Major   = __Major__;
    E->Minor   = __Minor__;
    E->Context = __Context__;
    E->Ops.B   = __Ops__;

    __DevTable__[__DevCount__++] = E;
    PDebug("Block registered %s (blk=%ld)\n", __Name__, (long)__Ops__.BlockSize);
    return SysOkay;
}

int
DevFsUnregisterDevice(const char* __Name__)
{
    long idx = __dev_index__(__Name__);
    if (idx < 0)
    {
        return -NotCanonical;
    }
    SysErr  err;
    SysErr* Error = &err;
    KFree(__DevTable__[idx], Error);
    for (long J = idx; J < __DevCount__ - 1; J++)
    {
        __DevTable__[J] = __DevTable__[J + 1];
    }
    __DevTable__[--__DevCount__] = 0;
    PDebug("Unregistered %s\n", __Name__);
    return SysOkay;
}

int
DevFsRegister(void)
{
    static FsType __DevFsType__ = {.Name = "devfs", .Mount = DevFsMountImpl, .Priv = 0};

    if (VfsRegisterFs(&__DevFsType__) != SysOkay)
    {
        return -NotInit;
    }

    return SysOkay;
}

Superblock*
DevFsMountImpl(const char* __Dev__ __attribute__((unused)),
               const char* __Opts__ __attribute__((unused)))
{
    SysErr  err;
    SysErr* Error = &err;

    /* Allocate superblock and root directory vnode */
    Superblock* Sb = (Superblock*)KMalloc(sizeof(Superblock));
    if (Probe_IF_Error(Sb) || !Sb)
    {
        return Error_TO_Pointer(-BadAlloc);
    }

    Vnode* Root = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(Root) || !Root)
    {
        KFree(Sb, Error);
        return Error_TO_Pointer(-BadAlloc);
    }

    DevFsRootPriv* RPriv = (DevFsRootPriv*)KMalloc(sizeof(DevFsRootPriv));
    if (Probe_IF_Error(RPriv) || !RPriv)
    {
        KFree(Root, Error);
        KFree(Sb, Error);
        return Error_TO_Pointer(-BadAlloc);
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

    __DevSuper__ = Sb;
    PDebug("Superblock created\n");
    return Sb;
}

static int
DevVfsOpen(Vnode* __Node__, File* __File__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__File__) || !__File__)
    {
        return -BadArgs;
    }

    if (__Node__->Type == VNodeDIR)
    {
        __File__->Node   = __Node__;
        __File__->Offset = 0;
        __File__->Refcnt = 1;
        __File__->Priv   = 0;
        return SysOkay;
    }

    if (__Node__->Type == VNodeDEV)
    {
        DevFsNodePriv* NPriv = (DevFsNodePriv*)__Node__->Priv;
        if (Probe_IF_Error(NPriv) || !NPriv || Probe_IF_Error(NPriv->Dev) || !NPriv->Dev)
        {
            return -Dangling;
        }

        DevFsFileCtx* FC = (DevFsFileCtx*)KMalloc(sizeof(DevFsFileCtx));
        if (Probe_IF_Error(FC) || !FC)
        {
            return -BadAlloc;
        }

        FC->Dev    = NPriv->Dev;
        FC->Lba    = 0;
        FC->Offset = 0;

        __File__->Node   = __Node__;
        __File__->Offset = 0;
        __File__->Refcnt = 1;
        __File__->Priv   = FC;

        /* Call device open if provided */
        if (NPriv->Dev->Type == DevChar && NPriv->Dev->Ops.C.Open)
        {
            return NPriv->Dev->Ops.C.Open(NPriv->Dev->Context);
        }
        if (NPriv->Dev->Type == DevBlock && NPriv->Dev->Ops.B.Open)
        {
            return NPriv->Dev->Ops.B.Open(NPriv->Dev->Context);
        }

        return SysOkay;
    }

    return -NoSuch;
}

static int
DevVfsClose(File* __File__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        return -BadArgs;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (FC && FC->Dev)
    {
        if (FC->Dev->Type == DevChar && FC->Dev->Ops.C.Close)
        {
            FC->Dev->Ops.C.Close(FC->Dev->Context);
        }
        if (FC->Dev->Type == DevBlock && FC->Dev->Ops.B.Close)
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
        return -BadArgs;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        return -Dangling;
    }

    if (FC->Dev->Type == DevChar)
    {
        if (!FC->Dev->Ops.C.Read)
        {
            return -NoOperations;
        }
        long r = FC->Dev->Ops.C.Read(FC->Dev->Context, __Buf__, __Len__);
        if (r > 0)
        {
            __File__->Offset += r;
        }
        return r;
    }

    SysErr  err;
    SysErr* Error = &err;

    if (FC->Dev->Type == DevBlock)
    {
        if (!FC->Dev->Ops.B.ReadBlocks)
        {
            return -NoOperations;
        }

        /* Raw streaming over blocks: compute block span */
        long Blk = FC->Dev->Ops.B.BlockSize;
        if (Blk <= 0)
        {
            return -Limits;
        }

        uint8_t* Dst       = (uint8_t*)__Buf__;
        long     Remaining = __Len__;
        long     Total     = 0;

        while (Remaining > 0)
        {
            long ToRead = Remaining;
            if (ToRead > Blk - FC->Offset)
            {
                ToRead = Blk - FC->Offset;
            }

            /* Read one block into a temporary buffer then copy slice */
            void* Tmp = KMalloc((size_t)Blk);
            if (Probe_IF_Error(Tmp) || !Tmp)
            {
                return (Total > 0) ? Total : -BadAlloc;
            }

            long rb = FC->Dev->Ops.B.ReadBlocks(FC->Dev->Context, FC->Lba, Tmp, 1);
            if (rb != 1)
            {
                KFree(Tmp, Error);
                break;
            }

            memcpy(Dst + Total, (uint8_t*)Tmp + FC->Offset, (size_t)ToRead);
            KFree(Tmp, Error);

            Total += ToRead;
            Remaining -= ToRead;
            FC->Offset += ToRead;

            if (FC->Offset >= Blk)
            {
                FC->Offset = 0;
                FC->Lba++;
            }
        }

        __File__->Offset += Total;
        return Total;
    }

    return -NoRead;
}

static long
DevVfsWrite(File* __File__, const void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        return -BadArgs;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        return -Dangling;
    }

    if (FC->Dev->Type == DevChar)
    {
        if (!FC->Dev->Ops.C.Write)
        {
            return -NoOperations;
        }
        long w = FC->Dev->Ops.C.Write(FC->Dev->Context, __Buf__, __Len__);
        if (w > 0)
        {
            __File__->Offset += w;
        }
        return w;
    }
    SysErr  err;
    SysErr* Error = &err;
    if (FC->Dev->Type == DevBlock)
    {
        if (!FC->Dev->Ops.B.WriteBlocks)
        {
            return -NoOperations;
        }

        long Blk = FC->Dev->Ops.B.BlockSize;
        if (Blk <= 0)
        {
            return -Limits;
        }

        const uint8_t* Src       = (const uint8_t*)__Buf__;
        long           Remaining = __Len__;
        long           Total     = 0;

        while (Remaining > 0)
        {
            long ToWrite = Remaining;
            if (ToWrite > Blk - FC->Offset)
            {
                ToWrite = Blk - FC->Offset;
            }

            void* Tmp = KMalloc((size_t)Blk);
            if (Probe_IF_Error(Tmp) || !Tmp)
            {
                return (Total > 0) ? Total : -BadAlloc;
            }

            /* Read-modify-write current block to preserve untouched bytes */
            long rb = FC->Dev->Ops.B.ReadBlocks(FC->Dev->Context, FC->Lba, Tmp, 1);
            if (rb != 1)
            {
                __builtin_memset(Tmp, 0, (size_t)Blk);
            }

            memcpy((uint8_t*)Tmp + FC->Offset, Src + Total, (size_t)ToWrite);

            long wb = FC->Dev->Ops.B.WriteBlocks(FC->Dev->Context, FC->Lba, Tmp, 1);
            KFree(Tmp, Error);
            if (wb != 1)
            {
                break;
            }

            Total += ToWrite;
            Remaining -= ToWrite;
            FC->Offset += ToWrite;

            if (FC->Offset >= Blk)
            {
                FC->Offset = 0;
                FC->Lba++;
            }
        }

        __File__->Offset += Total;
        return Total;
    }

    return -NoWrite;
}

static long
DevVfsLseek(File* __File__, long __Off__, int __Whence__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        return -BadArgs;
    }

    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
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
        /* Devices generally have no canonical size; for block devs we can treat END as "align to
         * next block boundary" */
        if (FC->Dev->Type == DevBlock && FC->Dev->Ops.B.BlockSize > 0)
        {
            Base = (long)(__File__->Offset - (__File__->Offset % FC->Dev->Ops.B.BlockSize) +
                          FC->Dev->Ops.B.BlockSize);
        }
        else
        {
            return -NotCanonical;
        }
    }
    else
    {
        return -NoSuch;
    }

    long New = Base + __Off__;
    if (New < 0)
    {
        New = 0;
    }

    /* Update streaming cursor */
    __File__->Offset = New;

    if (FC->Dev->Type == DevBlock)
    {
        long Blk   = FC->Dev->Ops.B.BlockSize;
        FC->Lba    = (uint64_t)(New / Blk);
        FC->Offset = (long)(New % Blk);
    }
    else
    {
        FC->Offset = New;
    }

    return New;
}

static int
DevVfsIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__ /*Could have used Vargs*/)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        return -BadEntity;
    }
    DevFsFileCtx* FC = (DevFsFileCtx*)__File__->Priv;
    if (Probe_IF_Error(FC) || !FC || Probe_IF_Error(FC->Dev) || !FC->Dev)
    {
        return -Dangling;
    }

    if (FC->Dev->Type == DevChar)
    {
        if (!FC->Dev->Ops.C.Ioctl)
        {
            return -NoOperations;
        }
        return FC->Dev->Ops.C.Ioctl(FC->Dev->Context, __Cmd__, __Arg__);
    }

    if (FC->Dev->Type == DevBlock)
    {
        if (!FC->Dev->Ops.B.Ioctl)
        {
            return -NoOperations;
        }
        return FC->Dev->Ops.B.Ioctl(FC->Dev->Context, __Cmd__, __Arg__);
    }

    return -NoSuch;
}

static int
DevVfsStat(Vnode* __Node__, VfsStat* __Out__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        return -BadArgs;
    }

    __Out__->Ino        = (long)(uintptr_t)__Node__;
    __Out__->Blocks     = 0;
    __Out__->BlkSize    = 0;
    __Out__->Nlink      = 1;
    __Out__->Rdev       = 0;
    __Out__->Dev        = 0;
    __Out__->Flags      = 0;
    __Out__->Perm.Mode  = 0;
    __Out__->Perm.Uid   = 0;
    __Out__->Perm.Gid   = 0;
    __Out__->Atime.Sec  = 0;
    __Out__->Atime.Nsec = 0;
    __Out__->Mtime.Sec  = 0;
    __Out__->Mtime.Nsec = 0;
    __Out__->Ctime.Sec  = 0;
    __Out__->Ctime.Nsec = 0;

    if (__Node__->Type == VNodeDIR)
    {
        __Out__->Type = VNodeDIR;
        __Out__->Size = 0;
        return SysOkay;
    }

    if (__Node__->Type == VNodeDEV)
    {
        DevFsNodePriv* NPriv = (DevFsNodePriv*)__Node__->Priv;
        __Out__->Type        = VNodeDEV;
        __Out__->Size        = 0;
        if (NPriv && NPriv->Dev && NPriv->Dev->Type == DevBlock)
        {
            __Out__->BlkSize = NPriv->Dev->Ops.B.BlockSize;
        }
        return SysOkay;
    }

    return -NoSuch;
}

static long
DevVfsReaddir(Vnode* __Dir__, void* __Buf__, long __BufLen__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __BufLen__ <= 0)
    {
        return -BadArgs;
    }

    if (__Dir__->Type != VNodeDIR)
    {
        return -BadEntity;
    }

    long Max = __BufLen__;

    if (Max <= 0)
    {
        return -TooSmall;
    }

    VfsDirEnt* DE    = (VfsDirEnt*)__Buf__;
    long       Wrote = 0;

    if (Wrote < Max)
    {
        DE[Wrote].Name[0] = '.';
        DE[Wrote].Name[1] = '\0';
        DE[Wrote].Type    = VNodeDIR;
        DE[Wrote].Ino     = (long)(uintptr_t)__Dir__;
        Wrote++;
    }

    if (Wrote < Max)
    {
        DE[Wrote].Name[0] = '.';
        DE[Wrote].Name[1] = '.';
        DE[Wrote].Name[2] = '\0';
        DE[Wrote].Type    = VNodeDIR;
        DE[Wrote].Ino     = (long)(uintptr_t)__Dir__; /* or parent if tracked */
        Wrote++;
    }

    for (long I = 0; I < __DevCount__ && Wrote < Max; I++)
    {
        DeviceEntry* E = __DevTable__[I];
        if (Probe_IF_Error(E) || !E)
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
        DE[Wrote].Ino  = (long)I; /** synthetic inode index */

        Wrote++;
    }

    return Wrote;
}

static Vnode*
DevVfsLookup(Vnode* __Dir__, const char* __Name__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Name__) || !__Name__)
    {
        return Error_TO_Pointer(-BadArgs);
    }
    if (__Dir__->Type != VNodeDIR)
    {
        return Error_TO_Pointer(-BadEntity);
    }

    DeviceEntry* E = __dev_find__(__Name__);
    if (Probe_IF_Error(E) || !E)
    {
        return Error_TO_Pointer(-NoSuch);
    }

    Vnode* V = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(V) || !V)
    {
        return Error_TO_Pointer(-BadAlloc);
    }

    SysErr  err;
    SysErr* Error = &err;

    DevFsNodePriv* NPriv = (DevFsNodePriv*)KMalloc(sizeof(DevFsNodePriv));
    if (Probe_IF_Error(NPriv) || !NPriv)
    {
        KFree(V, Error);
        return Error_TO_Pointer(-BadAlloc);
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
    return -Impilict;
}

static int
DevVfsMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__)
{
    return -Impilict;
}

static int
DevVfsSync(Vnode* __Node__)
{
    return SysOkay;
}

static int
DevVfsSuperSync(Superblock* __Sb__)
{
    return SysOkay;
}

static int
DevVfsSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        return -BadArgs;
    }
    __Out__->TypeId  = 0x64657666; /* 'devf' magic */
    __Out__->Bsize   = 0;
    __Out__->Blocks  = 0;
    __Out__->Bfree   = 0;
    __Out__->Bavail  = 0;
    __Out__->Files   = __DevCount__;
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
        SlotError(__Err__, -BadArgs);
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
}

static int
DevVfsSuperUmount(Superblock* __Sb__)
{
    return SysOkay;
}

static long
__null_read__(void* __Ctx__, void* __Buf__, long __Len__)
{
    return 0; /* EOF */
}

static long
__null_write__(void* __Ctx__, const void* __Buf__, long __Len__)
{
    return __Len__; /* discard */
}

static int
__null_open__(void* __Ctx__)
{
    return SysOkay;
}

static int
__null_close__(void* __Ctx__)
{
    return SysOkay;
}

static int
__null_ioctl__(void* __Ctx__, unsigned long __Cmd__, void* __Arg__)
{
    return -Impilict;
}

static long
__zero_read__(void* __Ctx__, void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__ || __Len__ <= 0)
    {
        return -BadArgs;
    }
    __builtin_memset(__Buf__, 0, (size_t)__Len__);
    return __Len__;
}

static long
__zero_write__(void* __Ctx__, const void* __Buf__, long __Len__)
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
        PWarn("cannot seed /dev/null\n"); /*Used warn because not neccessary*/
    }

    /* /dev/zero */
    CharDevOps ZeroOps = {.Open  = __null_open__,
                          .Close = __null_close__,
                          .Read  = __zero_read__,
                          .Write = __zero_write__,
                          .Ioctl = __null_ioctl__};
    if (DevFsRegisterCharDevice("zero", 1, 5, ZeroOps, 0) != SysOkay)
    {
        PWarn("cannot seed /dev/zero\n");
    }

    PSuccess("Seed devices present\n");
    return SysOkay;
}