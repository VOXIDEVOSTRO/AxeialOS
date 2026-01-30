#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <RamFs.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGVFSRAMFSC_Debug
#    define LOGVFSRAMFSC_PDebug(fmt, ...) PDebug("[KERNEL>>VfsRamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSRAMFSC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSRAMFSC_Logs
#    define LOGVFSRAMFSC_PError(fmt, ...) PError("[KERNEL>>VfsRamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSRAMFSC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSRAMFSC_Logs
#    define LOGVFSRAMFSC_PWarn(fmt, ...) PWarn("[KERNEL>>VfsRamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSRAMFSC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSRAMFSC_Logs
#    define LOGVFSRAMFSC_PInfo(fmt, ...) PInfo("[KERNEL>>VfsRamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSRAMFSC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVFSRAMFSC_Logs
#    define LOGVFSRAMFSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>VfsRamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVFSRAMFSC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

const VnodeOps __RamVfsOps__ = {
    .Open     = RamVfsOpen,     /**< Open file/directory handle */
    .Close    = RamVfsClose,    /**< Close file handle and free resources */
    .Read     = RamVfsRead,     /**< Read data from file */
    .Write    = RamVfsWrite,    /**< Write to file (not implemented - read-only) */
    .Lseek    = RamVfsLseek,    /**< Seek to position within file */
    .Ioctl    = RamVfsIoctl,    /**< I/O control operations (not implemented) */
    .Stat     = RamVfsStat,     /**< Get file/directory metadata */
    .Readdir  = RamVfsReaddir,  /**< Read directory entries */
    .Lookup   = RamVfsLookup,   /**< Lookup child by name in directory */
    .Create   = RamVfsCreate,   /**< Create new file in directory */
    .Unlink   = RamVfsUnlink,   /**< Remove file (not implemented) */
    .Mkdir    = RamVfsMkdir,    /**< Create new directory */
    .Rmdir    = RamVfsRmdir,    /**< Remove directory (not implemented) */
    .Symlink  = RamVfsSymlink,  /**< Create symlink (not implemented) */
    .Readlink = RamVfsReadlink, /**< Read symlink target (not implemented) */
    .Link     = RamVfsLink,     /**< Create hard link (not implemented) */
    .Rename   = RamVfsRename,   /**< Rename/move file (not implemented) */
    .Chmod    = RamVfsChmod,    /**< Change permissions (no-op) */
    .Chown    = RamVfsChown,    /**< Change ownership (no-op) */
    .Truncate = RamVfsTruncate, /**< Truncate file (not implemented) */
    .Sync     = RamVfsSync,     /**< Synchronize file (no-op) */
    .Map      = RamVfsMap,      /**< Memory map file (not implemented) */
    .Unmap    = RamVfsUnmap     /**< Unmap memory (not implemented) */
};

const SuperOps __RamVfsSuperOps__ = {
    .Sync    = RamVfsSuperSync,    /**< Sync filesystem to storage (no-op) */
    .StatFs  = RamVfsSuperStatFs,  /**< Get filesystem statistics */
    .Release = RamVfsSuperRelease, /**< Release superblock resources */
    .Umount  = RamVfsSuperUmount   /**< Unmount filesystem (no-op) */
};

int
RamFsRegister(void)
{
    static FsType __RamFsType__ = {.Name = "ramfs", .Mount = RamFsMountImpl, .Priv = 0};

    if (VfsRegisterFs(&__RamFsType__) != SysOkay)
    {
        PushError("RamFsRegister",
                  LOGVFSRAMFSC_PError,
                  "failed to register RAMFS with VFS",
                  -NotRecorded);
        return -NotRecorded;
    }

    LOGVFSRAMFSC_PSuccess("Registered with VFS\n");
    return SysOkay;
}

Superblock*
RamFsMountImpl(const char* __Dev__ _unused, const char* __Opts__ _unused)
{
    SysErr  err;
    SysErr* Error = &err;

    if (!RamFS.Root)
    {
        PushError("RamFsMountImpl",
                  LOGVFSRAMFSC_PError,
                  "RAMFS root node is not initialized",
                  -NotInitilized);
        return Error_TO_Pointer(-NotInitilized);
    }

    Superblock* Sb = (Superblock*)KMalloc(sizeof(Superblock));
    if (Probe_IF_Error(Sb) || !Sb)
    {
        PushError("RamFsMountImpl",
                  LOGVFSRAMFSC_PError,
                  "failed to allocate superblock for RAMFS",
                  -BadAllocation);
        return Error_TO_Pointer(-BadAllocation);
    }

    Vnode* Root = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(Root) || !Root)
    {
        PushError("RamFsMountImpl",
                  LOGVFSRAMFSC_PError,
                  "failed to allocate root vnode for RAMFS",
                  -BadAllocation);
        KFree(Sb, Error);
        return Error_TO_Pointer(-BadAllocation);
    }

    RamVfsPrivNode* Priv = (RamVfsPrivNode*)KMalloc(sizeof(RamVfsPrivNode));
    if (Probe_IF_Error(Priv) || !Priv)
    {
        PushError("RamFsMountImpl",
                  LOGVFSRAMFSC_PError,
                  "failed to allocate private data for RAMFS root vnode",
                  -BadAllocation);
        KFree(Root, Error);
        KFree(Sb, Error);
        return Error_TO_Pointer(-BadAllocation);
    }

    Priv->Node   = RamFS.Root;
    Root->Type   = VNodeDIR;
    Root->Ops    = &__RamVfsOps__;
    Root->Sb     = Sb;
    Root->Priv   = Priv;
    Root->Refcnt = 1;

    Sb->Type  = 0;
    Sb->Dev   = 0;
    Sb->Flags = 0;
    Sb->Root  = Root;
    Sb->Ops   = &__RamVfsSuperOps__;
    Sb->Priv  = 0;

    LOGVFSRAMFSC_PDebug("Superblock created\n");
    return Sb;
}

int
RamVfsOpen(Vnode* __Node__, File* __File__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__File__) || !__File__)
    {
        PushError("RamVfsOpen", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    RamVfsPrivNode* PN = (RamVfsPrivNode*)__Node__->Priv;
    if (Probe_IF_Error(PN) || !PN || Probe_IF_Error(PN->Node) || !PN->Node)
    {
        PushError("RamVfsOpen", LOGVFSRAMFSC_PError, "dangling vnode private data", -NotCanonical);
        return -NotCanonical;
    }

    if (PN->Node->Type == RamFSNode_Directory)
    {
        __File__->Node   = __Node__;
        __File__->Offset = 0;
        __File__->Refcnt = 1;
        __File__->Priv   = 0;
        return SysOkay;
    }

    if (PN->Node->Type == RamFSNode_File)
    {
        RamVfsPrivFile* PF = (RamVfsPrivFile*)KMalloc(sizeof(RamVfsPrivFile));
        if (Probe_IF_Error(PF) || !PF)
        {
            PushError("RamVfsOpen",
                      LOGVFSRAMFSC_PError,
                      "failed to allocate private data for RAMFS file",
                      -BadAllocation);
            return -BadAllocation;
        }

        PF->Node   = PN->Node;
        PF->Offset = 0;

        __File__->Node   = __Node__;
        __File__->Offset = 0;
        __File__->Refcnt = 1;
        __File__->Priv   = PF;
        return 0;
    }

    PushError("RamVfsOpen", LOGVFSRAMFSC_PError, "unsupported RAMFS node type", -NoSuch);
    return -NoSuch;
}

int
RamVfsClose(File* __File__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        PushError("RamVfsClose", LOGVFSRAMFSC_PError, "bad file handle", -BadArguments);
        return -BadArguments;
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

long
RamVfsRead(File* __File__, void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        PushError("RamVfsRead", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    RamVfsPrivFile* PF = (RamVfsPrivFile*)__File__->Priv;
    if (Probe_IF_Error(PF) || !PF || Probe_IF_Error(PF->Node) || !PF->Node)
    {
        PushError("RamVfsRead", LOGVFSRAMFSC_PError, "dangling file private data", -Dangling);
        return -Dangling;
    }

    size_t Got = RamFSRead(PF->Node, (size_t)PF->Offset, __Buf__, (size_t)__Len__);
    if (Got > 0)
    {
        PF->Offset += (long)Got;
        __File__->Offset += (long)Got;
        return (long)Got;
    }

    return Nothing;
}

long
RamVfsWrite(File* __File__ _unused, const void* __Buf__ _unused, long __Len__ _unused)
{
    PushError("RamVfsWrite",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, write operation not supported",
              -Impilict);
    return -Impilict;
}

long
RamVfsLseek(File* __File__, long __Off__, int __Whence__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        PushError("RamVfsLseek", LOGVFSRAMFSC_PError, "bad file handle", -BadArguments);
        return -BadEntry;
    }

    RamVfsPrivFile* PF   = (RamVfsPrivFile*)__File__->Priv;
    long            Size = 0;

    if (PF && PF->Node && PF->Node->Type == RamFSNode_File)
    {
        Size = (long)PF->Node->Size;
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
        Base = Size;
    }
    else
    {
        PushError("RamVfsLseek", LOGVFSRAMFSC_PError, "bad whence argument", -NotCanonical);
        return -NotCanonical;
    }

    long New = Base + __Off__;
    if (New < 0)
    {
        New = 0;
    }
    if (PF && PF->Node && New > (long)PF->Node->Size)
    {
        New = (long)PF->Node->Size;
    }

    __File__->Offset = New;
    if (PF)
    {
        PF->Offset = New;
    }
    return New;
}

int
RamVfsIoctl(File* __File__ _unused, unsigned long __Cmd__ _unused, void* __Arg__ _unused)
{
    PushError("RamVfsIoctl", LOGVFSRAMFSC_PError, "IOCTL not supported on RAMFS", -Impilict);
    return -Impilict;
}

int
RamVfsStat(Vnode* __Node__, VfsStat* __Out__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        PushError("RamVfsStat", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    RamVfsPrivNode* PN = (RamVfsPrivNode*)__Node__->Priv;
    if (Probe_IF_Error(PN) || !PN || Probe_IF_Error(PN->Node) || !PN->Node)
    {
        PushError("RamVfsStat", LOGVFSRAMFSC_PError, "dangling vnode private data", -Dangling);
        return -Dangling;
    }

    __Out__->Ino        = (long)(uintptr_t)PN->Node;
    __Out__->Size       = (PN->Node->Type == RamFSNode_File) ? (long)PN->Node->Size : Nothing;
    __Out__->Blocks     = 0;
    __Out__->BlkSize    = 0;
    __Out__->Nlink      = 1;
    __Out__->Rdev       = 0;
    __Out__->Dev        = 0;
    __Out__->Flags      = 0;
    __Out__->Type       = __Node__->Type;
    __Out__->Perm.Mode  = 0;
    __Out__->Perm.Uid   = 0;
    __Out__->Perm.Gid   = 0;
    __Out__->Atime.Sec  = 0;
    __Out__->Atime.Nsec = 0;
    __Out__->Mtime.Sec  = 0;
    __Out__->Mtime.Nsec = 0;
    __Out__->Ctime.Sec  = 0;
    __Out__->Ctime.Nsec = 0;
    return SysOkay;
}

long
RamVfsReaddir(Vnode* __Dir__, void* __Buf__, long __BufLen__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __BufLen__ <= 0)
    {
        PushError("RamVfsReaddir", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    RamVfsPrivNode* PN = (RamVfsPrivNode*)__Dir__->Priv;
    if (Probe_IF_Error(PN) || !PN || Probe_IF_Error(PN->Node) || !PN->Node)
    {
        PushError("RamVfsReaddir", LOGVFSRAMFSC_PError, "dangling vnode private data", -Dangling);
        return -Dangling;
    }

    if (PN->Node->Type != RamFSNode_Directory)
    {
        PushError("RamVfsReaddir",
                  LOGVFSRAMFSC_PError,
                  "attempted to read directory entries from non-directory node",
                  -BadEntry);
        return -BadEntry;
    }

    long       Max = __BufLen__;
    RamFSNode* Tmp[RamFSMaxChildren];
    uint32_t   Cnt = RamFSListChildren(PN->Node, Tmp, RamFSMaxChildren);

    long       Wrote = 0;
    VfsDirEnt* DE    = (VfsDirEnt*)__Buf__;

    for (uint32_t I = 0; I < Cnt && Wrote < Max; I++)
    {
        RamFSNode*  C  = Tmp[I];
        long        N  = 0;
        const char* Nm = C->Name;
        while (Nm[N] && N < 255)
        {
            DE[Wrote].Name[N] = Nm[N];
            N++;
        }
        DE[Wrote].Name[N] = 0;
        DE[Wrote].Type    = (C->Type == RamFSNode_Directory) ? VNodeDIR : VNodeFILE;
        DE[Wrote].Ino     = (long)(uintptr_t)C;
        Wrote++;
    }

    return Wrote; /* return count of entries */
}

/** Fixed this shi because it wasn't looking inside childrens*/
Vnode*
RamVfsLookup(Vnode* __Dir__, const char* __Name__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("RamVfsLookup", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    RamVfsPrivNode* PN = (RamVfsPrivNode*)__Dir__->Priv;
    if (Probe_IF_Error(PN) || !PN || Probe_IF_Error(PN->Node) || !PN->Node ||
        PN->Node->Type != RamFSNode_Directory)
    {
        PushError("RamVfsLookup",
                  LOGVFSRAMFSC_PError,
                  "dangling vnode private data or non-directory node",
                  -BadEntry);
        return Error_TO_Pointer(-BadEntry);
    }

    RamFSNode* Child = 0;
    for (uint32_t I = 0; I < PN->Node->ChildCount; I++)
    {
        RamFSNode* C = PN->Node->Children[I];
        if (Probe_IF_Error(C) || !C || Probe_IF_Error(C->Name) || !C->Name)
        {
            continue;
        }
        if (strcmp(C->Name, __Name__) == 0)
        {
            Child = C;
            break;
        }
    }
    if (Probe_IF_Error(Child) || !Child)
    {
        PushError("RamVfsLookup", LOGVFSRAMFSC_PError, "child not found", -BadEntry);
        return Error_TO_Pointer(-BadEntry);
    }

    Vnode* V = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(V) || !V)
    {
        PushError("RamVfsLookup", LOGVFSRAMFSC_PError, "failed to allocate vnode", -BadAllocation);
        return Error_TO_Pointer(-BadAllocation);
    }

    RamVfsPrivNode* Priv = (RamVfsPrivNode*)KMalloc(sizeof(RamVfsPrivNode));
    if (Probe_IF_Error(Priv) || !Priv)
    {
        PushError("RamVfsLookup",
                  LOGVFSRAMFSC_PError,
                  "failed to allocate private vnode data",
                  -BadAllocation);
        SysErr  err;
        SysErr* Error = &err;
        KFree(V, Error);
        return Error_TO_Pointer(-BadAllocation);
    }

    Priv->Node = Child;
    V->Type    = (Child->Type == RamFSNode_Directory) ? VNodeDIR : VNodeFILE;
    V->Ops     = &__RamVfsOps__;
    V->Sb      = __Dir__->Sb;
    V->Priv    = Priv;
    V->Refcnt  = 1;

    return V;
}

int
RamVfsCreate(Vnode* __Dir__, const char* __Name__, long __Flags__ _unused, VfsPerm __Perm__ _unused)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("RamVfsCreate", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }
    RamVfsPrivNode* PN = (RamVfsPrivNode*)__Dir__->Priv;
    if (Probe_IF_Error(PN) || !PN || Probe_IF_Error(PN->Node) || !PN->Node)
    {
        PushError("RamVfsCreate", LOGVFSRAMFSC_PError, "dangling vnode private data", -Dangling);
        return -Dangling;
    }
    if (PN->Node->Type != RamFSNode_Directory)
    {
        PushError("RamVfsCreate",
                  LOGVFSRAMFSC_PError,
                  "attempted to create file in non-directory node",
                  -BadEntry);
        return -BadEntry;
    }

    char* Path = RamFSJoinPath(PN->Node->Name ? PN->Node->Name : "/", __Name__);
    if (Probe_IF_Error(Path) || !Path)
    {
        PushError(
            "RamVfsCreate", LOGVFSRAMFSC_PError, "failed to join path for new file", -NotCanonical);
        return -NotCanonical;
    }

    SysErr     err;
    SysErr*    Error = &err;
    RamFSNode* Leaf  = RamFSAttachPath(RamFS.Root, Path, RamFSNode_File, 0, 0);
    KFree(Path, Error);
    return Leaf ? SysOkay : -NotCanonical;
}

int
RamVfsUnlink(Vnode* __Dir__ _unused, const char* __Name__ _unused)
{
    PushError("RamVfsUnlink",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, unlink operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__ _unused)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("RamVfsMkdir", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    RamVfsPrivNode* PN = (RamVfsPrivNode*)__Dir__->Priv;
    if (Probe_IF_Error(PN) || !PN || Probe_IF_Error(PN->Node) || !PN->Node)
    {
        PushError("RamVfsMkdir", LOGVFSRAMFSC_PError, "dangling vnode private data", -Dangling);
        return -Dangling;
    }

    if (PN->Node->Type != RamFSNode_Directory)
    {
        PushError("RamVfsMkdir",
                  LOGVFSRAMFSC_PError,
                  "attempted to create directory in non-directory node",
                  -BadEntry);
        return -BadEntry;
    }

    char* Path = RamFSJoinPath(PN->Node->Name ? PN->Node->Name : "/", __Name__);
    if (Probe_IF_Error(Path) || !Path)
    {
        PushError("RamVfsMkdir",
                  LOGVFSRAMFSC_PError,
                  "failed to join path for new directory",
                  -NotCanonical);
        return -NotCanonical;
    }

    SysErr     err;
    SysErr*    Error = &err;
    RamFSNode* Leaf  = RamFSAttachPath(RamFS.Root, Path, RamFSNode_Directory, 0, 0);
    KFree(Path, Error);

    return Leaf ? SysOkay : -NotCanonical;
}

int
RamVfsRmdir(Vnode* __Dir__, const char* __Name__)
{
    PushError("RamVfsRmdir",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, rmdir operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsSymlink(Vnode* __Dir__, const char* __Name__, const char* __Target__, VfsPerm __Perm__)
{
    PushError("RamVfsSymlink",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, symlink operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsReadlink(Vnode* __Node__, VfsNameBuf* __Buf__)
{
    PushError("RamVfsReadlink",
              LOGVFSRAMFSC_PError,
              "RAMFS does not support symlinks, readlink operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsLink(Vnode* __Dir__, Vnode* __Src__, const char* __Name__)
{
    PushError("RamVfsLink",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, link operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsRename(Vnode*      __OldDir__,
             const char* __OldName__,
             Vnode*      __NewDir__,
             const char* __NewName__,
             long        __Flags__)
{
    PushError("RamVfsRename",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, rename operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsChmod(Vnode* __Node__ _unused, long __Mode__ _unused)
{
    return SysOkay;
}

int
RamVfsChown(Vnode* __Node__ _unused, long __Uid__ _unused, long __Gid__ _unused)
{
    return SysOkay;
}

int
RamVfsTruncate(Vnode* __Node__ _unused, long __Len__ _unused)
{
    PushError("RamVfsTruncate",
              LOGVFSRAMFSC_PError,
              "RAMFS is read-only, truncate operation not supported",
              -Impilict);
    return -Impilict;
}

int
RamVfsSync(Vnode* __Node__ _unused)
{
    return SysOkay;
}

int
RamVfsMap(Vnode* __Node__ _unused,
          void** __Out__  _unused,
          long __Off__    _unused,
          long __Len__    _unused)
{
    PushError("RamVfsMap", LOGVFSRAMFSC_PError, "RAMFS does not support memory mapping", -Impilict);
    return -Impilict;
}

int
RamVfsUnmap(Vnode* __Node__ _unused, void* __Addr__ _unused, long __Len__ _unused)
{
    PushError(
        "RamVfsUnmap", LOGVFSRAMFSC_PError, "RAMFS does not support memory unmapping", -Impilict);
    return -Impilict;
}

int
RamVfsSuperSync(Superblock* __Sb__ _unused)
{
    return SysOkay;
}

int
RamVfsSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        PushError("RamVfsSuperStatFs", LOGVFSRAMFSC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    __Out__->TypeId  = RamFSMagic;
    __Out__->Bsize   = 0;
    __Out__->Blocks  = 0;
    __Out__->Bfree   = 0;
    __Out__->Bavail  = 0;
    __Out__->Files   = 0;
    __Out__->Ffree   = 0;
    __Out__->Namelen = 255;
    __Out__->Flags   = 0;

    return SysOkay;
}

void
RamVfsSuperRelease(Superblock* __Sb__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__)
    {
        PushError("RamVfsSuperRelease", LOGVFSRAMFSC_PError, "bad superblock", -BadArguments);
        SlotError(__Err__, -BadArguments);
        return;
    }

    if (__Sb__->Root)
    {
        RamVfsPrivNode* PN = (RamVfsPrivNode*)__Sb__->Root->Priv;
        if (PN)
        {
            KFree(PN, __Err__);
        }
        KFree(__Sb__->Root, __Err__);
        __Sb__->Root = 0;
    }

    KFree(__Sb__, __Err__);
}

int
RamVfsSuperUmount(Superblock* __Sb__ _unused)
{
    return SysOkay;
}

int
BootMountRamFs(const void* __Initrd__, size_t __Len__)
{
    if (Probe_IF_Error(__Initrd__) || !__Initrd__ || __Len__ == 0)
    {
        PushError("BootMountRamFs", LOGVFSRAMFSC_PError, "bad initrd data", -BadArguments);
        return -BadArguments;
    }

    /* Parse the cpio archive */
    if (!RamFSMount(__Initrd__, __Len__))
    {
        PushError("BootMountRamFs",
                  LOGVFSRAMFSC_PError,
                  "failed to mount RAMFS from initrd",
                  -NotCanonical);
        return -NotCanonical;
    }

    if (RamFsRegister() != SysOkay)
    {
        PushError("BootMountRamFs",
                  LOGVFSRAMFSC_PError,
                  "failed to register RAMFS filesystem",
                  -NotRecorded);
        return -NotRecorded;
    }

    /* Mount as root '/' */
    if (!VfsMount(0, "/", "ramfs", VMFlgNONE, 0) ||
        Probe_IF_Error(VfsMount(0, "/", "ramfs", VMFlgNONE, 0)))
    {
        PushError(
            "BootMountRamFs", LOGVFSRAMFSC_PError, "failed to mount RAMFS as root '/'", -NotRooted);
        return -NotRooted;
    }

    LOGVFSRAMFSC_PSuccess("RamFS from BootImg/initrd mounted as '/' (root)\n");
    return SysOkay;
}
