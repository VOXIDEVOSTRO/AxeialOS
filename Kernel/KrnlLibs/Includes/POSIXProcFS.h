#pragma once
#include <AllTypes.h>
#include <KExports.h>
#include <Sync.h>
#include <VFS.h>

typedef enum ProcFsNodeKind
{
    ProcFsNodeNone    = 0,
    ProcFsNodeDir     = 1,
    ProcFsNodeFile    = 2,
    ProcFsNodeSymlink = 3
} ProcFsNodeKind;

typedef struct ProcFsNode
{
    ProcFsNodeKind Kind;
    char*          Name;
    long           Ino;
    VfsPerm        Perm;
    void*          Priv;
} ProcFsNode;

typedef struct ProcFsSuper
{
    Superblock* Super;
    ProcFsNode* Root;
    long        NextIno;
    SpinLock    Lock;
} ProcFsSuper;

typedef struct ProcFsFileCtx
{
    ProcFsNode* Node;
    long        Offset;
} ProcFsFileCtx;

long ProcFsMakeStat(PosixProc* __Proc__, char* __Buf__, long __Cap__);
long ProcFsMakeStatus(PosixProc* __Proc__, char* __Buf__, long __Cap__);
long ProcFsListFds(PosixProc* __Proc__, char* __Buf__, long __Cap__);
long ProcFsWriteState(PosixProc* __Proc__, const char* __Buf__, long __Len__);
long ProcFsWriteExec(PosixProc* __Proc__, const char* __Buf__, long __Len__);
long ProcFsWriteSignal(PosixProc* __Proc__, const char* __Buf__, long __Len__);

int         ProcFsInit(void);
Superblock* ProcFsMountImpl(const char* __Dev__, const char* __Opts__);
int         ProcFsRegisterMount(const char* __MountPath__, Superblock* __Super__);

int    ProcOpen(Vnode* __Node__, File* __File__);
int    ProcClose(File* __File__);
long   ProcRead(File* __File__, void* __Buf__, long __Len__);
long   ProcWrite(File* __File__, const void* __Buf__, long __Len__);
long   ProcLseek(File* __File__, long __Off__, int __Wh__);
int    ProcIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__);
int    ProcStat(Vnode* __Node__, VfsStat* __Out__);
long   ProcReaddir(Vnode* __Node__, void* __Buf__, long __Len__);
Vnode* ProcLookup(Vnode* __Dir__, const char* __Name__);
int    ProcCreate(Vnode* __Dir__, const char* __Name__, long __Flags__, VfsPerm __Perm__);
int    ProcUnlink(Vnode* __Dir__, const char* __Name__);
int    ProcMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__);
int    ProcRmdir(Vnode* __Dir__, const char* __Name__);
int    ProcSymlink(Vnode* __Dir__, const char* __Name__, const char* __Target__, VfsPerm __Perm__);
int    ProcReadlink(Vnode* __Node__, VfsNameBuf* __Buf__);
int    ProcLink(Vnode* __Dir__, Vnode* __Node__, const char* __Name__);
int    ProcRename(Vnode*      __FromDir__,
                  const char* __FromName__,
                  Vnode*      __ToDir__,
                  const char* __ToName__,
                  long        __Flags__);
int    ProcChmod(Vnode* __Node__, long __Mode__);
int    ProcChown(Vnode* __Node__, long __Uid__, long __Gid__);
int    ProcTruncate(Vnode* __Node__, long __Len__);
int    ProcSync(Vnode* __Node__);
int    ProcMap(Vnode* __Node__, void** __Out__, long __Len__, long __Flags__);
int    ProcUnmap(Vnode* __Node__, void* __Addr__, long __Len__);
int    ProcSuperSync(Superblock* __Sb__);
int    ProcSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__);
void   ProcSuperRelease(Superblock* __Sb__);
int    ProcSuperUmount(Superblock* __Sb__);
int    ProcFsNotifyProcAdded(PosixProc* __Proc__);
int    ProcFsNotifyProcRemoved(PosixProc* __Proc__);

/* Read-only */
extern const VnodeOps __ProcFsOps__;
extern const SuperOps __ProcFsSuperOps__;

KEXPORT(ProcFsInit)
KEXPORT(ProcFsMountImpl)
KEXPORT(ProcFsRegisterMount)