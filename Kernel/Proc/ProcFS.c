#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <POSIXProc.h>
#include <POSIXProcFS.h>
#include <POSIXSignals.h>
#include <String.h>
#include <Timer.h>
#include <VFS.h>

typedef struct ProcFsInode
{
    ProcFsNodeKind Kind;
    char*          Name;
    long           Ino;
    VfsPerm        Perm;
    void*          Priv;
} ProcFsInode;

typedef struct ProcFsPriv
{
    ProcFsNode* Root;
    long        NextIno;
    SpinLock    Lock;
} ProcFsPriv;

typedef struct ProcDirCursor
{
    long Index;
} ProcDirCursor;

static Superblock* ProcSuper;
static ProcFsPriv* ProcPriv;

#define ProcMaxPIDS 32768

typedef struct ProcPidEntry
{
    long        Pid;
    ProcFsNode* DirNode;
} ProcPidEntry;

static ProcPidEntry __ProcPidCache__[ProcMaxPIDS];

static inline long
__Min__(long a, long IdxUal)
{
    return a < IdxUal ? a : IdxUal;
}

static inline PosixProc*
__CurrentProc__(void)
{
    uint32_t CPU = GetCurrentCpuId();
    Thread*  Th  = GetCurrentThread(CPU);
    return Th ? PosixFind((long)Th->ProcessId) : Error_TO_Pointer(-NoSuch);
}

int
ProcFsNotifyProcAdded(PosixProc* __Proc__)
{

    if (Probe_IF_Error(__Proc__) || !__Proc__ || __Proc__->Pid <= 0 || __Proc__->Pid >= ProcMaxPIDS)
    {
        return -BadEntry;
    }

    SysErr  err;
    SysErr* Error = &err;

    ProcPidEntry* E = &__ProcPidCache__[__Proc__->Pid];

    long        curPid = __atomic_load_n(&E->Pid, __ATOMIC_SEQ_CST);
    ProcFsNode* curDir = __atomic_load_n(&E->DirNode, __ATOMIC_SEQ_CST);
    if (curPid == __Proc__->Pid && curDir)
    {
        return SysOkay;
    }

    char Num[32];
    UnsignedToStringEx((uint64_t)__Proc__->Pid, Num, 10, 0);

    ProcFsNode* D = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
    if (Probe_IF_Error(D) || !D)
    {
        return -BadAlloc;
    }
    memset(D, 0, sizeof(*D));
    D->Kind = ProcFsNodeDir;
    D->Name = (char*)KMalloc((uint32_t)(strlen(Num) + 1));
    if (Probe_IF_Error(D->Name) || !D->Name)
    {
        KFree(D, Error);
        return -BadAlloc;
    }
    strcpy(D->Name, Num, (uint32_t)(strlen(Num) + 1));
    D->Ino       = 100 + __Proc__->Pid;
    D->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH | VModeXUSR | VModeXGRP | VModeXOTH;
    D->Priv      = (void*)__Proc__;

    __atomic_store_n(&E->Pid, __Proc__->Pid, __ATOMIC_SEQ_CST);
    __atomic_store_n(&E->DirNode, D, __ATOMIC_SEQ_CST);

    return SysOkay;
}

int
ProcFsNotifyProcRemoved(PosixProc* __Proc__)
{
    if (Probe_IF_Error(__Proc__) || !__Proc__ || __Proc__->Pid <= 0 || __Proc__->Pid >= ProcMaxPIDS)
    {
        return -BadEntry;
    }

    SysErr  err;
    SysErr* Error = &err;

    ProcPidEntry* E = &__ProcPidCache__[__Proc__->Pid];

    long        curPid = __atomic_load_n(&E->Pid, __ATOMIC_SEQ_CST);
    ProcFsNode* curDir = __atomic_load_n(&E->DirNode, __ATOMIC_SEQ_CST);
    if (curPid == __Proc__->Pid && curDir)
    {
        if (curDir->Name)
        {
            KFree(curDir->Name, Error);
        }
        KFree(curDir, Error);
        __atomic_store_n(&E->DirNode, NULL, __ATOMIC_SEQ_CST);
        __atomic_store_n(&E->Pid, 0, __ATOMIC_SEQ_CST);
    }

    return SysOkay;
}

int
ProcOpen(Vnode* __Node__, File* __File__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__File__) || !__File__)
    {
        return -BadArgs;
    }
    __File__->Priv = NULL;
    return SysOkay;
}

int
ProcClose(File* __File__)
{
    return SysOkay;
}

long
ProcRead(File* __File__, void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        return -BadArgs;
    }
    Vnode* Node = __File__->Node;
    if (Probe_IF_Error(Node) || !Node)
    {
        return -Dangling;
    }

    ProcFsNode* Pn = (ProcFsNode*)Node->Priv;
    if (Probe_IF_Error(Pn) || !Pn)
    {
        return -Dangling;
    }

    char* Buf = (char*)__Buf__;
    long  Cap = __Len__;
    long  N   = 0;

    if (Pn->Kind == ProcFsNodeFile)
    {
        const char* Nm = Pn->Name;

        if (strcmp(Nm, "uptime") == 0)
        {
            uint64_t ticks = GetSystemTicks();
            uint64_t secs  = ticks / 1000;
            char     Num[32];
            long     N = 0;

            UnsignedToStringEx(secs, Num, 10, 0);
            strcpy(Buf + N, Num, (uint32_t)(Cap - N));
            N += (long)StringLength(Num);

            if (N < Cap)
            {
                Buf[N++] = ' ';
            }

            UnsignedToStringEx(0ULL, Num, 10, 0);
            strcpy(Buf + N, Num, (uint32_t)(Cap - N));
            N += (long)StringLength(Num);

            if (N < Cap)
            {
                Buf[N++] = '\n';
            }

            return N;
        }

        if (strcmp(Nm, "self") == 0)
        {
            PosixProc* cur = __CurrentProc__();
            if (Probe_IF_Error(cur) || !cur)
            {
                return Nothing;
            }
            UnsignedToStringEx((uint64_t)cur->Pid, Buf, 10, 0);
            return (long)StringLength(Buf);
        }

        if (strcmp(Nm, "stat") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr)
            {
                return -BadEntity;
            }
            return ProcFsMakeStat(Pr, Buf, Cap);
        }

        if (strcmp(Nm, "status") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr)
            {
                return -BadEntity;
            }
            return ProcFsMakeStatus(Pr, Buf, Cap);
        }

        if (strcmp(Nm, "fds") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr)
            {
                return -BadEntity;
            }
            return ProcFsListFds(Pr, Buf, Cap);
        }

        if (strcmp(Nm, "cwd") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr)
            {
                return -BadEntity;
            }
            strcpy(Buf, Pr->Cwd, (uint32_t)Cap);
            return (long)StringLength(Buf);
        }

        if (strcmp(Nm, "root") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr)
            {
                return -BadEntity;
            }
            strcpy(Buf, Pr->Root, (uint32_t)Cap);
            return (long)StringLength(Buf);
        }

        if (strcmp(Nm, "cmdline") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr || Pr->CmdlineLen <= 0)
            {
                ((char*)__Buf__)[0] = '\0';
                return Nothing;
            }
            long C = __Min__(Pr->CmdlineLen, __Len__);
            memcpy(__Buf__, Pr->CmdlineBuf, (size_t)C);
            return C;
        }
        if (strcmp(Nm, "environ") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (Probe_IF_Error(Pr) || !Pr || Pr->EnvironLen <= 0)
            {
                ((char*)__Buf__)[0] = '\0';
                return Nothing;
            }
            long C = __Min__(Pr->EnvironLen, __Len__);
            memcpy(__Buf__, Pr->EnvironBuf, (size_t)C);
            return C;
        }

        return Nothing;
    }

    return Nothing;
}

long
ProcWrite(File* __File__, const void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Buf__) || !__Buf__ ||
        __Len__ <= 0)
    {
        return -BadArgs;
    }
    Vnode* Node = __File__->Node;
    if (Probe_IF_Error(Node) || !Node)
    {
        return -Dangling;
    }
    ProcFsNode* Pn = (ProcFsNode*)Node->Priv;
    if (Probe_IF_Error(Pn) || !Pn || Pn->Kind != ProcFsNodeFile)
    {
        return -BadEntity;
    }

    const char* Nm  = Pn->Name;
    const char* Src = (const char*)__Buf__;

    if (strcmp(Nm, "state") == 0)
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (Probe_IF_Error(Pr) || !Pr)
        {
            return -BadEntity;
        }
        return ProcFsWriteState(Pr, Src, __Len__);
    }
    if (strcmp(Nm, "exec") == 0)
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (Probe_IF_Error(Pr) || !Pr)
        {
            return -BadEntity;
        }
        return ProcFsWriteExec(Pr, Src, __Len__);
    }
    if (strcmp(Nm, "signal") == 0)
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (Probe_IF_Error(Pr) || !Pr)
        {
            return -BadEntity;
        }
        return ProcFsWriteSignal(Pr, Src, __Len__);
    }

    return -NoWrite;
}

long
ProcLseek(File* __File__, long __Off__, int __Wh__)
{
    if (Probe_IF_Error(__File__) || !__File__)
    {
        return -BadArgs;
    }
    __File__->Offset = __Off__;
    return __Off__;
}

int
ProcIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__)
{
    return -Impilict;
}

int
ProcStat(Vnode* __Node__, VfsStat* __Out__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        return -BadArgs;
    }
    ProcFsNode* Pn = (ProcFsNode*)__Node__->Priv;
    if (Probe_IF_Error(Pn) || !Pn)
    {
        return -Dangling;
    }

    __Out__->Ino  = Pn->Ino;
    __Out__->Type = (Pn->Kind == ProcFsNodeDir) ? VNodeDIR : VNodeFILE;
    __Out__->Perm = Pn->Perm;
    __Out__->Size = 0;
    return SysOkay;
}

#define MaxProcFsCursors 64

typedef struct ProcDirCursorEntry
{
    Vnode* Node;
    long   Index;
} ProcDirCursorEntry;

static ProcDirCursorEntry __ProcDirCursors__[MaxProcFsCursors];

static ProcDirCursorEntry*
__GetCursor__(Vnode* __Node__)
{
    for (long I = 0; I < MaxProcFsCursors; I++)
    {
        Vnode* n = __atomic_load_n(&__ProcDirCursors__[I].Node, __ATOMIC_SEQ_CST);
        if (n == __Node__)
        {
            return &__ProcDirCursors__[I];
        }
    }
    for (long J = 0; J < MaxProcFsCursors; J++)
    {
        Vnode* n = __atomic_load_n(&__ProcDirCursors__[J].Node, __ATOMIC_SEQ_CST);
        if (!n)
        {
            __atomic_store_n(&__ProcDirCursors__[J].Node, __Node__, __ATOMIC_SEQ_CST);
            __atomic_store_n(&__ProcDirCursors__[J].Index, 0, __ATOMIC_SEQ_CST);
            return &__ProcDirCursors__[J];
        }
    }
    return Error_TO_Pointer(-NoSuch);
}

static void
__AdvanceCursor__(ProcDirCursorEntry* __C__)
{
    if (__C__)
    {
        long idx = __atomic_load_n(&__C__->Index, __ATOMIC_SEQ_CST);
        __atomic_store_n(&__C__->Index, idx + 1, __ATOMIC_SEQ_CST);
    }
}

static void
__ResetCursor__(ProcDirCursorEntry* __C__)
{
    if (__C__)
    {
        __atomic_store_n(&__C__->Index, 0, __ATOMIC_SEQ_CST);
    }
}

long
ProcReaddir(Vnode* __Node__, void* __Buf__, long __Len__)
{
    if (Probe_IF_Error(__Node__) || !__Node__ || Probe_IF_Error(__Buf__) || !__Buf__)
    {
        return -BadArgs;
    }

    SysErr  err;
    SysErr* Error = &err;

    ProcFsNode* Pn = (ProcFsNode*)__Node__->Priv;
    if (Probe_IF_Error(Pn) || !Pn || Pn->Kind != ProcFsNodeDir)
    {
        return BadEntity;
    }

    ProcDirCursorEntry* Cur = __GetCursor__(__Node__);
    if (Probe_IF_Error(Cur) || !Cur)
    {
        return -NoSuch;
    }

    VfsDirEnt* Ent = (VfsDirEnt*)__Buf__;
    long       Idx = __atomic_load_n(&Cur->Index, __ATOMIC_SEQ_CST);

    if (Idx == 0)
    {
        strcpy(Ent->Name, ".", 256);
        Ent->Type = VNodeDIR;
        Ent->Ino  = Pn->Ino;
        __AdvanceCursor__(Cur);
        return sizeof(VfsDirEnt);
    }
    if (Idx == 1)
    {
        strcpy(Ent->Name, "..", 256);
        Ent->Type = VNodeDIR;
        Ent->Ino  = Pn->Ino;
        __AdvanceCursor__(Cur);
        return sizeof(VfsDirEnt);
    }

    if (strcmp(Pn->Name, "") == 0)
    {
        long Base = Idx - 2;

        if (Base == 0)
        {
            strcpy(Ent->Name, "uptime", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 1;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (Base == 1)
        {
            strcpy(Ent->Name, "self", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 2;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }

        long ListIdx = Base - 2;
        long Seen    = 0;

        for (long pid = 1; pid < ProcMaxPIDS; pid++)
        {
            ProcPidEntry* E = &__ProcPidCache__[pid];
            ProcFsNode*   D = __atomic_load_n(&E->DirNode, __ATOMIC_SEQ_CST);

            if (Probe_IF_Error(D) || !D || Probe_IF_Error(D->Priv) || !D->Priv)
            {
                continue;
            }
            if (Seen++ < ListIdx)
            {
                continue;
            }

            PosixProc* Pr = (PosixProc*)D->Priv;
            char       Num[32];
            UnsignedToStringEx((uint64_t)Pr->Pid, Num, 10, 0);
            strcpy(Ent->Name, Num, 256);
            Ent->Type = VNodeDIR;
            Ent->Ino  = D->Ino;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }

        long FallbackIdx = ListIdx - Seen;
        long Count       = PosixProcs.Count;
        if (FallbackIdx >= 0 && FallbackIdx < Count)
        {
            PosixProc* Pr = PosixProcs.Items[FallbackIdx];
            if (Pr)
            {
                char Num[32];
                UnsignedToStringEx((uint64_t)Pr->Pid, Num, 10, 0);
                strcpy(Ent->Name, Num, 256);
                Ent->Type = VNodeDIR;
                Ent->Ino  = Pn->Ino + 100 + (long)Pr->Pid;
                __AdvanceCursor__(Cur);
                return sizeof(VfsDirEnt);
            }
        }
        __ResetCursor__(Cur);
        return Nothing;
    }
    else
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (Probe_IF_Error(Pr) || !Pr)
        {
            __ResetCursor__(Cur);
            return Nothing;
        }

        long LocalIdx = Idx - 2;

        if (LocalIdx == 0)
        {
            strcpy(Ent->Name, "stat", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 1;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 1)
        {
            strcpy(Ent->Name, "status", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 2;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 2)
        {
            strcpy(Ent->Name, "fds", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 3;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 3)
        {
            strcpy(Ent->Name, "state", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 4;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 4)
        {
            strcpy(Ent->Name, "exec", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 5;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 5)
        {
            strcpy(Ent->Name, "signal", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 6;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 6)
        {
            strcpy(Ent->Name, "cwd", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 7;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 7)
        {
            strcpy(Ent->Name, "root", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 8;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 8)
        {
            strcpy(Ent->Name, "cmdline", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 9;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 9)
        {
            strcpy(Ent->Name, "environ", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 10;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }

        __ResetCursor__(Cur);
        return Nothing;
    }
}

Vnode*
ProcLookup(Vnode* __Dir__, const char* __Name__)
{
    if (Probe_IF_Error(__Dir__) || !__Dir__ || Probe_IF_Error(__Name__) || !__Name__)
    {
        return Error_TO_Pointer(-BadArgs);
    }
    ProcFsNode* Pn = (ProcFsNode*)__Dir__->Priv;
    if (Probe_IF_Error(Pn) || !Pn || Pn->Kind != ProcFsNodeDir)
    {
        return Error_TO_Pointer(-BadEntity);
    }

    SysErr  err;
    SysErr* Error = &err;

    if (strcmp(Pn->Name, "") == 0)
    {
        if (strcmp(__Name__, "uptime") == 0)
        {
            ProcFsNode* F = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
            if (Probe_IF_Error(F) || !F)
            {
                return Error_TO_Pointer(-BadAlloc);
            }
            memset(F, 0, sizeof(*F));
            F->Kind      = ProcFsNodeFile;
            F->Name      = "uptime";
            F->Ino       = Pn->Ino + 1;
            F->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH;

            Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
            if (Probe_IF_Error(N) || !N)
            {
                return Error_TO_Pointer(-BadAlloc);
            }
            memset(N, 0, sizeof(*N));
            N->Type   = VNodeFILE;
            N->Ops    = &__ProcFsOps__;
            N->Sb     = ProcSuper;
            N->Priv   = F;
            N->Refcnt = 1;
            return N;
        }

        if (strcmp(__Name__, "self") == 0)
        {
            ProcFsNode* F = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
            if (Probe_IF_Error(F) || !F)
            {
                return Error_TO_Pointer(-BadAlloc);
            }
            memset(F, 0, sizeof(*F));
            F->Kind      = ProcFsNodeFile;
            F->Name      = "self";
            F->Ino       = Pn->Ino + 2;
            F->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH;

            Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
            if (Probe_IF_Error(N) || !N)
            {
                return Error_TO_Pointer(-BadAlloc);
            }
            memset(N, 0, sizeof(*N));
            N->Type   = VNodeFILE;
            N->Ops    = &__ProcFsOps__;
            N->Sb     = ProcSuper;
            N->Priv   = F;
            N->Refcnt = 1;
            return N;
        }

        long pid = atol(__Name__);
        if (pid > 0 && pid < ProcMaxPIDS)
        {
            ProcPidEntry* E = &__ProcPidCache__[pid];
            ProcFsNode*   D = __atomic_load_n(&E->DirNode, __ATOMIC_SEQ_CST);

            if (D && D->Priv)
            {
                Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
                if (Probe_IF_Error(N) || !N)
                {
                    return Error_TO_Pointer(-BadAlloc);
                }
                memset(N, 0, sizeof(*N));
                N->Type   = VNodeDIR;
                N->Ops    = &__ProcFsOps__;
                N->Sb     = ProcSuper;
                N->Priv   = D;
                N->Refcnt = 1;
                return N;
            }
        }

        for (long I = 0; I < PosixProcs.Count; I++)
        {
            PosixProc* Pr = PosixProcs.Items[I];
            if (Probe_IF_Error(Pr) || !Pr)
            {
                continue;
            }
            char Num[32];
            UnsignedToStringEx((uint64_t)Pr->Pid, Num, 10, 0);
            if (strcmp(__Name__, Num) == 0)
            {
                ProcFsNode* D = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
                if (Probe_IF_Error(D) || !D)
                {
                    return Error_TO_Pointer(-BadAlloc);
                }
                memset(D, 0, sizeof(*D));
                D->Kind = ProcFsNodeDir;
                D->Name = (char*)KMalloc(32);
                if (Probe_IF_Error(D->Name) || !D->Name)
                {
                    KFree(D, Error);
                    return Error_TO_Pointer(-BadAlloc);
                }
                strcpy(D->Name, Num, 32);
                D->Ino = Pn->Ino + 100 + (long)Pr->Pid;
                D->Perm.Mode =
                    VModeRUSR | VModeRGRP | VModeROTH | VModeXUSR | VModeXGRP | VModeXOTH;
                D->Priv = (void*)Pr;

                Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
                if (Probe_IF_Error(N) || !N)
                {
                    KFree(D->Name, Error);
                    KFree(D, Error);
                    return Error_TO_Pointer(-BadAlloc);
                }
                memset(N, 0, sizeof(*N));
                N->Type   = VNodeDIR;
                N->Ops    = &__ProcFsOps__;
                N->Sb     = ProcSuper;
                N->Priv   = D;
                N->Refcnt = 1;
                return N;
            }
        }
        return Error_TO_Pointer(-NoSuch);
    }
    else
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (Probe_IF_Error(Pr) || !Pr)
        {
            return Error_TO_Pointer(-Dangling);
        }

        const char* Fn[] = {"stat",
                            "status",
                            "fds",
                            "state",
                            "exec",
                            "signal",
                            "cwd",
                            "root",
                            "cmdline",
                            "environ"};
        for (long KIdx = 0; KIdx < 10; KIdx++)
        {
            if (strcmp(__Name__, Fn[KIdx]) == 0)
            {
                ProcFsNode* F = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
                if (Probe_IF_Error(F) || !F)
                {
                    return Error_TO_Pointer(-NoSuch);
                }
                memset(F, 0, sizeof(*F));
                F->Kind = ProcFsNodeFile;
                F->Name = (char*)KMalloc((uint32_t)(strlen(Fn[KIdx]) + 1));
                if (F->Name)
                {
                    strcpy(F->Name, Fn[KIdx], (uint32_t)(strlen(Fn[KIdx]) + 1));
                }
                F->Ino       = Pn->Ino + KIdx + 1;
                F->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH;
                if (KIdx >= 3 && KIdx <= 5)
                {
                    F->Perm.Mode = VModeRUSR | VModeWUSR;
                }
                F->Priv = (void*)Pr;

                Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
                if (Probe_IF_Error(N) || !N)
                {
                    if (F->Name)
                    {
                        KFree(F->Name, Error);
                    }
                    KFree(F, Error);
                    return Error_TO_Pointer(-NoSuch);
                }
                memset(N, 0, sizeof(*N));
                N->Type   = VNodeFILE;
                N->Ops    = &__ProcFsOps__;
                N->Sb     = ProcSuper;
                N->Priv   = F;
                N->Refcnt = 1;
                return N;
            }
        }
        return Error_TO_Pointer(-NoSuch);
    }
}

int
ProcCreate(Vnode* __Dir__, const char* __Name__, long __Flags__, VfsPerm __Perm__)
{
    return -Impilict;
}

int
ProcUnlink(Vnode* __Dir__, const char* __Name__)
{
    return -Impilict;
}

int
ProcMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__)
{
    return -Impilict;
}

int
ProcRmdir(Vnode* __Dir__, const char* __Name__)
{
    return -Impilict;
}

int
ProcSymlink(Vnode* __Dir__, const char* __Name__, const char* __Target__, VfsPerm __Perm__)
{
    return -Impilict;
}

int
ProcReadlink(Vnode* __Node__, VfsNameBuf* __Buf__)
{
    return -Impilict;
}

int
ProcLink(Vnode* __Dir__, Vnode* __Node__, const char* __Name__)
{
    return -Impilict;
}

int
ProcRename(Vnode*      __FromDir__,
           const char* __FromName__,
           Vnode*      __ToDir__,
           const char* __ToName__,
           long        __Flags__)
{
    return -Impilict;
}

int
ProcChmod(Vnode* __Node__, long __Mode__)
{
    return -Impilict;
}

int
ProcChown(Vnode* __Node__, long __Uid__, long __Gid__)
{
    return -Impilict;
}

int
ProcTruncate(Vnode* __Node__, long __Len__)
{
    return -Impilict;
}

int
ProcSync(Vnode* __Node__)
{
    return SysOkay;
}

int
ProcMap(Vnode* __Node__, void** __Out__, long __Len__, long __Flags__)
{
    return -Impilict;
}

int
ProcUnmap(Vnode* __Node__, void* __Addr__, long __Len__)
{
    return -Impilict;
}

int
ProcSuperSync(Superblock* __Sb__)
{
    return SysOkay;
}

int
ProcSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__)
{
    if (Probe_IF_Error(__Sb__) || !__Sb__ || Probe_IF_Error(__Out__) || !__Out__)
    {
        return -BadArgs;
    }
    __Out__->TypeId  = 0xDEAD7001;
    __Out__->Bsize   = 1;
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
ProcSuperRelease(Superblock* __Sb__, SysErr* __Err__)
{
}

int
ProcSuperUmount(Superblock* __Sb__)
{
    return SysOkay;
}

const VnodeOps __ProcFsOps__ = {ProcOpen,   ProcClose,  ProcRead,    ProcWrite,   ProcLseek,
                                ProcIoctl,  ProcStat,   ProcReaddir, ProcLookup,  ProcCreate,
                                ProcUnlink, ProcMkdir,  ProcRmdir,   ProcSymlink, ProcReadlink,
                                ProcLink,   ProcRename, ProcChmod,   ProcChown,   ProcTruncate,
                                ProcSync,   ProcMap,    ProcUnmap};

const SuperOps __ProcFsSuperOps__ = {
    ProcSuperSync, ProcSuperStatFs, ProcSuperRelease, ProcSuperUmount};

int
ProcFsInit(void)
{
    ProcPriv = (ProcFsPriv*)KMalloc(sizeof(ProcFsPriv));
    if (Probe_IF_Error(ProcPriv) || !ProcPriv)
    {
        return -BadAlloc;
    }
    SysErr  err;
    SysErr* Error = &err;

    memset(ProcPriv, 0, sizeof(*ProcPriv));

    memset(__ProcPidCache__, 0, sizeof(__ProcPidCache__));

    Superblock* Sb = ProcFsMountImpl(NULL, NULL);
    if (Probe_IF_Error(Sb) || !Sb)
    {
        return -Dangling;
    }
    if (ProcFsRegisterMount("/proc", Sb) != SysOkay)
    {
        return -NotRooted;
    }
    return SysOkay;
}

Superblock*
ProcFsMountImpl(const char* __Dev__, const char* __Opts__)
{
    ProcSuper = (Superblock*)KMalloc(sizeof(Superblock));
    if (Probe_IF_Error(ProcSuper) || !ProcSuper)
    {
        return Error_TO_Pointer(-BadAlloc);
    }
    memset(ProcSuper, 0, sizeof(*ProcSuper));
    ProcSuper->Type  = NULL;
    ProcSuper->Dev   = NULL;
    ProcSuper->Flags = 0;
    ProcSuper->Ops   = &__ProcFsSuperOps__;

    ProcFsNode* Root = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
    if (Probe_IF_Error(Root) || !Root)
    {
        return Error_TO_Pointer(-BadAlloc);
    }
    memset(Root, 0, sizeof(*Root));
    Root->Kind      = ProcFsNodeDir;
    Root->Name      = "";
    Root->Ino       = 1;
    Root->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH | VModeXUSR | VModeXGRP | VModeXOTH;

    Vnode* RootV = (Vnode*)KMalloc(sizeof(Vnode));
    if (Probe_IF_Error(RootV) || !RootV)
    {
        return Error_TO_Pointer(-BadAlloc);
    }
    memset(RootV, 0, sizeof(*RootV));
    RootV->Type   = VNodeDIR;
    RootV->Ops    = &__ProcFsOps__;
    RootV->Sb     = ProcSuper;
    RootV->Priv   = Root;
    RootV->Refcnt = 1;

    ProcSuper->Root = RootV;
    return ProcSuper;
}

int
ProcFsRegisterMount(const char* __MountPath__, Superblock* __Super__)
{
    return VfsRegisterPseudoFs(__MountPath__, __Super__);
}