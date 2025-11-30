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
    return Th ? PosixFind((long)Th->ProcessId) : NULL;
}

int
ProcFsNotifyProcAdded(PosixProc* __Proc__)
{
    if (!__Proc__ || __Proc__->Pid <= 0 || __Proc__->Pid >= ProcMaxPIDS)
    {
        return -1;
    }

    AcquireSpinLock(&ProcPriv->Lock);

    ProcPidEntry* E = &__ProcPidCache__[__Proc__->Pid];
    if (E->Pid == __Proc__->Pid && E->DirNode)
    {
        ReleaseSpinLock(&ProcPriv->Lock);
        return 0;
    }

    char Num[32];
    UnsignedToStringEx((uint64_t)__Proc__->Pid, Num, 10, 0);

    ProcFsNode* D = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
    if (!D)
    {
        ReleaseSpinLock(&ProcPriv->Lock);
        return -1;
    }
    memset(D, 0, sizeof(*D));
    D->Kind = ProcFsNodeDir;
    D->Name = (char*)KMalloc((uint32_t)(strlen(Num) + 1));
    if (!D->Name)
    {
        KFree(D);
        ReleaseSpinLock(&ProcPriv->Lock);
        return -1;
    }
    StringCopy(D->Name, Num, (uint32_t)(strlen(Num) + 1));
    D->Ino       = 100 + __Proc__->Pid;
    D->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH | VModeXUSR | VModeXGRP | VModeXOTH;
    D->Priv      = (void*)__Proc__;

    E->Pid     = __Proc__->Pid;
    E->DirNode = D;

    ReleaseSpinLock(&ProcPriv->Lock);
    return 0;
}

int
ProcFsNotifyProcRemoved(PosixProc* __Proc__)
{
    if (!__Proc__ || __Proc__->Pid <= 0 || __Proc__->Pid >= ProcMaxPIDS)
    {
        return -1;
    }

    AcquireSpinLock(&ProcPriv->Lock);

    ProcPidEntry* E = &__ProcPidCache__[__Proc__->Pid];
    if (E->Pid == __Proc__->Pid && E->DirNode)
    {
        if (E->DirNode->Name)
        {
            KFree(E->DirNode->Name);
        }
        KFree(E->DirNode);
        E->DirNode = NULL;
        E->Pid     = 0;
    }

    ReleaseSpinLock(&ProcPriv->Lock);
    return 0;
}

int
ProcOpen(Vnode* __Node__, File* __File__)
{
    if (!__Node__ || !__File__)
    {
        return -1;
    }
    __File__->Priv = NULL;
    return 0;
}

int
ProcClose(File* __File__)
{
    return 0;
}

long
ProcRead(File* __File__, void* __Buf__, long __Len__)
{
    if (!__File__ || !__Buf__ || __Len__ <= 0)
    {
        return -1;
    }
    Vnode* Node = __File__->Node;
    if (!Node)
    {
        return -1;
    }

    ProcFsNode* Pn = (ProcFsNode*)Node->Priv;
    if (!Pn)
    {
        return -1;
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
            uint64_t secs  = ticks / 1000; /* 1 tick = 1ms */
            char     Num[32];
            long     N = 0;

            UnsignedToStringEx(secs, Num, 10, 0);
            StringCopy(Buf + N, Num, (uint32_t)(Cap - N));
            N += (long)StringLength(Num);

            /* space separator */
            if (N < Cap)
            {
                Buf[N++] = ' ';
            }

            UnsignedToStringEx(0ULL, Num, 10, 0);
            StringCopy(Buf + N, Num, (uint32_t)(Cap - N));
            N += (long)StringLength(Num);

            /* newline terminator */
            if (N < Cap)
            {
                Buf[N++] = '\n';
            }

            return N;
        }

        if (strcmp(Nm, "self") == 0)
        {
            PosixProc* cur = __CurrentProc__();
            if (!cur)
            {
                return 0;
            }
            UnsignedToStringEx((uint64_t)cur->Pid, Buf, 10, 0);
            return (long)StringLength(Buf);
        }

        if (strcmp(Nm, "stat") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr)
            {
                return -1;
            }
            return ProcFsMakeStat(Pr, Buf, Cap);
        }

        if (strcmp(Nm, "status") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr)
            {
                return -1;
            }
            return ProcFsMakeStatus(Pr, Buf, Cap);
        }

        if (strcmp(Nm, "fds") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr)
            {
                return -1;
            }
            return ProcFsListFds(Pr, Buf, Cap);
        }

        if (strcmp(Nm, "cwd") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr)
            {
                return -1;
            }
            StringCopy(Buf, Pr->Cwd, (uint32_t)Cap);
            return (long)StringLength(Buf);
        }

        if (strcmp(Nm, "root") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr)
            {
                return -1;
            }
            StringCopy(Buf, Pr->Root, (uint32_t)Cap);
            return (long)StringLength(Buf);
        }

        if (strcmp(Nm, "cmdline") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr || Pr->CmdlineLen <= 0)
            {
                ((char*)__Buf__)[0] = '\0';
                return 0;
            }
            long C = __Min__(Pr->CmdlineLen, __Len__);
            __builtin_memcpy(__Buf__, Pr->CmdlineBuf, (size_t)C);
            return C;
        }
        if (strcmp(Nm, "environ") == 0)
        {
            PosixProc* Pr = (PosixProc*)Pn->Priv;
            if (!Pr || Pr->EnvironLen <= 0)
            {
                ((char*)__Buf__)[0] = '\0';
                return 0;
            }
            long C = __Min__(Pr->EnvironLen, __Len__);
            __builtin_memcpy(__Buf__, Pr->EnvironBuf, (size_t)C);
            return C;
        }

        return 0;
    }

    return 0;
}

long
ProcWrite(File* __File__, const void* __Buf__, long __Len__)
{
    if (!__File__ || !__Buf__ || __Len__ <= 0)
    {
        return -1;
    }
    Vnode* Node = __File__->Node;
    if (!Node)
    {
        return -1;
    }
    ProcFsNode* Pn = (ProcFsNode*)Node->Priv;
    if (!Pn || Pn->Kind != ProcFsNodeFile)
    {
        return -1;
    }

    const char* Nm  = Pn->Name;
    const char* Src = (const char*)__Buf__;

    if (strcmp(Nm, "state") == 0)
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (!Pr)
        {
            return -1;
        }
        return ProcFsWriteState(Pr, Src, __Len__);
    }
    if (strcmp(Nm, "exec") == 0)
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (!Pr)
        {
            return -1;
        }
        return ProcFsWriteExec(Pr, Src, __Len__);
    }
    if (strcmp(Nm, "signal") == 0)
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (!Pr)
        {
            return -1;
        }
        return ProcFsWriteSignal(Pr, Src, __Len__);
    }

    return -1;
}

long
ProcLseek(File* __File__, long __Off__, int __Wh__)
{
    if (!__File__)
    {
        return -1;
    }
    __File__->Offset = __Off__;
    return __Off__;
}

int
ProcIoctl(File* __File__, unsigned long __Cmd__, void* __Arg__)
{
    return -1;
}

int
ProcStat(Vnode* __Node__, VfsStat* __Out__)
{
    if (!__Node__ || !__Out__)
    {
        return -1;
    }
    ProcFsNode* Pn = (ProcFsNode*)__Node__->Priv;
    if (!Pn)
    {
        return -1;
    }

    __Out__->Ino  = Pn->Ino;
    __Out__->Type = (Pn->Kind == ProcFsNodeDir) ? VNodeDIR : VNodeFILE;
    __Out__->Perm = Pn->Perm;
    __Out__->Size = 0;
    return 0;
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
        if (__ProcDirCursors__[I].Node == __Node__)
        {
            return &__ProcDirCursors__[I];
        }
    }
    for (long J = 0; J < MaxProcFsCursors; J++)
    {
        if (!__ProcDirCursors__[J].Node)
        {
            __ProcDirCursors__[J].Node  = __Node__;
            __ProcDirCursors__[J].Index = 0;
            return &__ProcDirCursors__[J];
        }
    }
    return NULL;
}

static void
__AdvanceCursor__(ProcDirCursorEntry* __C__)
{
    if (__C__)
    {
        __C__->Index++;
    }
}

static void
__ResetCursor__(ProcDirCursorEntry* __C__)
{
    if (__C__)
    {
        __C__->Index = 0;
    }
}

long
ProcReaddir(Vnode* __Node__, void* __Buf__, long __Len__)
{
    if (!__Node__ || !__Buf__)
    {
        return -1;
    }

    ProcFsNode* Pn = (ProcFsNode*)__Node__->Priv;
    if (!Pn || Pn->Kind != ProcFsNodeDir)
    {
        return -1;
    }

    ProcDirCursorEntry* Cur = __GetCursor__(__Node__);
    if (!Cur)
    {
        return -1;
    }

    VfsDirEnt* Ent = (VfsDirEnt*)__Buf__;
    long       Idx = Cur->Index;

    if (Idx == 0)
    {
        StringCopy(Ent->Name, ".", 256);
        Ent->Type = VNodeDIR;
        Ent->Ino  = Pn->Ino;
        __AdvanceCursor__(Cur);
        return sizeof(VfsDirEnt);
    }
    if (Idx == 1)
    {
        StringCopy(Ent->Name, "..", 256);
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
            StringCopy(Ent->Name, "uptime", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 1;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (Base == 1)
        {
            StringCopy(Ent->Name, "self", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 2;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }

        long ListIdx = Base - 2;
        long Seen    = 0;

        for (long pid = 1; pid < ProcMaxPIDS; pid++)
        {
            AcquireSpinLock(&ProcPriv->Lock);
            ProcPidEntry* E = &__ProcPidCache__[pid];
            ProcFsNode*   D = E->DirNode;
            ReleaseSpinLock(&ProcPriv->Lock);

            if (!D || !D->Priv)
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
            StringCopy(Ent->Name, Num, 256);
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
                StringCopy(Ent->Name, Num, 256);
                Ent->Type = VNodeDIR;
                Ent->Ino  = Pn->Ino + 100 + (long)Pr->Pid;
                __AdvanceCursor__(Cur);
                return sizeof(VfsDirEnt);
            }
        }
        __ResetCursor__(Cur);
        return 0;
    }
    else
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (!Pr)
        {
            __ResetCursor__(Cur);
            return 0;
        }

        long LocalIdx = Idx - 2;

        if (LocalIdx == 0)
        {
            StringCopy(Ent->Name, "stat", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 1;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 1)
        {
            StringCopy(Ent->Name, "status", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 2;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 2)
        {
            StringCopy(Ent->Name, "fds", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 3;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 3)
        {
            StringCopy(Ent->Name, "state", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 4;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 4)
        {
            StringCopy(Ent->Name, "exec", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 5;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 5)
        {
            StringCopy(Ent->Name, "signal", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 6;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 6)
        {
            StringCopy(Ent->Name, "cwd", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 7;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 7)
        {
            StringCopy(Ent->Name, "root", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 8;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 8)
        {
            StringCopy(Ent->Name, "cmdline", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 9;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }
        if (LocalIdx == 9)
        {
            StringCopy(Ent->Name, "environ", 256);
            Ent->Type = VNodeFILE;
            Ent->Ino  = Pn->Ino + 10;
            __AdvanceCursor__(Cur);
            return sizeof(VfsDirEnt);
        }

        __ResetCursor__(Cur);
        return 0;
    }
}

Vnode*
ProcLookup(Vnode* __Dir__, const char* __Name__)
{
    if (!__Dir__ || !__Name__)
    {
        return NULL;
    }
    ProcFsNode* Pn = (ProcFsNode*)__Dir__->Priv;
    if (!Pn || Pn->Kind != ProcFsNodeDir)
    {
        return NULL;
    }

    if (strcmp(Pn->Name, "") == 0)
    {
        if (strcmp(__Name__, "uptime") == 0)
        {
            ProcFsNode* F = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
            if (!F)
            {
                return NULL;
            }
            memset(F, 0, sizeof(*F));
            F->Kind      = ProcFsNodeFile;
            F->Name      = "uptime";
            F->Ino       = Pn->Ino + 1;
            F->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH;

            Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
            if (!N)
            {
                return NULL;
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
            if (!F)
            {
                return NULL;
            }
            memset(F, 0, sizeof(*F));
            F->Kind      = ProcFsNodeFile;
            F->Name      = "self";
            F->Ino       = Pn->Ino + 2;
            F->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH;

            Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
            if (!N)
            {
                return NULL;
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
            AcquireSpinLock(&ProcPriv->Lock);
            ProcPidEntry* E = &__ProcPidCache__[pid];
            ProcFsNode*   D = E->DirNode;
            ReleaseSpinLock(&ProcPriv->Lock);

            if (D && D->Priv)
            {
                Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
                if (!N)
                {
                    return NULL;
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
            if (!Pr)
            {
                continue;
            }
            char Num[32];
            UnsignedToStringEx((uint64_t)Pr->Pid, Num, 10, 0);
            if (strcmp(__Name__, Num) == 0)
            {
                ProcFsNode* D = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
                if (!D)
                {
                    return NULL;
                }
                memset(D, 0, sizeof(*D));
                D->Kind = ProcFsNodeDir;
                D->Name = (char*)KMalloc(32);
                if (!D->Name)
                {
                    KFree(D);
                    return NULL;
                }
                StringCopy(D->Name, Num, 32);
                D->Ino = Pn->Ino + 100 + (long)Pr->Pid;
                D->Perm.Mode =
                    VModeRUSR | VModeRGRP | VModeROTH | VModeXUSR | VModeXGRP | VModeXOTH;
                D->Priv = (void*)Pr;

                Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
                if (!N)
                {
                    KFree(D->Name);
                    KFree(D);
                    return NULL;
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
        return NULL;
    }
    else
    {
        PosixProc* Pr = (PosixProc*)Pn->Priv;
        if (!Pr)
        {
            return NULL;
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
                if (!F)
                {
                    return NULL;
                }
                memset(F, 0, sizeof(*F));
                F->Kind = ProcFsNodeFile;
                F->Name = (char*)KMalloc((uint32_t)(strlen(Fn[KIdx]) + 1));
                if (F->Name)
                {
                    StringCopy(F->Name, Fn[KIdx], (uint32_t)(strlen(Fn[KIdx]) + 1));
                }
                F->Ino       = Pn->Ino + KIdx + 1;
                F->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH;
                if (KIdx >= 3 && KIdx <= 5)
                {
                    F->Perm.Mode = VModeRUSR | VModeWUSR;
                }
                F->Priv = (void*)Pr;

                Vnode* N = (Vnode*)KMalloc(sizeof(Vnode));
                if (!N)
                {
                    if (F->Name)
                    {
                        KFree(F->Name);
                    }
                    KFree(F);
                    return NULL;
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
        return NULL;
    }
}

int
ProcCreate(Vnode* __Dir__, const char* __Name__, long __Flags__, VfsPerm __Perm__)
{
    return -1;
}

int
ProcUnlink(Vnode* __Dir__, const char* __Name__)
{
    return -1;
}

int
ProcMkdir(Vnode* __Dir__, const char* __Name__, VfsPerm __Perm__)
{
    return -1;
}

int
ProcRmdir(Vnode* __Dir__, const char* __Name__)
{
    return -1;
}

int
ProcSymlink(Vnode* __Dir__, const char* __Name__, const char* __Target__, VfsPerm __Perm__)
{
    return -1;
}

int
ProcReadlink(Vnode* __Node__, VfsNameBuf* __Buf__)
{
    return -1;
}

int
ProcLink(Vnode* __Dir__, Vnode* __Node__, const char* __Name__)
{
    return -1;
}

int
ProcRename(Vnode*      __FromDir__,
           const char* __FromName__,
           Vnode*      __ToDir__,
           const char* __ToName__,
           long        __Flags__)
{
    return -1;
}

int
ProcChmod(Vnode* __Node__, long __Mode__)
{
    return -1;
}

int
ProcChown(Vnode* __Node__, long __Uid__, long __Gid__)
{
    return -1;
}

int
ProcTruncate(Vnode* __Node__, long __Len__)
{
    return -1;
}

int
ProcSync(Vnode* __Node__)
{
    return 0;
}

int
ProcMap(Vnode* __Node__, void** __Out__, long __Len__, long __Flags__)
{
    return -1;
}

int
ProcUnmap(Vnode* __Node__, void* __Addr__, long __Len__)
{
    return -1;
}

int
ProcSuperSync(Superblock* __Sb__)
{
    return 0;
}

int
ProcSuperStatFs(Superblock* __Sb__, VfsStatFs* __Out__)
{
    if (!__Sb__ || !__Out__)
    {
        return -1;
    }
    __Out__->TypeId  = 0xDEAD7001; /*Ah*/
    __Out__->Bsize   = 1;
    __Out__->Blocks  = 0;
    __Out__->Bfree   = 0;
    __Out__->Bavail  = 0;
    __Out__->Files   = 0;
    __Out__->Ffree   = 0;
    __Out__->Namelen = 255;
    __Out__->Flags   = 0;
    return 0;
}

void
ProcSuperRelease(Superblock* __Sb__)
{
}

int
ProcSuperUmount(Superblock* __Sb__)
{
    return 0;
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
    if (!ProcPriv)
    {
        return -1;
    }
    memset(ProcPriv, 0, sizeof(*ProcPriv));
    InitializeSpinLock(&ProcPriv->Lock, "procfs");

    memset(__ProcPidCache__, 0, sizeof(__ProcPidCache__));

    Superblock* Sb = ProcFsMountImpl(NULL, NULL);
    if (!Sb)
    {
        return -1;
    }
    if (ProcFsRegisterMount("/proc", Sb) != 0)
    {
        return -1;
    }
    return 0;
}

Superblock*
ProcFsMountImpl(const char* __Dev__, const char* __Opts__)
{
    ProcSuper = (Superblock*)KMalloc(sizeof(Superblock));
    if (!ProcSuper)
    {
        return NULL;
    }
    memset(ProcSuper, 0, sizeof(*ProcSuper));
    ProcSuper->Type  = NULL;
    ProcSuper->Dev   = NULL;
    ProcSuper->Flags = 0;
    ProcSuper->Ops   = &__ProcFsSuperOps__;

    ProcFsNode* Root = (ProcFsNode*)KMalloc(sizeof(ProcFsNode));
    if (!Root)
    {
        return NULL;
    }
    memset(Root, 0, sizeof(*Root));
    Root->Kind      = ProcFsNodeDir;
    Root->Name      = "";
    Root->Ino       = 1;
    Root->Perm.Mode = VModeRUSR | VModeRGRP | VModeROTH | VModeXUSR | VModeXGRP | VModeXOTH;

    Vnode* RootV = (Vnode*)KMalloc(sizeof(Vnode));
    if (!RootV)
    {
        return NULL;
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