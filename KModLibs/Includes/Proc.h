#pragma once

#include <Memory.h>
#include <SyncSys.h>
#include <ThrdSys.h>
#include <Vfs.h>

typedef struct PosixFd
{
    long  Fd;
    long  Flags;
    void* Obj;
    long  Refcnt;
    int   IsFile;
    int   IsChar;
    int   IsBlock;
} PosixFd;

typedef struct PosixFdTable
{
    PosixFd* Entries;
    long     Count;
    long     Cap;
    long     StdinFd;
    long     StdoutFd;
    long     StderrFd;
    SpinLock Lock;
} PosixFdTable;

int  PosixFdInit(PosixFdTable* __Tab__, long __Cap__);
int  PosixOpen(PosixFdTable* __Tab__, const char* __Path__, long __Flags__, long __Mode__);
int  PosixClose(PosixFdTable* __Tab__, int __Fd__);
long PosixRead(PosixFdTable* __Tab__, int __Fd__, void* __Buf__, long __Len__);
long PosixWrite(PosixFdTable* __Tab__, int __Fd__, const void* __Buf__, long __Len__);
long PosixLseek(PosixFdTable* __Tab__, int __Fd__, long __Off__, int __Wh__);
int  PosixDup(PosixFdTable* __Tab__, int __Fd__);
int  PosixDup2(PosixFdTable* __Tab__, int __OldFd__, int __NewFd__);
int  PosixPipe(PosixFdTable* __Tab__, int __Pipefd__[2]);
int  PosixFcntl(PosixFdTable* __Tab__, int __Fd__, int __Cmd__, long __Arg__);
int  PosixIoctl(PosixFdTable* __Tab__, int __Fd__, unsigned long __Cmd__, void* __Arg__);
int  PosixAccess(PosixFdTable* __Tab__, const char* __Path__, long __Mode__);
int  PosixStatPath(const char* __Path__, VfsStat* __Out__);
int  PosixFstat(PosixFdTable* __Tab__, int __Fd__, VfsStat* __Out__);
int  PosixMkdir(const char* __Path__, long __Mode__);
int  PosixRmdir(const char* __Path__);
int  PosixUnlink(const char* __Path__);
int  PosixRename(const char* __Old__, const char* __New__);

typedef struct PosixTimes
{
    uint64_t UserUsec;
    uint64_t SysUsec;
    uint64_t StartTick;
} PosixTimes;

typedef struct PosixRusage
{
    uint64_t UtimeUsec;
    uint64_t StimeUsec;
    uint64_t MaxRss;
    uint64_t MinorFaults;
    uint64_t MajorFaults;
    uint64_t VoluntaryCtxt;
    uint64_t InvoluntaryCtxt;
} PosixRusage;

typedef struct PosixCred
{
    long Ruid;
    long Euid;
    long Suid;
    long Rgid;
    long Egid;
    long Sgid;
    long Umask;
} PosixCred;

typedef struct PosixProc
{
    long                Pid;
    long                Ppid;
    long                Pgrp;
    long                Sid;
    long                TtyFd;
    const char*         TtyName;
    VirtualMemorySpace* Space;
    Thread*             MainThread;
    PosixCred           Cred;
    char                Cwd[256];
    char                Root[256];
    volatile int        ExitCode;
    volatile int        Zombie;
    uint64_t            SigPending;
    uint64_t            SigMask;
    SpinLock            Lock;
    PosixTimes          Times;
} PosixProc;

typedef struct PosixProcTable
{
    PosixProc** Items;
    long        Count;
    long        Cap;
    SpinLock    Lock;
} PosixProcTable;

extern PosixProcTable PosixProcs;

PosixProc* PosixProcCreate(void);
int        PosixProcExecve(PosixProc*         __Proc__,
                           const char*        __Path__,
                           const char* const* __Argv__,
                           const char* const* __Envp__);
long       PosixFork(PosixProc* __Parent__, PosixProc** __OutChild__);
int        PosixExit(PosixProc* __Proc__, int __Status__);
long       PosixWait4(PosixProc*   __Parent__,
                      long         __Pid__,
                      int*         __OutStatus__,
                      int          __Options__,
                      PosixRusage* __OutUsage__);
int        PosixSetSid(PosixProc* __Proc__);
int        PosixSetPgrp(PosixProc* __Proc__, long __Pgid__);
int        PosixGetPid(PosixProc* __Proc__);
int        PosixGetPpid(PosixProc* __Proc__);
int        PosixGetPgrp(PosixProc* __Proc__);
int        PosixGetSid(PosixProc* __Proc__);
int        PosixChdir(PosixProc* __Proc__, const char* __Path__);
int        PosixFchdir(PosixProc* __Proc__, int __Fd__);
int        PosixSetUmask(PosixProc* __Proc__, long __Mask__);
int        PosixGetTty(PosixProc* __Proc__, char* __Out__, long __Len__);
PosixProc* PosixFind(long __Pid__);

typedef void (*PosixSigHandler)(int);

typedef struct PosixSigAction
{
    PosixSigHandler Handler;
    uint64_t        Mask;
    int             Flags;
} PosixSigAction;

typedef enum PosixSig
{
    SigHup  = 1,
    SigInt  = 2,
    SigQuit = 3,
    SigIll  = 4,
    SigAbrt = 6,
    SigFpe  = 8,
    SigKill = 9,
    SigSegv = 11,
    SigPipe = 13,
    SigAlrm = 14,
    SigTerm = 15,
    SigStop = 19,
    SigTstp = 20,
    SigCont = 18,
    SigChld = 17
} PosixSig;

int PosixKill(long __Pid__, int __Sig__);
int PosixTkill(long __Tid__, int __Sig__);
int PosixSigaction(int __Sig__, const PosixSigAction* __Act__, PosixSigAction* __OldAct__);
int PosixSigprocmask(int __How__, const uint64_t* __Set__, uint64_t* __OldSet__);
int PosixSigpending(uint64_t* __OutMask__);
int PosixSigsuspend(const uint64_t* __Mask__);
int PosixSigqueue(long __Pid__, int __Sig__, int __Value__);
int PosixDeliverSignals(void);
