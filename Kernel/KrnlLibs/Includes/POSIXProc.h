#pragma once
#include <AllTypes.h>
#include <AxeThreads.h>
#include <Sync.h>
#include <VFS.h>
#include <VMM.h>

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
    long                 Pid;
    long                 Ppid;
    long                 Pgrp;
    long                 Sid;
    long                 TtyFd;
    const char*          TtyName;
    VirtualMemorySpace*  Space;
    Thread*              MainThread;
    PosixCred            Cred;
    char                 Cwd[256];
    char                 Root[256];
    volatile int         ExitCode;
    volatile int         Zombie;
    uint64_t             SigPending;
    uint64_t             SigMask;
    SpinLock             Lock;
    PosixTimes           Times;
    char                 Comm[64];
    char*                CmdlineBuf;
    long                 CmdlineLen;
    char*                EnvironBuf;
    long                 EnvironLen;
    struct PosixFdTable* Fds;

} PosixProc;

typedef struct PosixProcTable
{
    PosixProc** Items;
    long        Count;
    long        Cap;
    SpinLock    Lock;
} PosixProcTable;

#ifndef WNOHANG
#    define WNOHANG 1
#endif

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
/*Global Helpers*/
char __ProcStateCode__(PosixProc* __Proc__);

KEXPORT(PosixProcCreate)
KEXPORT(PosixProcExecve)
KEXPORT(PosixFork)
KEXPORT(PosixExit)
KEXPORT(PosixWait4)
KEXPORT(PosixSetSid)
KEXPORT(PosixSetPgrp)
KEXPORT(PosixGetPid)
KEXPORT(PosixGetPpid)
KEXPORT(PosixGetPgrp)
KEXPORT(PosixGetSid)
KEXPORT(PosixChdir)
KEXPORT(PosixFchdir)
KEXPORT(PosixSetUmask)
KEXPORT(PosixGetTty)
KEXPORT(PosixFind)