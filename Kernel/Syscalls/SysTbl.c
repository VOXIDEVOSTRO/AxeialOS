#include <APICTimer.h>
#include <AllTypes.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <BootConsole.h>
#include <BootImg.h>
#include <DevFS.h>
#include <EarlyBootFB.h>
#include <GDT.h>
#include <IDT.h>
#include <KExports.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <LimineServices.h>
#include <ModELF.h>
#include <ModMemMgr.h>
#include <PMM.h>
#include <POSIXFd.h>
#include <POSIXProc.h>
#include <POSIXProcFS.h>
#include <POSIXSignals.h>
#include <SMP.h>
#include <Serial.h>
#include <SymAP.h>
#include <Sync.h>
#include <Syscall.h>
#include <Timer.h>
#include <VFS.h>
#include <VMM.h>

#define __attribute_unused__ __attribute__((unused))

static inline PosixProc*
__GetCurrentProc__(void)
{
    uint32_t CpuId = GetCurrentCpuId();
    Thread*  Thrd  = GetCurrentThread(CpuId);
    return Thrd ? PosixFind((long)Thrd->ProcessId) : NULL;
}

int64_t
__Handle__Read(uint64_t __Fd__,
               uint64_t __Buf__,
               uint64_t __Len__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixRead(Proc->Fds, (int)__Fd__, (void*)__Buf__, (long)__Len__);
}

int64_t
__Handle__Write(uint64_t __Fd__,
                uint64_t __Buf__,
                uint64_t __Len__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixWrite(Proc->Fds, (int)__Fd__, (const void*)__Buf__, (long)__Len__);
}

int64_t
__Handle__Writev(uint64_t __Fd__,
                 uint64_t __IovPtr__,
                 uint64_t __IovCnt__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds || !__IovPtr__ || __IovCnt__ <= 0)
    {
        return -BadSystemcall;
    }

    Iovec* Iov   = (Iovec*)__IovPtr__;
    long   Total = 0;

    for (long I = 0; I < (long)__IovCnt__; I++)
    {
        const void* Buf = Iov[I].IovBase;
        long        Len = (long)Iov[I].IovLen;
        if (Probe_IF_Error(Buf) || !Buf || Len <= 0)
        {
            continue;
        }

        long W = PosixWrite(Proc->Fds, (int)__Fd__, Buf, Len);
        if (W < 0)
        {
            return (Total > 0) ? Total : -BadSystemcall;
        }
        Total += W;
        if (W < Len)
        {
            break; /* short write: stop */
        }
    }
    return Total;
}

int64_t
__Handle__Readv(uint64_t __Fd__,
                uint64_t __IovPtr__,
                uint64_t __IovCnt__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds || !__IovPtr__ || __IovCnt__ <= 0)
    {
        return -BadSystemcall;
    }

    Iovec* Iov   = (Iovec*)__IovPtr__;
    long   Total = 0;

    for (long I = 0; I < (long)__IovCnt__; I++)
    {
        void* Buf = Iov[I].IovBase;
        long  Len = (long)Iov[I].IovLen;
        if (Probe_IF_Error(Buf) || !Buf || Len <= 0)
        {
            continue;
        }

        long R = PosixRead(Proc->Fds, (int)__Fd__, Buf, Len);
        if (R < 0)
        {
            return (Total > 0) ? Total : -BadSystemcall;
        }
        Total += R;
        if (R < Len)
        {
            break; /* short read: stop */
        }
    }
    return Total;
}

int64_t
__Handle__Open(uint64_t __Path__,
               uint64_t __Flags__,
               uint64_t __Mode__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixOpen(Proc->Fds, (const char*)__Path__, (long)__Flags__, (long)__Mode__);
}

int64_t
__Handle__Close(uint64_t __Fd__,
                uint64_t __U2__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixClose(Proc->Fds, (int)__Fd__);
}

int64_t
__Handle__Stat(uint64_t __Path__,
               uint64_t __OutStat__,
               uint64_t __U3__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    return PosixStatPath((const char*)__Path__, (VfsStat*)__OutStat__);
}

int64_t
__Handle__Fstat(uint64_t __Fd__,
                uint64_t __OutStat__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixFstat(Proc->Fds, (int)__Fd__, (VfsStat*)__OutStat__);
}

int64_t
__Handle__Lseek(uint64_t __Fd__,
                uint64_t __Off__,
                uint64_t __Whence__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixLseek(Proc->Fds, (int)__Fd__, (long)__Off__, (int)__Whence__);
}

int64_t
__Handle__Ioctl(uint64_t __Fd__,
                uint64_t __Cmd__,
                uint64_t __Arg__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixIoctl(Proc->Fds, (int)__Fd__, (unsigned long)__Cmd__, (void*)__Arg__);
}

int64_t
__Handle__Access(uint64_t __Path__,
                 uint64_t __Mode__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    PosixFdTable* Tab  = NULL;
    PosixProc*    Proc = __GetCurrentProc__();
    if (Proc)
    {
        Tab = Proc->Fds;
    }
    __attribute_unused__ PosixFdTable* ignore = Tab;
    return PosixAccess(NULL, (const char*)__Path__, (long)__Mode__);
}

int64_t
__Handle__Pipe(uint64_t __PipefdPtr__,
               uint64_t __U2__,
               uint64_t __U3__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds || !__PipefdPtr__)
    {
        return -BadSystemcall;
    }
    int fds[2] = {-BadSystemcall, -BadSystemcall};
    int r      = PosixPipe(Proc->Fds, fds);
    if (r == 0)
    {
        ((int*)__PipefdPtr__)[0] = fds[0];
        ((int*)__PipefdPtr__)[1] = fds[1];
    }
    return r;
}

int64_t
__Handle__Dup(uint64_t __Fd__,
              uint64_t __U2__,
              uint64_t __U3__,
              uint64_t __U4__,
              uint64_t __U5__,
              uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixDup(Proc->Fds, (int)__Fd__);
}

int64_t
__Handle__Dup2(uint64_t __OldFd__,
               uint64_t __NewFd__,
               uint64_t __U3__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }
    return PosixDup2(Proc->Fds, (int)__OldFd__, (int)__NewFd__);
}

int64_t
__Handle__Mkdir(uint64_t __Path__,
                uint64_t __Mode__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    return PosixMkdir((const char*)__Path__, (long)__Mode__);
}

int64_t
__Handle__Rmdir(uint64_t __Path__,
                uint64_t __U2__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    return PosixRmdir((const char*)__Path__);
}

int64_t
__Handle__Unlink(uint64_t __Path__,
                 uint64_t __U2__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    return PosixUnlink((const char*)__Path__);
}

int64_t
__Handle__Rename(uint64_t __Old__,
                 uint64_t __New__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    return PosixRename((const char*)__Old__, (const char*)__New__);
}

int64_t
__Handle__SchedYield(uint64_t __U1__,
                     uint64_t __U2__,
                     uint64_t __U3__,
                     uint64_t __U4__,
                     uint64_t __U5__,
                     uint64_t __U6__)
{
    SysErr  err;
    SysErr* Error = &err;
    ThreadYield(Error);
    return SysOkay;
}

int64_t
__Handle__Nanosleep(uint64_t __ReqPtr__,
                    uint64_t __RemPtr__,
                    uint64_t __U3__,
                    uint64_t __U4__,
                    uint64_t __U5__,
                    uint64_t __U6__)
{
    __attribute_unused__ uint64_t __unused_rem__ = __RemPtr__;
    if (Probe_IF_Error(__ReqPtr__) || !__ReqPtr__)
    {
        return -BadSystemcall;
    }
    struct
    {
        long Sec;
        long Nsec;
    }*       ts = (void*)__ReqPtr__;
    uint64_t ms = (ts->Sec * 1000ULL) + (ts->Nsec / 1000000ULL);
    SysErr   err;
    SysErr*  Error = &err;
    Sleep((uint32_t)ms, Error);
    return SysOkay;
}

int64_t
__Handle__Getpid(uint64_t __U1__,
                 uint64_t __U2__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    return Proc ? (int64_t)Proc->Pid : -BadSystemcall;
}

int64_t
__Handle__Getppid(uint64_t __U1__,
                  uint64_t __U2__,
                  uint64_t __U3__,
                  uint64_t __U4__,
                  uint64_t __U5__,
                  uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    return Proc ? (int64_t)Proc->Ppid : -BadSystemcall;
}

int64_t
__Handle__Gettid(uint64_t __U1__,
                 uint64_t __U2__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    uint32_t CpuId = GetCurrentCpuId();
    Thread*  Thrd  = GetCurrentThread(CpuId);
    return Thrd ? (int64_t)Thrd->ThreadId : -BadSystemcall;
}

int64_t
__Handle__Fork(uint64_t __U1__,
               uint64_t __U2__,
               uint64_t __U3__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    PosixProc* Parent = __GetCurrentProc__();
    if (Probe_IF_Error(Parent) || !Parent)
    {
        return -BadSystemcall;
    }
    PosixProc* Child = NULL;
    long       pid   = PosixFork(Parent, &Child);
    return pid; /* parent gets child pid, child path returns 0 in its thread context */
}

int64_t
__Handle__Execve(uint64_t __Path__,
                 uint64_t __Argv__,
                 uint64_t __Envp__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        return -BadSystemcall;
    }
    return PosixProcExecve(
        Proc, (const char*)__Path__, (const char* const*)__Argv__, (const char* const*)__Envp__);
}

int64_t
__Handle__Exit(uint64_t __Status__,
               uint64_t __U2__,
               uint64_t __U3__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        return -BadSystemcall;
    }
    PosixExit(Proc, (int)__Status__);
    return SysOkay;
}

int64_t
__Handle__Wait4(uint64_t __Pid__,
                uint64_t __StatusPtr__,
                uint64_t __Options__,
                uint64_t __RusagePtr__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Parent = __GetCurrentProc__();
    if (Probe_IF_Error(Parent) || !Parent)
    {
        return -BadSystemcall;
    }
    int         status = 0;
    PosixRusage ru     = {0};
    long        pid    = PosixWait4(Parent,
                          (long)__Pid__,
                          __StatusPtr__ ? &status : NULL,
                          (int)__Options__,
                          __RusagePtr__ ? &ru : NULL);
    if (pid > 0)
    {
        if (__StatusPtr__)
        {
            *(int*)__StatusPtr__ = status;
        }
        if (__RusagePtr__)
        {
            *(PosixRusage*)__RusagePtr__ = ru;
        }
    }
    return pid;
}

int64_t
__Handle__Kill(uint64_t __Pid__,
               uint64_t __Sig__,
               uint64_t __U3__,
               uint64_t __U4__,
               uint64_t __U5__,
               uint64_t __U6__)
{
    return PosixKill((long)__Pid__, (int)__Sig__);
}

int64_t
__Handle__Getcwd(uint64_t __Buf__,
                 uint64_t __Len__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !__Buf__ || __Len__ == 0)
    {
        return -BadSystemcall;
    }
    strcpy((char*)__Buf__, Proc->Cwd, (uint32_t)__Len__);
    return (int64_t)StringLength((const char*)__Buf__);
}

int64_t
__Handle__Chdir(uint64_t __Path__,
                uint64_t __U2__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        return -BadSystemcall;
    }
    return PosixChdir(Proc, (const char*)__Path__);
}

int64_t
__Handle__Uname(uint64_t __Buf__,
                uint64_t __U2__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    if (Probe_IF_Error(__Buf__) || !__Buf__)
    {
        return -BadSystemcall;
    }
    /* sysname,nodename,release,version,machine */
    struct Uts
    {
        char Sys[65], Node[65], Rel[65], Ver[65], Mach[65];
    };
    struct Uts* u = (struct Uts*)__Buf__;
    strcpy(u->Sys, "AxeialOS", 64);
    strcpy(u->Node, "Oil Up", 64);
    strcpy(u->Rel, "0.0000000000000001", 64);
    strcpy(u->Ver, "Idk", 64);
    strcpy(u->Mach, "x86_64/AMD64", 64);
    return SysOkay;
}

int64_t
__Handle__Gettimeofday(uint64_t __Tv__,
                       uint64_t __Tz__,
                       uint64_t __U3__,
                       uint64_t __U4__,
                       uint64_t __U5__,
                       uint64_t __U6__)
{
    __attribute_unused__ uint64_t __unused_tz__ = __Tz__;
    if (Probe_IF_Error(__Tv__) || !__Tv__)
    {
        return -BadSystemcall;
    }
    struct
    {
        long Sec;
        long Usec;
    }*       tv    = (void*)__Tv__;
    uint64_t ticks = GetSystemTicks();
    tv->Sec        = (long)(ticks / 1000ULL);
    tv->Usec       = (long)((ticks % 1000ULL) * 1000ULL);
    return SysOkay;
}

int64_t
__Handle__Times(uint64_t __TmsPtr__,
                uint64_t __U2__,
                uint64_t __U3__,
                uint64_t __U4__,
                uint64_t __U5__,
                uint64_t __U6__)
{
    if (Probe_IF_Error(__TmsPtr__) || !__TmsPtr__)
    {
        return -BadSystemcall;
    }
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc)
    {
        return -BadSystemcall;
    }
    struct
    {
        long Utime;
        long Stime;
        long Cutime;
        long Cstime;
    }* tms      = (void*)__TmsPtr__;
    tms->Utime  = (long)(Proc->Times.UserUsec / 10000ULL); /* arbitrary 1/100 sec units */
    tms->Stime  = (long)(Proc->Times.SysUsec / 10000ULL);
    tms->Cutime = 0;
    tms->Cstime = 0;
    return SysOkay;
}

int64_t
__Handle__ClockGettime(uint64_t __ClkId__,
                       uint64_t __Tp__,
                       uint64_t __U3__,
                       uint64_t __U4__,
                       uint64_t __U5__,
                       uint64_t __U6__)
{
    if (Probe_IF_Error(__Tp__) || !__Tp__)
    {
        return -BadSystemcall;
    }
    struct
    {
        long Sec;
        long Nsec;
    }*       tp    = (void*)__Tp__;
    uint64_t ticks = GetSystemTicks();
    tp->Sec        = (long)(ticks / 1000ULL);
    tp->Nsec       = (long)((ticks % 1000ULL) * 1000000ULL);
    return SysOkay;
}

static inline uint64_t
__AlignUp__(uint64_t __V__, uint64_t __A__)
{
    return (__V__ + (__A__ - 1)) & ~(__A__ - 1);
}

static inline uint64_t
__AlignDown__(uint64_t __V__, uint64_t __A__)
{
    return __V__ & ~(__A__ - 1);
}

typedef struct ProcBrkRec
{
    long     Pid;
    uint64_t BrkCur;
    uint64_t BrkBase;

} ProcBrkRec;

#define __BrkMaxRecs__ 32768
static ProcBrkRec __BrkTbl__[__BrkMaxRecs__];

static ProcBrkRec*
__BrkLookup__(long __Pid__)
{
    if (__Pid__ <= 0)
    {
        return NULL;
    }
    long        IdenX = __Pid__ % __BrkMaxRecs__;
    ProcBrkRec* Enter = &__BrkTbl__[IdenX];
    if (Enter->Pid != __Pid__)
    {
        Enter->Pid     = __Pid__;
        Enter->BrkCur  = 0;
        Enter->BrkBase = 0;
    }
    return Enter;
}

int64_t
__Handle__Mmap(uint64_t __Addr__,
               uint64_t __Len__,
               uint64_t __Prot__,
               uint64_t __Flags__,
               uint64_t __Fd__,
               uint64_t __Off__)
{
    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Space || __Len__ == 0)
    {
        return -BadSystemcall;
    }

    uint64_t VaBase = (__Addr__ == 0) ? __AlignUp__(UserVirtualBase + 0x01000000ULL, PageSize)
                                      : __AlignDown__(__Addr__, PageSize);
    uint64_t MapLen = __AlignUp__(__Len__, PageSize);

    /* default NX; clear NX if PROT_EXEC (0x4) present */
    uint64_t PteFlags = PTEPRESENT | PTEUSER | PTEWRITABLE;
    if (__Prot__ & 0x4)
    {
        PteFlags &= ~PTENOEXECUTE;
    }
    else
    {
        PteFlags |= PTENOEXECUTE;
    }

    (void)__Fd__;
    (void)__Off__;
    int RIdx = MapRangeZeroed(Proc->Space, VaBase, MapLen, PteFlags);
    if (RIdx != 0)
    {
        PError("mmap: MapRangeZeroed failed base=0x%llx len=0x%llx\n",
               (unsigned long long)VaBase,
               (unsigned long long)MapLen);
        return -BadSystemcall;
    }

    return (int64_t)VaBase;
}

int64_t
__Handle__Munmap(uint64_t __Addr__,
                 uint64_t __Len__,
                 uint64_t __U3__,
                 uint64_t __U4__,
                 uint64_t __U5__,
                 uint64_t __U6__)
{
    (void)__U3__;
    (void)__U4__;
    (void)__U5__;
    (void)__U6__;

    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Space || __Addr__ == 0 || __Len__ == 0)
    {
        return -BadSystemcall;
    }

    uint64_t Va  = __AlignDown__(__Addr__, PageSize);
    uint64_t End = __AlignUp__(__Addr__ + __Len__, PageSize);

    for (; Va < End; Va += PageSize)
    {
        (void)UnmapPage(Proc->Space, Va);
    }
    SysErr  err;
    SysErr* Error = &err;
    FlushAllTlb(Error);
    return SysOkay;
}

int64_t
__Handle__Brk(uint64_t __NewBrk__,
              uint64_t __U2__,
              uint64_t __U3__,
              uint64_t __U4__,
              uint64_t __U5__,
              uint64_t __U6__)
{
    (void)__U2__;
    (void)__U3__;
    (void)__U4__;
    (void)__U5__;
    (void)__U6__;

    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Space)
    {
        return -BadSystemcall;
    }

    ProcBrkRec* Br = __BrkLookup__(Proc->Pid);
    if (Probe_IF_Error(Br) || !Br)
    {
        return -BadSystemcall;
    }

    if (Br->BrkBase == 0)
    {
        Br->BrkBase = __AlignUp__(UserVirtualBase + 0x04000000ULL, PageSize); /* +64MB */
        Br->BrkCur  = Br->BrkBase;
    }

    if (__NewBrk__ == 0)
    {
        return (int64_t)Br->BrkCur;
    }

    uint64_t Want = __AlignUp__(__NewBrk__, PageSize);
    if (Want == Br->BrkCur)
    {
        return (int64_t)Br->BrkCur;
    }
    else if (Want > Br->BrkCur)
    {
        uint64_t GrowLen  = Want - Br->BrkCur;
        uint64_t PteFlags = PTEPRESENT | PTEUSER | PTEWRITABLE | PTENOEXECUTE;
        int      RIdx     = MapRangeZeroed(Proc->Space, Br->BrkCur, GrowLen, PteFlags);
        if (RIdx != 0)
        {
            return -BadSystemcall;
        }
        Br->BrkCur = Want;
        return (int64_t)Br->BrkCur;
    }
    else
    {
        uint64_t Va = Want;
        for (; Va < Br->BrkCur; Va += PageSize)
        {
            (void)UnmapPage(Proc->Space, Va);
        }
        SysErr  err;
        SysErr* Error = &err;
        FlushAllTlb(Error);
        Br->BrkCur = Want;
        return (int64_t)Br->BrkCur;
    }
}

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
__FdIsReadable__(PosixFdTable* __Tab__, int __Fd__)
{
    if (Probe_IF_Error(__Tab__) || !__Tab__)
    {
        return SysOkay;
    }
    if (__Fd__ < 0 || (long)__Fd__ >= __Tab__->Cap)
    {
        return SysOkay;
    }
    PosixFd* E = &__Tab__->Entries[__Fd__];
    if (E->Fd < 0)
    {
        return SysOkay;
    }
    if (E->IsFile)
    {
        return 1;
    }
    if (E->IsChar && E->Obj)
    {
        PosixPipeT* P = (PosixPipeT*)E->Obj;
        SysErr      err;
        SysErr*     Error = &err;
        AcquireSpinLock(&P->Lock, Error);
        int Ok = (P->Len > 0);
        ReleaseSpinLock(&P->Lock, Error);
        return Ok;
    }
    return SysOkay;
}

static int
__FdIsWritable__(PosixFdTable* __Tab__, int __Fd__)
{
    if (Probe_IF_Error(__Tab__) || !__Tab__)
    {
        return SysOkay;
    }
    if (__Fd__ < 0 || (long)__Fd__ >= __Tab__->Cap)
    {
        return SysOkay;
    }
    PosixFd* E = &__Tab__->Entries[__Fd__];
    if (E->Fd < 0)
    {
        return SysOkay;
    }
    if (E->IsFile)
    {
        return 1;
    }
    if (E->IsChar && E->Obj)
    {
        PosixPipeT* P = (PosixPipeT*)E->Obj;
        SysErr      err;
        SysErr*     Error = &err;
        AcquireSpinLock(&P->Lock, Error);
        int Ok = (P->Len < P->Cap);
        ReleaseSpinLock(&P->Lock, Error);
        return Ok;
    }
    return SysOkay;
}

static int
__FdsetTest__(const void* __Set__, int __Fd__)
{
    if (Probe_IF_Error(__Set__) || !__Set__ || __Fd__ < 0)
    {
        return SysOkay;
    }
    const unsigned char* S = (const unsigned char*)__Set__;
    return (S[__Fd__ / 8] & (1u << (__Fd__ % 8))) ? 1 : 0;
}

static void
__FdsetClear__(void* __Set__, int __Fd__)
{
    if (Probe_IF_Error(__Set__) || !__Set__ || __Fd__ < 0)
    {
        return;
    }
    unsigned char* S = (unsigned char*)__Set__;
    S[__Fd__ / 8] &= ~(1u << (__Fd__ % 8));
}

static void
__FdsetSet__(void* __Set__, int __Fd__)
{
    if (Probe_IF_Error(__Set__) || !__Set__ || __Fd__ < 0)
    {
        return;
    }
    unsigned char* S = (unsigned char*)__Set__;
    S[__Fd__ / 8] |= (1u << (__Fd__ % 8));
}

int64_t
__Handle__Select(uint64_t __Nfds__,
                 uint64_t __Readfds__,
                 uint64_t __Writefds__,
                 uint64_t __Exceptfds__,
                 uint64_t __Timeout__,
                 uint64_t __U6__)
{
    (void)__U6__;

    PosixProc* Proc = __GetCurrentProc__();
    if (Probe_IF_Error(Proc) || !Proc || !Proc->Fds)
    {
        return -BadSystemcall;
    }

    unsigned char* Rfds = (unsigned char*)__Readfds__;
    unsigned char* Wfds = (unsigned char*)__Writefds__;
    unsigned char* Efds = (unsigned char*)__Exceptfds__;

    if (Efds)
    {
        long Bytes = (long)((__Nfds__ + 7) / 8);
        for (long I = 0; I < Bytes; I++)
        {
            Efds[I] = 0;
        }
    }

    long Ready = 0;

    for (int fd = 0; fd < (int)__Nfds__; fd++)
    {
        int WantR = Rfds && __FdsetTest__(Rfds, fd);
        int WantW = Wfds && __FdsetTest__(Wfds, fd);
        int OkR   = WantR ? __FdIsReadable__(Proc->Fds, fd) : Nothing;
        int OkW   = WantW ? __FdIsWritable__(Proc->Fds, fd) : Nothing;

        if (Rfds && WantR && !OkR)
        {
            __FdsetClear__(Rfds, fd);
        }
        else if (Rfds && WantR && OkR)
        {
            __FdsetSet__(Rfds, fd);
            Ready++;
        }

        if (Wfds && WantW && !OkW)
        {
            __FdsetClear__(Wfds, fd);
        }
        else if (Wfds && WantW && OkW)
        {
            __FdsetSet__(Wfds, fd);
            Ready++;
        }
    }

    if (Ready > 0)
    {
        return Ready;
    }

    if (__Timeout__)
    {
        struct
        {
            long Sec;
            long Usec;
        }*       tv = (void*)__Timeout__;
        uint64_t ms = (tv->Sec * 1000ULL) + (tv->Usec / 1000ULL);
        SysErr   err;
        SysErr*  Error = &err;
        Sleep((uint32_t)ms, Error);

        Ready = 0;
        for (int fd = 0; fd < (int)__Nfds__; fd++)
        {
            int WantR = Rfds && __FdsetTest__(Rfds, fd);
            int WantW = Wfds && __FdsetTest__(Wfds, fd);
            int OkR   = WantR ? __FdIsReadable__(Proc->Fds, fd) : Nothing;
            int OkW   = WantW ? __FdIsWritable__(Proc->Fds, fd) : Nothing;

            if (Rfds && WantR && !OkR)
            {
                __FdsetClear__(Rfds, fd);
            }
            else if (Rfds && WantR && OkR)
            {
                __FdsetSet__(Rfds, fd);
                Ready++;
            }

            if (Wfds && WantW && !OkW)
            {
                __FdsetClear__(Wfds, fd);
            }
            else if (Wfds && WantW && OkW)
            {
                __FdsetSet__(Wfds, fd);
                Ready++;
            }
        }
        return Ready;
    }
    SysErr  err;
    SysErr* Error = &err;
    ThreadYield(Error);
    return SysOkay;
}
