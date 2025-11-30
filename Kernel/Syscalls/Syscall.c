#include <SysABI.h>
#include <SysTbl.h>
#include <Syscall.h>

void
SyscallHandler(uint64_t __SyscallNo__,
               uint64_t __A1__,
               uint64_t __A2__,
               uint64_t __A3__,
               uint64_t __A4__,
               uint64_t __A5__,
               uint64_t __A6__)
{
    if (__SyscallNo__ >= MaxSysNo || SysTbl[__SyscallNo__].Handler == NULL)
    {
        __asm__ volatile("movq $-1, %%rax" : : : "rax");
        return;
    }
    int64_t RaxrRes = SysTbl[__SyscallNo__].Handler(__A1__, __A2__, __A3__, __A4__, __A5__, __A6__);
    __asm__ volatile("movq %0, %%rax" : : "r"(RaxrRes) : "rax");
}

__asm__(".global SysEntASM\n"
        "SysEntASM:\n"
        " pushq %rbx\n"
        " pushq %rcx\n"
        " pushq %rdx\n"
        " pushq %rsi\n"
        " pushq %rdi\n"
        " pushq %rbp\n"
        " pushq %r8\n"
        " pushq %r9\n"
        " pushq %r10\n"
        " pushq %r11\n"
        " pushq %r12\n"
        " pushq %r13\n"
        " pushq %r14\n"
        " pushq %r15\n"
        " \n"
        " # RAX = syscall number\n"
        " # RDI = __A1__, RSI = __A2__, RDX = __A3__\n"
        " # R10 = __A4__, R8 = __A5__, R9 = __A6__\n"
        " \n"
        " movq %rdi, %rbx # Save __A1__\n"
        " movq %rsi, %r11 # Save __A2__\n"
        " movq %rdx, %r12 # Save __A3__\n"
        " movq %r10, %r13 # Save __A4__\n"
        " movq %r8, %r14 # Save __A5__\n"
        " movq %r9, %r15 # Save __A6__\n"
        " \n"
        " # SyscallHandler(__SyscallNo__, __A1__, __A2__, __A3__, __A4__, __A5__, "
        "__A6__)\n"
        " movq %rax, %rdi # __SyscallNo__ -> RDI\n"
        " movq %rbx, %rsi # __A1__ -> RSI\n"
        " movq %r11, %rdx # __A2__ -> RDX\n"
        " movq %r12, %rcx # __A3__ -> RCX\n"
        " movq %r13, %r8 # __A4__ -> R8\n"
        " movq %r14, %r9 # __A5__ -> R9\n"
        " pushq %r15 # __A6__ -> stack\n"
        " \n"
        " call SyscallHandler\n"
        " addq $8, %rsp # Clean up pushed __A6__\n"
        " \n"
        " popq %r15\n"
        " popq %r14\n"
        " popq %r13\n"
        " popq %r12\n"
        " popq %r11\n"
        " popq %r10\n"
        " popq %r9\n"
        " popq %r8\n"
        " popq %rbp\n"
        " popq %rdi\n"
        " popq %rsi\n"
        " popq %rdx\n"
        " popq %rcx\n"
        " popq %rbx\n"
        " \n"
        " iretq\n");

void
InitSyscall(void)
{
    /*handles*/
    SysTbl[SysRead].Handler = __Handle__Read;
    SysTbl[SysRead].SysName = "read";

    SysTbl[SysWrite].Handler = __Handle__Write;
    SysTbl[SysWrite].SysName = "write";

    SysTbl[SysOpen].Handler = __Handle__Open;
    SysTbl[SysOpen].SysName = "open";

    SysTbl[SysClose].Handler = __Handle__Close;
    SysTbl[SysClose].SysName = "close";

    SysTbl[SysStat].Handler = __Handle__Stat;
    SysTbl[SysStat].SysName = "stat";

    SysTbl[SysFstat].Handler = __Handle__Fstat;
    SysTbl[SysFstat].SysName = "fstat";

    SysTbl[SysLseek].Handler = __Handle__Lseek;
    SysTbl[SysLseek].SysName = "lseek";

    SysTbl[SysIoctl].Handler = __Handle__Ioctl;
    SysTbl[SysIoctl].SysName = "ioctl";

    SysTbl[SysAccess].Handler = __Handle__Access;
    SysTbl[SysAccess].SysName = "access";

    SysTbl[SysPipe].Handler = __Handle__Pipe;
    SysTbl[SysPipe].SysName = "pipe";

    SysTbl[SysSchedYield].Handler = __Handle__SchedYield;
    SysTbl[SysSchedYield].SysName = "sched_yield";

    SysTbl[SysMkdir].Handler = __Handle__Mkdir;
    SysTbl[SysMkdir].SysName = "mkdir";

    SysTbl[SysRmdir].Handler = __Handle__Rmdir;
    SysTbl[SysRmdir].SysName = "rmdir";

    SysTbl[SysUnlink].Handler = __Handle__Unlink;
    SysTbl[SysUnlink].SysName = "unlink";

    SysTbl[SysRename].Handler = __Handle__Rename;
    SysTbl[SysRename].SysName = "rename";

    SysTbl[SysGetpid].Handler = __Handle__Getpid;
    SysTbl[SysGetpid].SysName = "getpid";

    SysTbl[SysGetppid].Handler = __Handle__Getppid;
    SysTbl[SysGetppid].SysName = "getppid";

    SysTbl[SysGettid].Handler = __Handle__Gettid;
    SysTbl[SysGettid].SysName = "gettid";

    SysTbl[SysFork].Handler = __Handle__Fork;
    SysTbl[SysFork].SysName = "fork";

    SysTbl[SysExecve].Handler = __Handle__Execve;
    SysTbl[SysExecve].SysName = "execve";

    SysTbl[SysExit].Handler = __Handle__Exit;
    SysTbl[SysExit].SysName = "exit";

    SysTbl[SysWait4].Handler = __Handle__Wait4;
    SysTbl[SysWait4].SysName = "wait4";

    SysTbl[SysKill].Handler = __Handle__Kill;
    SysTbl[SysKill].SysName = "kill";

    SysTbl[SysDup].Handler = __Handle__Dup;
    SysTbl[SysDup].SysName = "dup";

    SysTbl[SysDup2].Handler = __Handle__Dup2;
    SysTbl[SysDup2].SysName = "dup2";

    SysTbl[SysNanosleep].Handler = __Handle__Nanosleep;
    SysTbl[SysNanosleep].SysName = "nanosleep";

    SysTbl[SysGetcwd].Handler = __Handle__Getcwd;
    SysTbl[SysGetcwd].SysName = "getcwd";

    SysTbl[SysChdir].Handler = __Handle__Chdir;
    SysTbl[SysChdir].SysName = "chdir";

    SysTbl[SysUname].Handler = __Handle__Uname;
    SysTbl[SysUname].SysName = "uname";

    SysTbl[SysGettimeofday].Handler = __Handle__Gettimeofday;
    SysTbl[SysGettimeofday].SysName = "gettimeofday";

    SysTbl[SysTimes].Handler = __Handle__Times;
    SysTbl[SysTimes].SysName = "times";

    SysTbl[SysClockGettime].Handler = __Handle__ClockGettime;
    SysTbl[SysClockGettime].SysName = "clock_gettime";

    SysTbl[SysMmap].Handler = __Handle__Mmap;
    SysTbl[SysMmap].SysName = "mmap";

    SysTbl[SysMunmap].Handler = __Handle__Munmap;
    SysTbl[SysMunmap].SysName = "munmap";

    SysTbl[SysBrk].Handler = __Handle__Brk;
    SysTbl[SysBrk].SysName = "brk";

    SysTbl[SysSelect].Handler = __Handle__Select;
    SysTbl[SysSelect].SysName = "select";

    SysTbl[SysWritev].Handler = __Handle__Writev;
    SysTbl[SysWritev].SysName = "writev";

    SysTbl[SysReadv].Handler = __Handle__Readv;
    SysTbl[SysReadv].SysName = "readv";
}
