#include "../install/x86_64-elf/include/errno.h"
#include "../install/x86_64-elf/include/stdint.h"
#include "../install/x86_64-elf/include/stdlib.h"
#include "../install/x86_64-elf/include/sys/resource.h"
#include "../install/x86_64-elf/include/sys/select.h"
#include "../install/x86_64-elf/include/sys/stat.h"
#include "../install/x86_64-elf/include/sys/time.h"
#include "../install/x86_64-elf/include/sys/times.h"
#include "../install/x86_64-elf/include/sys/types.h"
#include "sysmac.h"

extern char  _end;
static char* __heap_cursor__;

void*
sbrk(ptrdiff_t __incr__)
{
    int64_t __cur__ = Syscall(SysBrk, 0, 0, 0, 0, 0, 0);
    if (__cur__ < 0)
    {
        errno = (int)(-__cur__);
        return (void*)-1;
    }
    int64_t __want__ = __cur__ + (int64_t)__incr__;
    int64_t __res__  = Syscall(SysBrk, (uint64_t)__want__, 0, 0, 0, 0, 0);
    if (__res__ < 0)
    {
        errno = (int)(-__res__);
        return (void*)-1;
    }
    return (void*)(uintptr_t)__cur__;
}

ssize_t
read(int __fd__, void* __buf__, size_t __len__)
{
    int64_t r = Syscall(SysRead, (uint64_t)__fd__, (uint64_t)__buf__, (uint64_t)__len__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (ssize_t)r;
}

ssize_t
write(int __fd__, const void* __buf__, size_t __len__)
{
    int64_t r = Syscall(SysWrite, (uint64_t)__fd__, (uint64_t)__buf__, (uint64_t)__len__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (ssize_t)r;
}

ssize_t
writev(int __fd__, const struct iovec* __iov__, int __iovcnt__)
{
    if (!__iov__ || __iovcnt__ <= 0)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t r =
        Syscall(SysWritev, (uint64_t)__fd__, (uint64_t)__iov__, (uint64_t)__iovcnt__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (ssize_t)r;
}

ssize_t
readv(int __fd__, const struct iovec* __iov__, int __iovcnt__)
{
    if (!__iov__ || __iovcnt__ <= 0)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t r =
        Syscall(SysReadv, (uint64_t)__fd__, (uint64_t)__iov__, (uint64_t)__iovcnt__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (ssize_t)r;
}

int
open(const char* __path__, int __flags__, int __mode__)
{
    int64_t r =
        Syscall(SysOpen, (uint64_t)__path__, (uint64_t)__flags__, (uint64_t)__mode__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (int)r;
}

int
close(int __fd__)
{
    int64_t r = Syscall(SysClose, (uint64_t)__fd__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

off_t
lseek(int __fd__, off_t __pos__, int __whence__)
{
    int64_t r =
        Syscall(SysLseek, (uint64_t)__fd__, (uint64_t)__pos__, (uint64_t)__whence__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (off_t)-1;
    }
    return (off_t)r;
}

int
fstat(int __fd__, struct stat* __st__)
{
    if (!__st__)
    {
        errno = EINVAL;
        return -1;
    }
    /*Well it satisfies*/
    /*
    VfsStat __kst__ = {0};
    int64_t r       = Syscall(SysFstat, (uint64_t)__fd__, (uint64_t)&__kst__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    __st__->st_mode    = (__kst__.Mode);
    __st__->st_nlink   = (__kst__.Nlink);
    __st__->st_blksize = (__kst__.BlkSize);
    __st__->st_size    = (__kst__.Size);
    */
    return 0;
}

int
isatty(int __fd__)
{
    if (__fd__ == 0 || __fd__ == 1 || __fd__ == 2)
    {
        return 1;
    }
    errno = ENOTTY;
    return 0;
}

void
_exit(int __status__)
{
    (void)Syscall(SysExit, (uint64_t)__status__, 0, 0, 0, 0, 0);
    for (;;)
    {
    }
}

int
kill(pid_t __pid__, int __sig__)
{
    int64_t r = Syscall(SysKill, (uint64_t)__pid__, (uint64_t)__sig__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

pid_t
getpid(void)
{
    int64_t r = Syscall(SysGetpid, 0, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (pid_t)-1;
    }
    return (pid_t)r;
}

int
unlink(const char* __path__)
{
    int64_t r = Syscall(SysUnlink, (uint64_t)__path__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
rename(const char* __old__, const char* __new__)
{
    int64_t r = Syscall(SysRename, (uint64_t)__old__, (uint64_t)__new__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
mkdir(const char* __path__, mode_t __mode__)
{
    int64_t r = Syscall(SysMkdir, (uint64_t)__path__, (uint64_t)__mode__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
rmdir(const char* __path__)
{
    int64_t r = Syscall(SysRmdir, (uint64_t)__path__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
gettimeofday(struct timeval* __tv__, void* __tz__)
{
    int64_t r = Syscall(SysGettimeofday, (uint64_t)__tv__, (uint64_t)__tz__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
nanosleep(const struct timespec* __req__, struct timespec* __rem__)
{
    int64_t r = Syscall(SysNanosleep, (uint64_t)__req__, (uint64_t)__rem__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
access(const char* __path__, int __mode__)
{
    int64_t r = Syscall(SysAccess, (uint64_t)__path__, (uint64_t)__mode__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
chdir(const char* __path__)
{
    int64_t r = Syscall(SysChdir, (uint64_t)__path__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

char*
getcwd(char* __buf__, size_t __len__)
{
    int64_t r = Syscall(SysGetcwd, (uint64_t)__buf__, (uint64_t)__len__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return NULL;
    }
    return __buf__;
}

int
select(
    int __nfds__, fd_set* __rfds__, fd_set* __wfds__, fd_set* __efds__, struct timeval* __timeout__)
{
    int64_t r = Syscall(SysSelect,
                        (uint64_t)__nfds__,
                        (uint64_t)__rfds__,
                        (uint64_t)__wfds__,
                        (uint64_t)__efds__,
                        (uint64_t)__timeout__,
                        0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (int)r;
}

int
ioctl(int __fd__, unsigned long __cmd__, void* __arg__)
{
    int64_t r = Syscall(SysIoctl, (uint64_t)__fd__, (uint64_t)__cmd__, (uint64_t)__arg__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (int)r;
}

int
dup(int __fd__)
{
    int64_t r = Syscall(SysDup, (uint64_t)__fd__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (int)r;
}

int
dup2(int __oldfd__, int __newfd__)
{
    int64_t r = Syscall(SysDup2, (uint64_t)__oldfd__, (uint64_t)__newfd__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return (int)r;
}

pid_t
getppid(void)
{
    int64_t r = Syscall(SysGetppid, 0, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (pid_t)-1;
    }
    return (pid_t)r;
}

pid_t
gettid(void)
{
    int64_t r = Syscall(SysGettid, 0, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (pid_t)-1;
    }
    return (pid_t)r;
}

pid_t
fork(void)
{
    int64_t r = Syscall(SysFork, 0, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (pid_t)-1;
    }
    return (pid_t)r;
}

int
execve(const char* __path__, char* const __argv__, char* const __envp__)
{
    int64_t r =
        Syscall(SysExecve, (uint64_t)__path__, (uint64_t)__argv__, (uint64_t)__envp__, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

pid_t
wait4(pid_t __pid__, int* __status__, int __options__, struct rusage* __rusage__)
{
    int64_t r = Syscall(SysWait4,
                        (uint64_t)__pid__,
                        (uint64_t)__status__,
                        (uint64_t)__options__,
                        (uint64_t)__rusage__,
                        0,
                        0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (pid_t)-1;
    }
    return (pid_t)r;
}

int
pipe(int __pipefd__[2])
{
    if (!__pipefd__)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t r = Syscall(SysPipe, (uint64_t)__pipefd__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
uname(struct utsname* __buf__)
{
    if (!__buf__)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t r = Syscall(SysUname, (uint64_t)__buf__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

void*
mmap(void* __addr__, size_t __len__, int __prot__, int __flags__, int __fd__, off_t __off__)
{
    int64_t r = Syscall(SysMmap,
                        (uint64_t)__addr__,
                        (uint64_t)__len__,
                        (uint64_t)__prot__,
                        (uint64_t)__flags__,
                        (uint64_t)__fd__,
                        (uint64_t)__off__);
    if (r < 0)
    {
#define MAP_FAILED ((void*)-1)
        errno = (int)(-r);
        return (void*)MAP_FAILED;
    }
    return (void*)(uintptr_t)r;
}

int
munmap(void* __addr__, size_t __len__)
{
    int64_t r = Syscall(SysMunmap, (uint64_t)__addr__, (uint64_t)__len__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
brk(void* __new_end__)
{
    int64_t r = Syscall(SysBrk, (uint64_t)__new_end__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

int
stat(const char* __path__, struct stat* __st__)
{
    if (!__path__ || !__st__)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t r = Syscall(SysStat, (uint64_t)__path__, (uint64_t)__st__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

clock_t
times(struct tms* __buf__)
{
    if (!__buf__)
    {
        errno = EINVAL;
        return (clock_t)-1;
    }
    int64_t r = Syscall(SysTimes, (uint64_t)__buf__, 0, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return (clock_t)-1;
    }
    return (clock_t)0;
}

int
clock_gettime(clockid_t __clk_id__, struct timespec* __tp__)
{
    if (!__tp__)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t r = Syscall(SysClockGettime, (uint64_t)__clk_id__, (uint64_t)__tp__, 0, 0, 0, 0);
    if (r < 0)
    {
        errno = (int)(-r);
        return -1;
    }
    return 0;
}

pid_t
waitpid(pid_t __pid__, int* __status__, int __opt__)
{
    int64_t r = Syscall(
        SysWait4, (uint64_t)__pid__, (uint64_t)__status__, (uint64_t)__opt__, (uint64_t)NULL, 0, 0);
    /*Wrap Up to wait4*/
    if (r < 0)
    {
        errno = (int)(-r);
        return (pid_t)-1;
    }
    return (pid_t)r;
}
