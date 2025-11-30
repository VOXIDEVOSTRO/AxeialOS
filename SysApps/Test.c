#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>

/*take full advantage of the newlibbbb*/

#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#define PROT_NONE     0x0
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED    ((void*)-1)

int
main(void)
{
    /* 1) stdio baseline */
    printf("[stdio] Hello AxeOS via newlib!\n");
    fprintf(stderr, "[stdio] stderr path alive\n");
    fflush(stdout);
    fflush(stderr);

    int fd = open("/dev/tty0", O_WRONLY);
    if (fd < 0)
    {
        fd = open("/dev/null", O_WRONLY);
    }
    if (fd >= 0)
    {
        const char* msg = "[vfs] write() says hi!\n";
        ssize_t     w   = write(fd, msg, (size_t)strlen(msg));
        printf("[vfs] wrote %ld bytes\n", (long)w);
        close(fd);
    }
    else
    {
        printf("[vfs] open failed\n");
    }
    fflush(stdout);

    char* buf = (char*)malloc(4096);
    if (buf)
    {
        memset(buf, 'A', 4095);
        buf[4095] = '\0';
        printf("[malloc] filled 4KB buffer, last=%c\n", buf[4094]);
        free(buf);
    }
    else
    {
        printf("[malloc] failed (heap not extended?)\n");
    }
    fflush(stdout);

    size_t total = 0;
    for (int i = 0; i < 10; i++)
    {
        void* p = malloc(8192);
        if (!p)
        {
            printf("[brk] malloc failed at %d (total=%lu)\n", i, (unsigned long)total);
            break;
        }
        memset(p, 0x5A, 8192);
        total += 8192;
    }

    printf("[brk] allocated ~%lu bytes via malloc bursts\n", (unsigned long)total);
    fflush(stdout);

    void* m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m != MAP_FAILED && m != NULL)
    {
        strcpy((char*)m, "[mmap] hello page\n");
        printf("%s", (char*)m);
        printf("[mmap] ok at %p\n", m);
        munmap(m, 4096);
    }
    else
    {
        printf("[mmap] failed (MAP_ANONYMOUS not supported or mapping denied)\n");
    }
    fflush(stdout);

    struct timeval tv = {0};
    if (gettimeofday(&tv, NULL) == 0)
    {
        printf("[time] %ld.%06ld\n", (long)tv.tv_sec, (long)tv.tv_usec);
    }
    struct tms tmsbuf;
    clock_t    t = times(&tmsbuf);
    if (t != (clock_t)-1)
    {
        printf("[times] utime=%ld stime=%ld\n", (long)tmsbuf.tms_utime, (long)tmsbuf.tms_stime);
    }
    fflush(stdout);

    struct stat st;
    if (stat("/proc/2/stat", &st) == 0)
    {
        printf(
            "[stat] /proc/2/stat ino=%lu mode=0%o\n", (unsigned long)st.st_ino, st.st_mode & 0777);
    }
    else
    {
        printf("[stat] failed\n");
    }
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0)
    {
        printf("Pid is 0!\n");
        long pid1 = (long)getpid();
        printf("[fork] child says hi (pid=%ld)\n", pid1);
        fflush(stdout);
        _exit(0);
    }
    else if (pid > 0)
    {
        printf("Pid is NON 0!\n");
        /*Anyway it would spin forever*/
        /*
        int   status = 0;
        pid_t r      = waitpid(pid, &status, 0);
        printf("[fork] parent reaped pid=%ld status=%d ret=%ld\n", (long)pid, status, (long)r);
        */
    }
    else
    {
        printf("[fork] failed\n");
    }
    fflush(stdout);

    for (int i = 0; i < 5; i++)
    {
        printf("[stdio] line %d\n", i);
    }
    fflush(stdout);

    return 0;
}