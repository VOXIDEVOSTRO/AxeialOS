#pragma once

#include <AllTypes.h>
#include <IDT.h>
#include <__AXEKCONF__.h>

#include <Errnos.h>
#define MaxSysNo         99999
#define SyscallIntNo     0x80
#define SysInterruptGate 0xEE

typedef int64_t (*SysHandle)(uint64_t __Arg1__,
                             uint64_t __Arg2__,
                             uint64_t __Arg3__,
                             uint64_t __Arg4__,
                             uint64_t __Arg5__,
                             uint64_t __Arg6__);
typedef struct
{
    SysHandle   Handler;
    const char* SysName;
    int         ArgIdx; /*Deprecated, TODO: remove it in the future*/
} SysEnt;

static SysEnt SysTbl[MaxSysNo];

// #define LegacySyscalls

/*Int 0x80*/
#ifdef LegacySyscalls
#    define Syscall(__SysNum__, __Arg1__, __Arg2__, __Arg3__, __Arg4__, __Arg5__, __Arg6__)        \
        ({                                                                                         \
            int64_t result;                                                                        \
            __asm__ volatile("movq %1, %%rax\n\t" /* syscall __SysNum__ber */                      \
                             "movq %2, %%rdi\n\t" /* __Arg1__ */                                   \
                             "movq %3, %%rsi\n\t" /* __Arg2__ */                                   \
                             "movq %4, %%rdx\n\t" /* __Arg3__ */                                   \
                             "movq %5, %%r10\n\t" /* __Arg4__ */                                   \
                             "movq %6, %%r8\n\t"  /* __Arg5__ */                                   \
                             "movq %7, %%r9\n\t"  /* __Arg6__ */                                   \
                             "int $0x80\n\t"      /* syscall interrupt */                          \
                             "movq %%rax, %0"                                                      \
                             : "=r"(result)                                                        \
                             : "r"((uint64_t)(__SysNum__)),                                        \
                               "r"((uint64_t)(__Arg1__)),                                          \
                               "r"((uint64_t)(__Arg2__)),                                          \
                               "r"((uint64_t)(__Arg3__)),                                          \
                               "r"((uint64_t)(__Arg4__)),                                          \
                               "r"((uint64_t)(__Arg5__)),                                          \
                               "r"((uint64_t)(__Arg6__))                                           \
                             : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory");           \
            result;                                                                                \
        })

#else
/*Syscall instruction*/
#    define Syscall(__SysNum__, __Arg1__, __Arg2__, __Arg3__, __Arg4__, __Arg5__, __Arg6__)        \
        ({                                                                                         \
            long          result;                                                                  \
            register long rax __asm__("rax") = (__SysNum__);                                       \
            register long rdi __asm__("rdi") = (__Arg1__);                                         \
            register long rsi __asm__("rsi") = (__Arg2__);                                         \
            register long rdx __asm__("rdx") = (__Arg3__);                                         \
            register long r10 __asm__("r10") = (__Arg4__);                                         \
            register long r8 __asm__("r8")   = (__Arg5__);                                         \
            register long r9 __asm__("r9")   = (__Arg6__);                                         \
            __asm__ volatile("syscall"                                                             \
                             : "=a"(result)                                                        \
                             : "a"(rax), "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10), "r"(r8), "r"(r9)  \
                             : "rcx", "r11", "memory");                                            \
            result;                                                                                \
        })
#endif

extern void SysEntASM(void);
extern void SysEntASMSys(void);
void        InitSyscall(void);
void        SyscallHandler(uint64_t __SyscallNo__,
                           uint64_t __A1__,
                           uint64_t __A2__,
                           uint64_t __A3__,
                           uint64_t __A4__,
                           uint64_t __A5__,
                           uint64_t __A6__);