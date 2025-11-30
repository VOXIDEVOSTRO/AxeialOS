#pragma once

#include <AllTypes.h>
#include <IDT.h>

#define MaxSysNo 99999

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
    int         ArgIdx;
} SysEnt;

static SysEnt SysTbl[MaxSysNo];

#define Syscall(__SysNum__, __Arg1__, __Arg2__, __Arg3__, __Arg4__, __Arg5__, __Arg6__)            \
    ({                                                                                             \
        int64_t result;                                                                            \
        __asm__ volatile("movq %1, %%rax\n\t" /* syscall __SysNum__ber */                          \
                         "movq %2, %%rdi\n\t" /* __Arg1__ */                                       \
                         "movq %3, %%rsi\n\t" /* __Arg2__ */                                       \
                         "movq %4, %%rdx\n\t" /* __Arg3__ */                                       \
                         "movq %5, %%r10\n\t" /* __Arg4__ */                                       \
                         "movq %6, %%r8\n\t"  /* __Arg5__ */                                       \
                         "movq %7, %%r9\n\t"  /* __Arg6__ */                                       \
                         "int $0x80\n\t"      /* syscall interrupt */                              \
                         "movq %%rax, %0"                                                          \
                         : "=r"(result)                                                            \
                         : "r"((uint64_t)(__SysNum__)),                                            \
                           "r"((uint64_t)(__Arg1__)),                                              \
                           "r"((uint64_t)(__Arg2__)),                                              \
                           "r"((uint64_t)(__Arg3__)),                                              \
                           "r"((uint64_t)(__Arg4__)),                                              \
                           "r"((uint64_t)(__Arg5__)),                                              \
                           "r"((uint64_t)(__Arg6__))                                               \
                         : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory");               \
        result;                                                                                    \
    })
extern void SysEntASM(void);
void        InitSyscall(void);
void        SyscallHandler(uint64_t __SyscallNo__,
                           uint64_t __A1__,
                           uint64_t __A2__,
                           uint64_t __A3__,
                           uint64_t __A4__,
                           uint64_t __A5__,
                           uint64_t __A6__);