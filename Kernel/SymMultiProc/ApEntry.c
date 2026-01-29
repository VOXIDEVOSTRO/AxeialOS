#include <APICTimer.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <PerCPUData.h>
#include <SymAP.h>
#include <Syscall.h>
#include <Timer.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGAPENTRYC_Debug
#    define LOGAPENTRYC_PDebug(fmt, ...) PDebug("[KERNEL>>ApEntry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPENTRYC_PDebug(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPENTRYC_Logs
#    define LOGAPENTRYC_PError(fmt, ...) PError("[KERNEL>>ApEntry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPENTRYC_PError(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPENTRYC_Logs
#    define LOGAPENTRYC_PWarn(fmt, ...) PWarn("[KERNEL>>ApEntry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPENTRYC_PWarn(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPENTRYC_Logs
#    define LOGAPENTRYC_PInfo(fmt, ...) PInfo("[KERNEL>>ApEntry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPENTRYC_PInfo(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPENTRYC_Logs
#    define LOGAPENTRYC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ApEntry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPENTRYC_PSuccess(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*Ap's will jump here*/
void
ApEntryPoint(struct limine_smp_info* __CpuInfo__)
{
    uint32_t CpuNumber = 0;
    for (uint32_t Index = 0; Index < atomic_load_explicit(&Smp.CpuCount, memory_order_relaxed);
         Index++)
    {
        if (atomic_load_explicit(&Smp.Cpus[Index].ApicId, memory_order_relaxed) ==
            __CpuInfo__->lapic_id)
        {
            CpuNumber = Index;
            break;
        }
    }

    LOGAPENTRYC_PInfo("CPU %u jumped to AP entry point\n", CpuNumber);

    SysErr  err;
    SysErr* Error = &err;

    atomic_store_explicit(&Smp.Cpus[CpuNumber].Status, CPU_STATUS_ONLINE, memory_order_seq_cst);
    atomic_store_explicit(&Smp.Cpus[CpuNumber].Started, 1, memory_order_seq_cst);
    atomic_fetch_add_explicit(&CpuStartupCount, 1, memory_order_seq_cst);
    atomic_fetch_add_explicit(&Smp.OnlineCpus, 1, memory_order_seq_cst);

    /*FPU/SSE/Floats*/
    LOGAPENTRYC_PInfo("Reloading Floats/SSE/FPU for CPU %u\n", CpuNumber);
    unsigned long Cr0, Cr4;
    __asm__ volatile("mov %%cr0, %0" : "=r"(Cr0));
    __asm__ volatile("mov %%cr4, %0" : "=r"(Cr4));
    Cr0 &= ~(1UL << 2); /* EM = 0 */
    Cr0 |= (1UL << 1);  /* MP = 1 */
    Cr0 &= ~(1UL << 3); /* TS = 0 */
    __asm__ volatile("mov %0, %%cr0" ::"r"(Cr0) : "memory");
    Cr4 |= (1UL << 9) | (1UL << 10);
    __asm__ volatile("mov %0, %%cr4" ::"r"(Cr4) : "memory");
    __asm__ volatile("fninit");
    LOGAPENTRYC_PSuccess("CPU %u Floats/SSE/FPU reloaded\n", CpuNumber);

    /*Stack*/
    LOGAPENTRYC_PInfo("Reloading stack for CPU %u\n", CpuNumber);
    ReloadStack(CpuNumber);
    LOGAPENTRYC_PSuccess("CPU %u stack reloaded\n", CpuNumber);

    /*GDT/IDT/TSS*/
    LOGAPENTRYC_PInfo("Reloading core data for CPU %u\n", CpuNumber);
    ReloadCoreAps(CpuNumber);
    LOGAPENTRYC_PSuccess("CPU %u core data reloaded\n", CpuNumber);

    /*Timer*/
    LOGAPENTRYC_PInfo("Callibrating a timer for CPU %u\n", CpuNumber);
    InitializeTimer(false, Error);
    LOGAPENTRYC_PSuccess("CPU %u Timer callibrated\n", CpuNumber);

    /*Syscall*/
    LOGAPENTRYC_PInfo("Opening syscall gate for CPU %u\n", CpuNumber);

    /*Legacy*/
    SetIdtEntry(SyscallIntNo,
                (uint64_t)SysEntASM /*Int 0x80*/,
                KernelCodeSelector,
                SysInterruptGate,
                Error);

    /*Modern*/
    uint64_t Efer = ReadMsr(0xC0000080); // EFER MSR
    Efer |= (1 << 0);                    // Set SCE (System Call Enable)
    WriteMsr(0xC0000080, Efer);
    uint64_t Star = ((uint64_t)0x13 << 48) | ((uint64_t)0x08 << 32);
    WriteMsr(0xC0000081, Star);                               // STAR MSR
    WriteMsr(0xC0000082, (uint64_t)SysEntASMSys /*Syscall*/); // LSTAR MSR
    WriteMsr(0xC0000084, (1ULL << 9));                        // SFMASK MSR
    LOGAPENTRYC_PSuccess("CPU %u Syscall gate opened\n", CpuNumber);

    /*Pages*/
    LOGAPENTRYC_PInfo("Reloading BSP Pages for CPU %u\n", CpuNumber);
    GlobalizePerCPUMem(Error);
    LOGAPENTRYC_PSuccess("CPU %u BSP Pages reloaded\n", CpuNumber);

    LOGAPENTRYC_PSuccess("CPU %u online with stack at 0x%016lx and ready for stuff\n",
                         CpuNumber,
                         GetPerCpuData(GetCurrentCpuId())->StackTop);

    for (;;)
    {
        __asm__ volatile("hlt");
    }
}
