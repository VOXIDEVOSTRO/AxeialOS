#include <APICTimer.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <SymAP.h>
#include <Syscall.h>
#include <Timer.h>
#include <VMM.h>

/*Ap's will jump here*/
void
ApEntryPoint(struct limine_smp_info* __CpuInfo__)
{
    uint32_t CpuNumber = 0;
    for (uint32_t Index = 0; Index < Smp.CpuCount; Index++)
    {
        if (Smp.Cpus[Index].ApicId == __CpuInfo__->lapic_id)
        {
            CpuNumber = Index;
            break;
        }
    }

    SysErr  err;
    SysErr* Error = &err;

    Smp.Cpus[CpuNumber].Status  = CPU_STATUS_ONLINE;
    Smp.Cpus[CpuNumber].Started = 1;

    __atomic_fetch_add(&CpuStartupCount, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&Smp.OnlineCpus, 1, __ATOMIC_SEQ_CST);

    uint64_t CpuStackPhys = AllocPages(SMPCPUStackSize / 0x1000);
    if (!CpuStackPhys)
    {
        while (1)
        {
            __asm__("hlt"); /* Infinite loop of shame; CPU cannot proceed */
        }
    }

    void* CpuStack = PhysToVirt(CpuStackPhys);

    uint64_t NewStackTop = (uint64_t)CpuStack + SMPCPUStackSize - 16;
    __asm__ volatile("movq %0, %%rsp" : : "r"(NewStackTop));

    PInfo("CPU %u online with stack at 0x%016lx\n", CpuNumber, NewStackTop);

    PerCpuInterruptInit(CpuNumber, NewStackTop, Error);

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

    SetupApicTimerForThisCpu(Error);

    InitializeCpuScheduler(CpuNumber, Error);

    SetIdtEntry(SyscallIntNo, (uint64_t)SysEntASM, KernelCodeSelector, SysInterruptGate, Error);

    __asm__ volatile("sti");

    for (;;)
    {
        __asm__ volatile("hlt");
    }
}
