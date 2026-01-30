#include <GDT.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <String.h>
#include <SymAP.h>
#include <Timer.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGStackAndCPUC_Debug
#    define LOGStackAndCPUC_PDebug(fmt, ...) PDebug("[KERNEL>>StackAndCPU.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGStackAndCPUC_PDebug(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGStackAndCPUC_Logs
#    define LOGStackAndCPUC_PError(fmt, ...) PError("[KERNEL>>StackAndCPU.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGStackAndCPUC_PError(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGStackAndCPUC_Logs
#    define LOGStackAndCPUC_PWarn(fmt, ...) PWarn("[KERNEL>>StackAndCPU.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGStackAndCPUC_PWarn(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGStackAndCPUC_Logs
#    define LOGStackAndCPUC_PInfo(fmt, ...) PInfo("[KERNEL>>StackAndCPU.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGStackAndCPUC_PInfo(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGStackAndCPUC_Logs
#    define LOGStackAndCPUC_PSuccess(fmt, ...)                                                     \
        PSuccess("[KERNEL>>StackAndCPU.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGStackAndCPUC_PSuccess(fmt, ...)                                                     \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

PerCpuData CpuDataArray[MaxCPUs];

PerCpuData*
GetPerCpuData(uint32_t __CpuNumber__)
{
    return &CpuDataArray[__CpuNumber__];
}

bool
InitCoreAps(SysErr* __Err__)
{
    uint32_t CpuCount = (uint32_t)atomic_load_explicit(&Smp.CpuCount, memory_order_relaxed);

    for (uint32_t Cpu = 0; Cpu < CpuCount; ++Cpu)
    {
        PerCpuData* CpuData = &CpuDataArray[Cpu];

        for (int Idx = 0; Idx < MaxGdt; ++Idx)
        {
            CpuData->Gdt[Idx] = GdtEntries[Idx];
        }

        for (int Idx = 0; Idx < MaxIdt; ++Idx)
        {
            CpuData->Idt[Idx] = IdtEntries[Idx];
        }

        CpuData->StackTop = (uint64_t)atomic_load_explicit(
            (atomic_uint_fast64_t*)&CpuData->StackTop, memory_order_relaxed);
        memset(&CpuData->Tss, 0, sizeof(CpuData->Tss));
        CpuData->Tss.IoMapBase                    = sizeof(TaskStateSegment);
        CpuData->Tss.Rsp0                         = CpuData->StackTop;
        uint64_t TssBase                          = (uint64_t)&CpuData->Tss;
        uint32_t TssLimit                         = sizeof(TaskStateSegment) - 1;
        CpuData->Gdt[GdtTssIndex].LimitLow        = TssLimit & 0xFFFF;
        CpuData->Gdt[GdtTssIndex].BaseLow         = TssBase & 0xFFFF;
        CpuData->Gdt[GdtTssIndex].BaseMiddle      = (TssBase >> 16) & 0xFF;
        CpuData->Gdt[GdtTssIndex].Access          = 0x89;
        CpuData->Gdt[GdtTssIndex].Granularity     = (TssLimit >> 16) & 0x0F;
        CpuData->Gdt[GdtTssIndex].BaseHigh        = (TssBase >> 24) & 0xFF;
        CpuData->Gdt[GdtTssIndex + 1].LimitLow    = (TssBase >> 32) & 0xFFFF;
        CpuData->Gdt[GdtTssIndex + 1].BaseLow     = (TssBase >> 48) & 0xFFFF;
        CpuData->Gdt[GdtTssIndex + 1].BaseMiddle  = 0;
        CpuData->Gdt[GdtTssIndex + 1].Access      = 0;
        CpuData->Gdt[GdtTssIndex + 1].Granularity = 0;
        CpuData->Gdt[GdtTssIndex + 1].BaseHigh    = 0;
        CpuData->GdtPtr.Limit                     = (sizeof(GdtEntry) * MaxGdt) - 1;
        CpuData->GdtPtr.Base                      = (uint64_t)CpuData->Gdt;
        CpuData->IdtPtr.Limit                     = (sizeof(IdtEntry) * MaxIdt) - 1;
        CpuData->IdtPtr.Base                      = (uint64_t)CpuData->Idt;
        CpuData->ApicBase        = (uint64_t)PhysToVirt(ReadMsr(0x1B) & 0xFFFFF000);
        CpuData->LocalTicks      = 0;
        CpuData->LocalInterrupts = 0;
        atomic_thread_fence(memory_order_release);
        atomic_store_explicit(&CpuData->Initialized, (uint8_t)1, memory_order_release);

        LOGStackAndCPUC_PDebug("Per-CPU data for CPU %u (GDT=0x%llx IDT=0x%llx "
                               "TSS=0x%llx StackTop=0x%llx)\n",
                               Cpu,
                               (unsigned long long)CpuData->GdtPtr.Base,
                               (unsigned long long)CpuData->IdtPtr.Base,
                               (unsigned long long)TssBase,
                               (unsigned long long)CpuData->StackTop);
    }

    LOGStackAndCPUC_PSuccess("GDT/IDT/TSS completed for %u CPUs\n", CpuCount);
    return true;
}

bool
ReloadCoreAps(uint32_t __CpuNumber__)
{
    SysErr  err;
    SysErr* Error = &err;
    GlobalizePerCPUMem(Error);
    PerCpuData* CpuData = GetPerCpuData(__CpuNumber__);

    while (!atomic_load_explicit(&CpuData->Initialized, memory_order_acquire))
    {
        __asm__ volatile("pause");
    }

    LOGStackAndCPUC_PDebug("CPU %u: Reloading Per-CPU Data from Slot\n", __CpuNumber__);

    CpuData->GdtPtr.Base = (uint64_t)CpuData->Gdt;
    CpuData->IdtPtr.Base = (uint64_t)CpuData->Idt;
    atomic_thread_fence(memory_order_seq_cst);

    __asm__ volatile("lgdt %0" : : "m"(CpuData->GdtPtr) : "memory");
    __asm__ volatile("lidt %0" : : "m"(CpuData->IdtPtr) : "memory");
    __asm__ volatile("pushq $0x08\n\t"
                     "leaq 1f(%%rip), %%rax\n\t"
                     "pushq %%rax\n\t"
                     "lretq\n\t"
                     "1:\n\t"
                     :
                     :
                     : "rax", "memory");
    __asm__ volatile("mov $0x10, %%ax\n\t"
                     "mov %%ax, %%ds\n\t"
                     "mov %%ax, %%es\n\t"
                     "mov %%ax, %%fs\n\t"
                     "mov %%ax, %%gs\n\t"
                     "mov %%ax, %%ss\n\t"
                     :
                     :
                     : "ax", "memory");
    __asm__ volatile("ltr %0" : : "r"((uint16_t)TssSelector) : "memory");

    GdtPointer VerifyGdt;
    IdtPointer VerifyIdt;
    uint16_t   VerifyTr;

    __asm__ volatile("sgdt %0" : "=m"(VerifyGdt));
    __asm__ volatile("sidt %0" : "=m"(VerifyIdt));
    __asm__ volatile("str %0" : "=r"(VerifyTr));

    LOGStackAndCPUC_PDebug("CPU %u: Verification for GDT/IDT/TSS:\n", __CpuNumber__);
    LOGStackAndCPUC_PDebug("  GDT: Expected=0x%llx, Actual=0x%llx\n",
                           (unsigned long long)CpuData->GdtPtr.Base,
                           (unsigned long long)VerifyGdt.Base);
    LOGStackAndCPUC_PDebug("  IDT: Expected=0x%llx, Actual=0x%llx\n",
                           (unsigned long long)CpuData->IdtPtr.Base,
                           (unsigned long long)VerifyIdt.Base);
    LOGStackAndCPUC_PDebug(
        "  TSS: Expected=0x%x, Actual=0x%x\n", (uint32_t)TssSelector, (uint32_t)VerifyTr);

    bool VerifyOK = true;

    if (VerifyGdt.Base != CpuData->GdtPtr.Base)
    {
        LOGStackAndCPUC_PError("CPU %u: [GDT] verification failed!\n", __CpuNumber__);
        VerifyOK = false;
    }

    if (VerifyIdt.Base != CpuData->IdtPtr.Base)
    {
        LOGStackAndCPUC_PError("CPU %u: [IDT] verification failed!\n", __CpuNumber__);
        VerifyOK = false;
    }

    if (VerifyTr != TssSelector)
    {
        LOGStackAndCPUC_PError("CPU %u: [TSS] verification failed!\n", __CpuNumber__);
        VerifyOK = false;
    }

    if (CpuData->Tss.Rsp0 == 0)
    {
        LOGStackAndCPUC_PError("CPU %u: TSS Rsp0 is NULL!, Cannot proceed!\n", __CpuNumber__);
        VerifyOK = false;
    }

    if (VerifyOK == false)
    {
        PushError("ReloadCoreAps",
                  LOGStackAndCPUC_PError,
                  "Failed to reload core AP data, failed verification",
                  -NotCanonical);
        return false;
    }

    LOGStackAndCPUC_PSuccess("CPU %u: Interrupt handling active\n", __CpuNumber__);

    return true;
}

bool
SetApStack(SysErr* __Err__)
{
    uint32_t CpuCount = (uint32_t)atomic_load_explicit(&Smp.CpuCount, memory_order_relaxed);

    for (uint32_t Cpu = 0; Cpu < CpuCount; ++Cpu)
    {
        PerCpuData* CpuData = GetPerCpuData(Cpu);

        /* allocate physical pages for the AP stack */
        uint64_t CpuStackPhys = AllocPages(SMPCPUStackSize / 0x1000);
        if (!CpuStackPhys)
        {
            LOGStackAndCPUC_PError("Failed to allocate stack for CPU %u\n", Cpu);
            SlotError(__Err__, -TooMany);
            PushError(
                "SetApStack", LOGStackAndCPUC_PError, "failed to allocate stack for AP", -TooMany);
            return false;
        }

        void*    CpuStack    = PhysToVirt(CpuStackPhys);
        uint64_t NewStackTop = (uint64_t)CpuStack + SMPCPUStackSize - 16;
        atomic_store_explicit(
            (_Atomic uint64_t*)&CpuData->StackTop, NewStackTop, memory_order_release);
        atomic_thread_fence(memory_order_seq_cst);
        CpuData->Tss.Rsp0 = NewStackTop;

        LOGStackAndCPUC_PDebug("Allocated stack for CPU %u phys=0x%llx virt=0x%llx top=0x%llx\n",
                               Cpu,
                               (unsigned long long)CpuStackPhys,
                               (unsigned long long)CpuStack,
                               (unsigned long long)NewStackTop);
    }

    LOGStackAndCPUC_PSuccess("SetApStack completed for %u CPUs\n", CpuCount);
    return true;
}

void
ReloadStack(uint32_t __CpuNumber__)
{
    PerCpuData* CpuData = GetPerCpuData(__CpuNumber__);
    uint64_t    StackTop;
    SysErr      err;
    SysErr*     Error = &err;

    GlobalizePerCPUMem(Error);

    do
    {
        StackTop =
            atomic_load_explicit((_Atomic uint64_t*)&CpuData->StackTop, memory_order_acquire);
        if (!StackTop)
        {
            __asm__ volatile("pause");
        }
    } while (!StackTop);

    /* switch to the published stack top */
    __asm__ volatile("movq %0, %%rsp" : : "r"(StackTop) : "memory");

    LOGStackAndCPUC_PDebug("AP %u: ReloadStack set RSP=0x%llx (TSS.Rsp0=0x%llx)\n",
                           __CpuNumber__,
                           (unsigned long long)StackTop,
                           (unsigned long long)CpuData->Tss.Rsp0);
}
