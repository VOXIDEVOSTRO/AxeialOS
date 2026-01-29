#include <APICTimer.h>
#include <LimineSMP.h>
#include <LimineServices.h>
#include <SMP.h>
#include <Timer.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGLIMINESMPC_Debug
#    define LOGLIMINESMPC_PDebug(fmt, ...) PDebug("[KERNEL>>LimineSMP.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLIMINESMPC_PDebug(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLIMINESMPC_Logs
#    define LOGLIMINESMPC_PError(fmt, ...) PError("[KERNEL>>LimineSMP.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLIMINESMPC_PError(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLIMINESMPC_Logs
#    define LOGLIMINESMPC_PWarn(fmt, ...) PWarn("[KERNEL>>LimineSMP.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLIMINESMPC_PWarn(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLIMINESMPC_Logs
#    define LOGLIMINESMPC_PInfo(fmt, ...) PInfo("[KERNEL>>LimineSMP.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLIMINESMPC_PInfo(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLIMINESMPC_Logs
#    define LOGLIMINESMPC_PSuccess(fmt, ...) PSuccess("[KERNEL>>LimineSMP.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLIMINESMPC_PSuccess(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

SmpManager        Smp;
SpinLock          SMPLock;
volatile uint32_t CpuStartupCount = 0;

uint32_t
GetCurrentCpuId(void)
{
    uint64_t ApicBaseMsr  = ReadMsr(TimerApicBaseMsr); /* IA32_APIC_BASE Model-Specific Register */
    uint64_t ApicPhysBase = ApicBaseMsr & 0xFFFFF000;  /* Extract 4KB-aligned base address */

    volatile uint32_t* ApicIdReg = (volatile uint32_t*)(PhysToVirt(ApicPhysBase) + 0x20);
    uint32_t           ApicId    = (*ApicIdReg >> 24) & 0xFF;

    for (uint32_t Index = 0; Index < Smp.CpuCount; Index++)
    {
        if (Smp.Cpus[Index].ApicId == ApicId)
        {
            return Index;
        }
    }

    return ApicId;
}

void
InitializeSmp(SysErr* __Err__)
{
    if (!EarlyLimineSmp.response)
    {
        LOGLIMINESMPC_PWarn("BSP only\n");
        atomic_store_explicit((_Atomic uint32_t*)&Smp.CpuCount, 1u, memory_order_seq_cst);
        atomic_store_explicit((_Atomic uint32_t*)&Smp.OnlineCpus, 1u, memory_order_seq_cst);
        atomic_store_explicit((_Atomic uint32_t*)&Smp.BspApicId, 0u, memory_order_seq_cst);
        atomic_store_explicit((_Atomic uint32_t*)&Smp.Cpus[0].ApicId, 0u, memory_order_seq_cst);
        atomic_store_explicit((_Atomic uint32_t*)&Smp.Cpus[0].CpuNumber, 0u, memory_order_seq_cst);
        atomic_store_explicit(
            (_Atomic uint32_t*)&Smp.Cpus[0].Status, CPU_STATUS_ONLINE, memory_order_seq_cst);
        atomic_store_explicit((_Atomic uint32_t*)&Smp.Cpus[0].Started, 1u, memory_order_seq_cst);
        return;
    }

    struct limine_smp_response* SmpResponse = EarlyLimineSmp.response;

    LOGLIMINESMPC_PInfo("via Limine detected %u CPU(s)\n", SmpResponse->cpu_count);
    LOGLIMINESMPC_PInfo("BootStrap LAPIC ID: %u\n", SmpResponse->bsp_lapic_id);

    atomic_store_explicit(
        (_Atomic uint32_t*)&Smp.CpuCount, (uint32_t)SmpResponse->cpu_count, memory_order_seq_cst);
    atomic_store_explicit(
        (_Atomic uint32_t*)&Smp.OnlineCpus, 1u, memory_order_seq_cst); /* BSP is already online */
    atomic_store_explicit(
        (_Atomic uint32_t*)&Smp.BspApicId, SmpResponse->bsp_lapic_id, memory_order_seq_cst);
    atomic_store_explicit((_Atomic uint32_t*)&CpuStartupCount, 0u, memory_order_seq_cst);

    if (SmpResponse->cpu_count == 1)
    {
        LOGLIMINESMPC_PWarn("UniProcessor\n");
        return;
    }

    /*Set all CPU Data*/
    if (SetApStack(__Err__) != true)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("InitializeSmp", LOGLIMINESMPC_PError, "failed to set AP stack", -NotInitilized);
        return;
    }
    if (InitCoreAps(__Err__) != true)
    {
        SlotError(__Err__, -NotInitilized);
        PushError(
            "InitializeSmp", LOGLIMINESMPC_PError, "failed to set AP IDT/GDT/TSS", -NotInitilized);
        return;
    }

    for (uint32_t Index = 0; Index < MaxCPUs; Index++)
    {
        atomic_store_explicit(
            (_Atomic uint32_t*)&Smp.Cpus[Index].Status, CPU_STATUS_OFFLINE, memory_order_seq_cst);
        atomic_store_explicit(
            (_Atomic uint32_t*)&Smp.Cpus[Index].Started, 0u, memory_order_seq_cst);
        atomic_store_explicit((_Atomic(struct limine_smp_info*)*)&Smp.Cpus[Index].LimineInfo,
                              (struct limine_smp_info*)NULL,
                              memory_order_seq_cst);
    }

    uint32_t StartedAps = 0;
    for (uint64_t Index = 0; Index < SmpResponse->cpu_count; Index++)
    {
        struct limine_smp_info* CpuInfo = SmpResponse->cpus[Index];

        atomic_store_explicit(
            (_Atomic uint32_t*)&Smp.Cpus[Index].ApicId, CpuInfo->lapic_id, memory_order_seq_cst);
        atomic_store_explicit(
            (_Atomic uint32_t*)&Smp.Cpus[Index].CpuNumber, (uint32_t)Index, memory_order_seq_cst);
        atomic_store_explicit((_Atomic(struct limine_smp_info*)*)&Smp.Cpus[Index].LimineInfo,
                              CpuInfo,
                              memory_order_seq_cst);

        if (CpuInfo->lapic_id == SmpResponse->bsp_lapic_id)
        {
            atomic_store_explicit((_Atomic uint32_t*)&Smp.Cpus[Index].Status,
                                  CPU_STATUS_ONLINE,
                                  memory_order_seq_cst);
            atomic_store_explicit(
                (_Atomic uint32_t*)&Smp.Cpus[Index].Started, 1u, memory_order_seq_cst);
            LOGLIMINESMPC_PDebug("BSP CPU %u (LAPIC ID %u)\n", (uint32_t)Index, CpuInfo->lapic_id);
            continue;
        }
        else
        {
            atomic_store_explicit((_Atomic uint32_t*)&Smp.Cpus[Index].Status,
                                  CPU_STATUS_STARTING,
                                  memory_order_seq_cst);
            CpuInfo->goto_address = ApEntryPoint; /* Set AP entry point (limine struct field) */
            StartedAps++;
            LOGLIMINESMPC_PInfo(
                "Starting AP %u (LAPIC ID %u)\n", (uint32_t)Index, CpuInfo->lapic_id);
        }
    }

    if (StartedAps > 0)
    {
        LOGLIMINESMPC_PInfo("Waiting for %u APs to start...\n", StartedAps);

#define ApCountTimeout 999999999 /* Large timeout value for AP startup */
        uint32_t Timeout = ApCountTimeout;

        while (atomic_load_explicit((_Atomic uint32_t*)&CpuStartupCount, memory_order_seq_cst) <
                   StartedAps &&
               Timeout > 0)
        {
            __asm__ volatile("pause");
            Timeout--;
        }

        uint32_t started =
            atomic_load_explicit((_Atomic uint32_t*)&CpuStartupCount, memory_order_seq_cst);
        if (started > StartedAps)
        {
            LOGLIMINESMPC_PWarn("%u out of %u APs started!\n", started, StartedAps);
        }
        else
        {
            LOGLIMINESMPC_PSuccess("%u out of %u APs started successfully\n", started, StartedAps);
        }
    }
}