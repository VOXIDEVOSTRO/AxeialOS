#include <APICTimer.h>
#include <LimineSMP.h>
#include <PerCPUData.h>
#include <SymAP.h>
#include <Timer.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGAPICC_Debug
#    define LOGAPICC_PDebug(fmt, ...) PDebug("[KERNEL>>APIC.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPICC_PDebug(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPICC_Logs
#    define LOGAPICC_PError(fmt, ...) PError("[KERNEL>>APIC.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPICC_PError(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPICC_Logs
#    define LOGAPICC_PWarn(fmt, ...) PWarn("[KERNEL>>APIC.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPICC_PWarn(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPICC_Logs
#    define LOGAPICC_PInfo(fmt, ...) PInfo("[KERNEL>>APIC.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPICC_PInfo(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGAPICC_Logs
#    define LOGAPICC_PSuccess(fmt, ...) PSuccess("[KERNEL>>APIC.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGAPICC_PSuccess(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

static int
CheckApicSupport(void)
{
    uint32_t Eax, Ebx, Ecx, Edx;

    __asm__ volatile("cpuid" : "=a"(Eax), "=b"(Ebx), "=c"(Ecx), "=d"(Edx) : "a"(1));

    if (!(Edx & (1 << 9)))
    {
        PushError("CheckApicSupport",
                  LOGAPICC_PError,
                  "CPU does not support APIC (CPUID.1:EDX.APIC = 0)",
                  -Impilict);
        return -Impilict;
    }

    LOGAPICC_PDebug("CPU supports APIC (CPUID.1:EDX.APIC = 1)\n");
    return SysOkay;
}

int
DetectApicTimer(void)
{
    if (CheckApicSupport() != SysOkay)
    {
        PushError("DetectApicTimer", LOGAPICC_PError, "APIC support check failed", -Impilict);
        return -Impilict;
    }

    uint64_t ApicBaseMsrValue = ReadMsr(TimerApicBaseMsr);
    LOGAPICC_PDebug("Base MSR = 0x%016llX\n", ApicBaseMsrValue);

    if (!(ApicBaseMsrValue & TimerApicBaseEnable))
    {
        ApicBaseMsrValue |= TimerApicBaseEnable;
        WriteMsr(TimerApicBaseMsr, ApicBaseMsrValue);

        ApicBaseMsrValue = ReadMsr(TimerApicBaseMsr);
        if (!(ApicBaseMsrValue & TimerApicBaseEnable))
        {
            PushError("DetectApicTimer", LOGAPICC_PError, "Failed to enable APIC", -NotCanonical);
            return -NotCanonical;
        }
        LOGAPICC_PDebug("APIC Successfully enabled\n");
    }

    uint64_t ApicPhysBase = ApicBaseMsrValue & 0xFFFFF000;
    Timer.ApicBase        = (uint64_t)PhysToVirt(ApicPhysBase);
    LOGAPICC_PDebug(
        "Physical base = 0x%016llX, Virtual base = 0x%016llX\n", ApicPhysBase, Timer.ApicBase);

    volatile uint32_t* ApicVersionReg = (volatile uint32_t*)(Timer.ApicBase + TimerApicRegVersion);
    uint32_t           VersionValue   = *ApicVersionReg;

    if (VersionValue == 0xFFFFFFFF || VersionValue == 0x00000000)
    {
        PushError("DetectApicTimer", LOGAPICC_PError, "bad APIC version value", -NotCanonical);
        return -NotCanonical;
    }

    uint32_t ApicVersion = VersionValue & 0xFF;
    uint32_t MaxLvtEntry = (VersionValue >> 16) & 0xFF;

    LOGAPICC_PDebug("Version = 0x%02X, Max LVT = %u\n", ApicVersion, MaxLvtEntry);

    if (MaxLvtEntry < 3)
    {
        PushError(
            "DetectApicTimer", LOGAPICC_PError, "APIC does not support timer LVT entry", -Impilict);
        return -Impilict;
    }

    return SysOkay;
}

int
SetupApicTimer(uint32_t __CpuId__, bool __IsBsp__)
{
    _Atomic uint64_t ApicBaseMsrValue = ReadMsr(TimerApicBaseMsr);
    if (!(atomic_load_explicit(&ApicBaseMsrValue, memory_order_acquire) & TimerApicBaseEnable))
    {
        atomic_fetch_or_explicit(&ApicBaseMsrValue, TimerApicBaseEnable, memory_order_acq_rel);
        WriteMsr(TimerApicBaseMsr, atomic_load_explicit(&ApicBaseMsrValue, memory_order_acquire));
        atomic_store_explicit(&ApicBaseMsrValue, ReadMsr(TimerApicBaseMsr), memory_order_release);

        if (!(atomic_load_explicit(&ApicBaseMsrValue, memory_order_acquire) & TimerApicBaseEnable))
        {
            PushError("SetupApicTimer", LOGAPICC_PError, "Failed to enable APIC", -NotCanonical);
            return -NotCanonical;
        }
        LOGAPICC_PDebug("CPU %u: APIC enabled\n", __CpuId__);
    }
    _Atomic uint64_t ApicPhysBase =
        atomic_load_explicit(&ApicBaseMsrValue, memory_order_acquire) & 0xFFFFF000ULL;
    PerCpuData* CpuData = GetPerCpuData(__CpuId__);
    atomic_store_explicit(
        (_Atomic uint64_t*)&CpuData->ApicBase,
        (uint64_t)PhysToVirt(atomic_load_explicit(&ApicPhysBase, memory_order_acquire)),
        memory_order_release);
    if (__IsBsp__)
    {
        atomic_store_explicit(
            (_Atomic uint64_t*)&Timer.ApicBase,
            atomic_load_explicit((_Atomic uint64_t*)&CpuData->ApicBase, memory_order_acquire),
            memory_order_release);
    }
    LOGAPICC_PDebug("CPU %u: LAPIC base phys=0x%llx virt=0x%llx\n",
                    __CpuId__,
                    (unsigned long long)atomic_load_explicit(&ApicPhysBase, memory_order_acquire),
                    (unsigned long long)atomic_load_explicit((_Atomic uint64_t*)&CpuData->ApicBase,
                                                             memory_order_acquire));
    _Atomic volatile uint32_t* SpuriousReg =
        (_Atomic volatile uint32_t*)(CpuData->ApicBase + TimerApicRegSpuriousInt);
    _Atomic volatile uint32_t* LvtTimer =
        (_Atomic volatile uint32_t*)(CpuData->ApicBase + TimerApicRegLvtTimer);
    _Atomic volatile uint32_t* TimerDivide =
        (_Atomic volatile uint32_t*)(CpuData->ApicBase + TimerApicRegTimerDivide);
    _Atomic volatile uint32_t* TimerInitCount =
        (_Atomic volatile uint32_t*)(CpuData->ApicBase + TimerApicRegTimerInitCount);
    _Atomic volatile uint32_t* TimerCurrCount =
        (_Atomic volatile uint32_t*)(CpuData->ApicBase + TimerApicRegTimerCurrCount);
    _Atomic volatile uint32_t* EoiReg =
        (_Atomic volatile uint32_t*)(CpuData->ApicBase + TimerApicRegEoi);
    _Atomic volatile uint32_t* TprReg = (_Atomic volatile uint32_t*)(CpuData->ApicBase + 0x080);
    atomic_store_explicit(TimerInitCount, 0, memory_order_release);
    atomic_store_explicit(LvtTimer, TimerApicTimerMasked, memory_order_release);
    atomic_store_explicit(TprReg, 0, memory_order_release);
    *EoiReg = 0;
    atomic_store_explicit(SpuriousReg, 0x100 | 0xFF, memory_order_release);
    atomic_store_explicit(TimerDivide, TimerApicTimerDivideBy16, memory_order_release);

    if (__IsBsp__)
    {
        atomic_store_explicit(LvtTimer, TimerVector | TimerApicTimerMasked, memory_order_release);
        atomic_store_explicit(TimerInitCount, 0xFFFFFFFF, memory_order_release);
        atomic_store_explicit(LvtTimer, TimerVector | TimerApicTimerPeriodic, memory_order_release);
        uint32_t StartCount = atomic_load_explicit(TimerCurrCount, memory_order_acquire);
#define BusyWait 10000
        for (uint32_t I = 0; I < BusyWait; I++)
        {
            __asm__ volatile("outb %%al, $0x80" : : "a"((uint8_t)0));
        }
        uint32_t EndCount    = atomic_load_explicit(TimerCurrCount, memory_order_acquire);
        uint32_t TicksIn10ms = StartCount - EndCount;

        atomic_store_explicit((_Atomic uint32_t*)&Timer.TimerFrequency,
                              (TicksIn10ms ? TicksIn10ms * 100 : 100000000),
                              memory_order_release);

        atomic_store_explicit(LvtTimer, TimerApicTimerMasked, memory_order_release);
    }
    uint32_t TimerFreq =
        atomic_load_explicit((_Atomic uint32_t*)&Timer.TimerFrequency, memory_order_acquire);
    uint32_t InitialCount = TimerFreq / TimerTargetFrequency;
    if (InitialCount == 0)
    {
        InitialCount = 1;
    }
    atomic_store_explicit(TimerInitCount, InitialCount, memory_order_release);

    atomic_store_explicit((_Atomic bool*)&CpuData->TimerActive, true, memory_order_release);
    atomic_store_explicit(
        (_Atomic uint32_t*)&CpuData->TimerFrequency, TimerFreq, memory_order_release);
    LOGAPICC_PSuccess("CPU %u: APIC timer configured at %u Hz\n", __CpuId__, TimerFreq);
    atomic_store_explicit(LvtTimer, TimerVector | TimerApicTimerPeriodic, memory_order_release);
    return SysOkay;
}