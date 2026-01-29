#include <APICTimer.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <HPETTimer.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <SymAP.h>
#include <Timer.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGTIMERCTLC_Debug
#    define LOGTIMERCTLC_PDebug(fmt, ...) PDebug("[KERNEL>>TimerCtl.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTIMERCTLC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTIMERCTLC_Logs
#    define LOGTIMERCTLC_PError(fmt, ...) PError("[KERNEL>>TimerCtl.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTIMERCTLC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTIMERCTLC_Logs
#    define LOGTIMERCTLC_PWarn(fmt, ...) PWarn("[KERNEL>>TimerCtl.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTIMERCTLC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTIMERCTLC_Logs
#    define LOGTIMERCTLC_PInfo(fmt, ...) PInfo("[KERNEL>>TimerCtl.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTIMERCTLC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTIMERCTLC_Logs
#    define LOGTIMERCTLC_PSuccess(fmt, ...) PSuccess("[KERNEL>>TimerCtl.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTIMERCTLC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

TimerManager Timer;

volatile uint32_t TimerInterruptCount = 0;

void
InitializeTimer(bool __IsBSP__, SysErr* __Err__)
{
    if (__IsBSP__) /*BSP*/
    {
        Timer.ActiveTimer      = TIMER_TYPE_NONE;
        Timer.SystemTicks      = 0;
        Timer.TimerInitialized = false;

        if (SetupApicTimer(GetCurrentCpuId(), true) == SysOkay)
        {
            Timer.ActiveTimer      = TIMER_TYPE_APIC;
            Timer.TimerInitialized = true;
        }
        else if (DetectHpetTimer() == SysOkay && InitializeHpetTimer() == SysOkay)
        {
            Timer.ActiveTimer      = TIMER_TYPE_HPET;
            Timer.TimerInitialized = true;
        }
        else if (InitializePitTimer() == SysOkay)
        {
            Timer.ActiveTimer      = TIMER_TYPE_PIT;
            Timer.TimerInitialized = true;
        }
        else
        {
            SlotError(__Err__, -NotInitilized);
            PushError("InitializeTimer",
                      LOGTIMERCTLC_PError,
                      "failed to initialize any timer on BSP",
                      -NotInitilized);
            return;
        }
    }
    else /*APs*/
    {
        if (SetupApicTimer(GetCurrentCpuId(), false) == SysOkay)
        {
            GetPerCpuData(GetCurrentCpuId())->TimerActive = true;
        }
        else if (DetectHpetTimer() == SysOkay && InitializeHpetTimer() == SysOkay)
        {
            GetPerCpuData(GetCurrentCpuId())->TimerActive = true;
        }
        else if (InitializePitTimer() == SysOkay)
        {
            GetPerCpuData(GetCurrentCpuId())->TimerActive = true;
        }
        else
        {
            SlotError(__Err__, -NotInitilized);
            PushError("InitializeTimer",
                      LOGTIMERCTLC_PError,
                      "failed to initialize any timer on AP",
                      -NotInitilized);
            return;
        }
    }

    LOGTIMERCTLC_PSuccess("Timer system initialized using %s\n",
                          Timer.ActiveTimer == TIMER_TYPE_HPET   ? "HPET"
                          : Timer.ActiveTimer == TIMER_TYPE_APIC ? "APIC"
                                                                 : "PIT");

    __asm__ volatile("sti");
}

void
TimerHandler(InterruptFrame* __Frame__, SysErr* __Err__)
{
    uint32_t    CpuId   = GetCurrentCpuId();
    PerCpuData* CpuData = GetPerCpuData(CpuId);

    __atomic_fetch_add(&CpuData->LocalInterrupts, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&CpuData->LocalTicks, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&TimerInterruptCount, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&Timer.SystemTicks, 1, __ATOMIC_SEQ_CST);

#ifdef TimerIntTrace
    if ((TimerInterruptCount % InEveryInt) == 0)
    {
        LOGTIMERCTLC_PDebug(
            "Timer interrupt #%llu on CPU %u\n", (unsigned long long)TimerInterruptCount, CpuId);
    }
#endif

    Schedule(CpuId, __Frame__, __Err__);

    /*EOI*/
    if (CpuId == 0) /*BSP*/
    {
        volatile uint32_t* EoiReg = (volatile uint32_t*)(Timer.ApicBase + TimerApicRegEoi);
        *EoiReg                   = 0;
    }
    else /*AP*/
    {
        volatile uint32_t* EoiReg = (volatile uint32_t*)(CpuData->ApicBase + TimerApicRegEoi);
        *EoiReg                   = 0;
    }
}

uint64_t
GetSystemTicks(void)
{
    return Timer.SystemTicks;
}

void
Sleep(uint32_t __Milliseconds__, SysErr* __Err__)
{
    if (!Timer.TimerInitialized)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("Sleep", LOGTIMERCTLC_PError, "timer not initialized", -NotInitilized);
        return;
    }

    uint64_t StartTicks = Timer.SystemTicks;
    uint64_t EndTicks   = StartTicks + __Milliseconds__;

    while (Timer.SystemTicks < EndTicks)
    {
        __asm__ volatile("hlt");
    }
}

uint32_t
GetTimerInterruptCount(void)
{
    return TimerInterruptCount;
}
