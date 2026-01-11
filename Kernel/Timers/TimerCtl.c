#include <APICTimer.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <HPETTimer.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <SymAP.h>
#include <Timer.h>
#include <VMM.h>

TimerManager Timer;

volatile uint32_t TimerInterruptCount = 0;

void
InitializeTimer(SysErr* __Err__)
{
    Timer.ActiveTimer      = TIMER_TYPE_NONE;
    Timer.SystemTicks      = 0;
    Timer.TimerInitialized = 0;

    if (DetectApicTimer() == SysOkay && InitializeApicTimer() == SysOkay)
    {
        /* APIC timer successfully initialized */
    }

    else if (DetectHpetTimer() == SysOkay && InitializeHpetTimer() == SysOkay)
    {
        /* HPET timer successfully initialized */
    }

    else if (InitializePitTimer() == SysOkay)
    {
        /* PIT timer successfully initialized */
    }

    else
    {
        SlotError(__Err__, -NotInit);
        return;
    }

    Timer.TimerInitialized = 1;

    PSuccess("Timer system initialized using %s\n",
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

    WakeSleepingThreads(__Err__);
    Schedule(CpuId, __Frame__, __Err__);

    volatile uint32_t* EoiReg = (volatile uint32_t*)(CpuData->ApicBase + TimerApicRegEoi);
    *EoiReg                   = 0;
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
        SlotError(__Err__, -NotInit);
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
