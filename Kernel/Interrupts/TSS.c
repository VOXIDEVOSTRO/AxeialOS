#include <Errnos.h>
#include <GDT.h>
#include <SymAP.h>
#include <__AXEKCONF__.h>

#ifdef LOGTSSC_Debug
#    define LOGTSSC_PDebug(fmt, ...) PDebug("[KERNEL>>TSS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTSSC_PDebug(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTSSC_Logs
#    define LOGTSSC_PError(fmt, ...) PError("[KERNEL>>TSS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTSSC_PError(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTSSC_Logs
#    define LOGTSSC_PWarn(fmt, ...) PWarn("[KERNEL>>TSS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTSSC_PWarn(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTSSC_Logs
#    define LOGTSSC_PInfo(fmt, ...) PInfo("[KERNEL>>TSS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTSSC_PInfo(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTSSC_Logs
#    define LOGTSSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>TSS.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTSSC_PSuccess(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

TaskStateSegment Tss;

void
SetTssEntry(int __Index__, uint64_t __Base__, uint32_t __Limit__, SysErr* __Err__)
{
    /*First entry - Main TSS descriptor with lower 32 bits of base*/
    GdtEntries[__Index__].LimitLow    = __Limit__ & 0xFFFF;
    GdtEntries[__Index__].BaseLow     = __Base__ & 0xFFFF;
    GdtEntries[__Index__].BaseMiddle  = (__Base__ >> 16) & 0xFF;
    GdtEntries[__Index__].Access      = GdtAccessTss64; /*TSS access byte*/
    GdtEntries[__Index__].Granularity = ((__Limit__ >> 16) & 0x0F) | GdtGranTss64;
    GdtEntries[__Index__].BaseHigh    = (__Base__ >> 24) & 0xFF;

    /*Second entry - Upper 32 bits of base address*/
    GdtEntries[__Index__ + 1].LimitLow    = (__Base__ >> 32) & 0xFFFF;
    GdtEntries[__Index__ + 1].BaseLow     = (__Base__ >> 48) & 0xFFFF;
    GdtEntries[__Index__ + 1].BaseMiddle  = 0;
    GdtEntries[__Index__ + 1].Access      = 0;
    GdtEntries[__Index__ + 1].Granularity = 0;
    GdtEntries[__Index__ + 1].BaseHigh    = 0;

    LOGTSSC_PDebug("TSS[%d]: Base=0x%lx, Limit=0x%x\n", __Index__, __Base__, __Limit__);
}

void
InitializeTss(SysErr* __Err__)
{
    /*Defult all Zeros*/
    for (size_t Iteration = 0; Iteration < sizeof(TaskStateSegment); Iteration++)
    {
        ((uint8_t*)&Tss)[Iteration] = 0;
    }

    uint64_t CurrentStack;
    __asm__ volatile("mov %%rsp, %0" : "=r"(CurrentStack));

    Tss.Rsp0      = CurrentStack;             /*Stack pointer for privilege level 0*/
    Tss.IoMapBase = sizeof(TaskStateSegment); /*I/O permission bitmap offset*/

    SetTssEntry(GdtTssIndex, (uint64_t)&Tss, sizeof(TaskStateSegment) - 1, __Err__); /*2*/

    /*Store BSP TSS information in per-CPU arrays*/
    CpuTssSelectors[0]  = TssSelector;
    CpuTssStructures[0] = Tss;

    /*(TR)*/
    __asm__ volatile("ltr %0" : : "r"((uint16_t)TssSelector));

    LOGTSSC_PDebug("BSP TSS[5]: LimitLow=0x%04x, BaseLow=0x%04x, BaseMiddle=0x%02x, Access=0x%02x, "
                   "Gran=0x%02x, BaseHigh=0x%02x\n",
                   GdtEntries[5].LimitLow,
                   GdtEntries[5].BaseLow,
                   GdtEntries[5].BaseMiddle,
                   GdtEntries[5].Access,
                   GdtEntries[5].Granularity,
                   GdtEntries[5].BaseHigh);

    LOGTSSC_PDebug("BSP TSS[6]: LimitLow=0x%04x, BaseLow=0x%04x, BaseMiddle=0x%02x, Access=0x%02x, "
                   "Gran=0x%02x, BaseHigh=0x%02x\n",
                   GdtEntries[6].LimitLow,
                   GdtEntries[6].BaseLow,
                   GdtEntries[6].BaseMiddle,
                   GdtEntries[6].Access,
                   GdtEntries[6].Granularity,
                   GdtEntries[6].BaseHigh);

    LOGTSSC_PSuccess("TSS init... OK\n");
}
