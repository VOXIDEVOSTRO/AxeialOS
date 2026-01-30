#include <AllTypes.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGBSPPagesC_Debug
#    define LOGBSPPagesC_PDebug(fmt, ...) PDebug("[KERNEL>>BSPPages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBSPPagesC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBSPPagesC_Logs
#    define LOGBSPPagesC_PError(fmt, ...) PError("[KERNEL>>BSPPages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBSPPagesC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBSPPagesC_Logs
#    define LOGBSPPagesC_PWarn(fmt, ...) PWarn("[KERNEL>>BSPPages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBSPPagesC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBSPPagesC_Logs
#    define LOGBSPPagesC_PInfo(fmt, ...) PInfo("[KERNEL>>BSPPages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBSPPagesC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBSPPagesC_Logs
#    define LOGBSPPagesC_PSuccess(fmt, ...) PSuccess("[KERNEL>>BSPPages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBSPPagesC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
GlobalizePerCPUMem(SysErr* __Err__)
{
    uint64_t BSPCR3 = atomic_load_explicit(&BspKernelCr3, memory_order_acquire);

    if (BSPCR3 == 0)
    {
        SlotError(__Err__, -NotInitilized);
        PushError(
            "GlobalizePerCPUMem", LOGBSPPagesC_PError, "BSP CR3 not yet published", -NotInitilized);
        return;
    }
    __asm__ volatile("mov %0, %%cr3" ::"r"(BSPCR3) : "memory");
}
