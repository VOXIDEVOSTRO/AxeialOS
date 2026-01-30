#include <HPETTimer.h>
#include <Timer.h>
#include <__AXEKCONF__.h>

#ifdef LOGHPETC_Debug
#    define LOGHPETC_PDebug(fmt, ...) PDebug("[KERNEL>>HPET.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGHPETC_PDebug(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGHPETC_Logs
#    define LOGHPETC_PError(fmt, ...) PError("[KERNEL>>HPET.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGHPETC_PError(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGHPETC_Logs
#    define LOGHPETC_PWarn(fmt, ...) PWarn("[KERNEL>>HPET.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGHPETC_PWarn(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGHPETC_Logs
#    define LOGHPETC_PInfo(fmt, ...) PInfo("[KERNEL>>HPET.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGHPETC_PInfo(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGHPETC_Logs
#    define LOGHPETC_PSuccess(fmt, ...) PSuccess("[KERNEL>>HPET.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGHPETC_PSuccess(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
DetectHpetTimer(void)
{
    return SysOkay;
}

int
InitializeHpetTimer(void)
{
    return SysOkay;
}
