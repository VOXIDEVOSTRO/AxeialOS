#include <Timer.h>
#include <__AXEKCONF__.h>

#ifdef LOGMSRHELPERSC_Debug
#    define LOGMSRHELPERSC_PDebug(fmt, ...) PDebug("[KERNEL>>MSRhelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSRHELPERSC_PDebug(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSRHELPERSC_Logs
#    define LOGMSRHELPERSC_PError(fmt, ...) PError("[KERNEL>>MSRhelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSRHELPERSC_PError(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSRHELPERSC_Logs
#    define LOGMSRHELPERSC_PWarn(fmt, ...) PWarn("[KERNEL>>MSRhelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSRHELPERSC_PWarn(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSRHELPERSC_Logs
#    define LOGMSRHELPERSC_PInfo(fmt, ...) PInfo("[KERNEL>>MSRhelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSRHELPERSC_PInfo(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSRHELPERSC_Logs
#    define LOGMSRHELPERSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>MSRhelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSRHELPERSC_PSuccess(fmt, ...)                                                      \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

uint64_t
ReadMsr(uint32_t __Msr__)
{
    uint32_t Low, High;

    __asm__ volatile("rdmsr" : "=a"(Low), "=d"(High) : "c"(__Msr__));

    return ((uint64_t)High << 32) | Low;
}

void
WriteMsr(uint32_t __Msr__, uint64_t __Value__)
{
    uint32_t Low  = (uint32_t)__Value__;
    uint32_t High = (uint32_t)(__Value__ >> 32);

    __asm__ volatile("wrmsr" : : "a"(Low), "d"(High), "c"(__Msr__));
}
