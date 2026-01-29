#include <Timer.h>
#include <__AXEKCONF__.h>

#ifdef LOGPITC_Debug
#    define LOGPITC_PDebug(fmt, ...) PDebug("[KERNEL>>PIT.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPITC_PDebug(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPITC_Logs
#    define LOGPITC_PError(fmt, ...) PError("[KERNEL>>PIT.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPITC_PError(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPITC_Logs
#    define LOGPITC_PWarn(fmt, ...) PWarn("[KERNEL>>PIT.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPITC_PWarn(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPITC_Logs
#    define LOGPITC_PInfo(fmt, ...) PInfo("[KERNEL>>PIT.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPITC_PInfo(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPITC_Logs
#    define LOGPITC_PSuccess(fmt, ...) PSuccess("[KERNEL>>PIT.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPITC_PSuccess(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#define BaseFreqTimer 1193182

int
InitializePitTimer(void)
{
    uint16_t Divisor = BaseFreqTimer /* PIT base frequency */ / TimerTargetFrequency;
    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)0x36), "Nd"((uint16_t)0x43));
    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)(Divisor & 0xFF)), "Nd"((uint16_t)0x40));
    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)(Divisor >> 8)), "Nd"((uint16_t)0x40));
    Timer.TimerFrequency = TimerTargetFrequency;
    LOGPITC_PSuccess("PIT Timer initialized at %u Hz\n", Timer.TimerFrequency);

    return SysOkay;
}
