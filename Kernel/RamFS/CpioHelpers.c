#include <AllTypes.h>
#include <__AXEKCONF__.h>

#ifdef LOGCPIOHELPERSC_Debug
#    define LOGCPIOHELPERSC_PDebug(fmt, ...) PDebug("[KERNEL>>CpioHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGCPIOHELPERSC_PDebug(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGCPIOHELPERSC_Logs
#    define LOGCPIOHELPERSC_PError(fmt, ...) PError("[KERNEL>>CpioHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGCPIOHELPERSC_PError(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGCPIOHELPERSC_Logs
#    define LOGCPIOHELPERSC_PWarn(fmt, ...) PWarn("[KERNEL>>CpioHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGCPIOHELPERSC_PWarn(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGCPIOHELPERSC_Logs
#    define LOGCPIOHELPERSC_PInfo(fmt, ...) PInfo("[KERNEL>>CpioHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGCPIOHELPERSC_PInfo(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGCPIOHELPERSC_Logs
#    define LOGCPIOHELPERSC_PSuccess(fmt, ...)                                                     \
        PSuccess("[KERNEL>>CpioHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGCPIOHELPERSC_PSuccess(fmt, ...)                                                     \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

uint32_t
CpioAlignUp(uint32_t __Value__, uint32_t __Align__)
{
    return (__Value__ + (__Align__ - 1)) & ~(__Align__ - 1);
}

uint32_t
CpioParseHex(const char* __Hex__)
{
    uint32_t Value = 0;
    for (uint32_t Index = 0; Index < 8; Index++)
    {
        char     C = __Hex__[Index];
        uint32_t D = 0;

        if (C >= '0' && C <= '9')
        {
            D = (uint32_t)(C - '0');
        }
        else if (C >= 'a' && C <= 'f')
        {
            D = (uint32_t)(C - 'a' + 10);
        }
        else if (C >= 'A' && C <= 'F')
        {
            D = (uint32_t)(C - 'A' + 10);
        }

        Value = (Value << 4) | D;
    }
    return Value;
}
