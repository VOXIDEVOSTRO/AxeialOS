#include <Serial.h>
#include <__AXEKCONF__.h>

#ifdef LOGSERIALPUTSC_Debug
#    define LOGSERIALPUTSC_PDebug(fmt, ...) PDebug("[KERNEL>>SerialPuts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALPUTSC_PDebug(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALPUTSC_Logs
#    define LOGSERIALPUTSC_PError(fmt, ...) PError("[KERNEL>>SerialPuts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALPUTSC_PError(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALPUTSC_Logs
#    define LOGSERIALPUTSC_PWarn(fmt, ...) PWarn("[KERNEL>>SerialPuts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALPUTSC_PWarn(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALPUTSC_Logs
#    define LOGSERIALPUTSC_PInfo(fmt, ...) PInfo("[KERNEL>>SerialPuts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALPUTSC_PInfo(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALPUTSC_Logs
#    define LOGSERIALPUTSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>SerialPuts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALPUTSC_PSuccess(fmt, ...)                                                      \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
SerialPutChar(char __Char__)
{
    uint8_t Status;
    do
    {
        __asm__ volatile("inb %1, %0"
                         : "=a"(Status)
                         : "Nd"((uint16_t)(SerialPort1 + SerialLineStatusReg)));
    } while ((Status & 0x20) == 0);

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)__Char__), "Nd"((uint16_t)(SerialPort1 + SerialDataReg)));
}

void
SerialPutString(const char* __String__)
{
    while (*__String__)
    {
        SerialPutChar(*__String__);
        __String__++;
    }
}
