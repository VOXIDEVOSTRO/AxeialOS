#include <Serial.h>
#include <__AXEKCONF__.h>

#ifdef LOGSERIALC_Debug
#    define LOGSERIALC_PDebug(fmt, ...) PDebug("[KERNEL>>Serial.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALC_Logs
#    define LOGSERIALC_PError(fmt, ...) PError("[KERNEL>>Serial.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALC_Logs
#    define LOGSERIALC_PWarn(fmt, ...) PWarn("[KERNEL>>Serial.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALC_Logs
#    define LOGSERIALC_PInfo(fmt, ...) PInfo("[KERNEL>>Serial.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSERIALC_Logs
#    define LOGSERIALC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Serial.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSERIALC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
InitializeSerial(void)
{
    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0x00), "Nd"((uint16_t)(SerialPort1 + SerialIntEnableReg)));

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0x80), "Nd"((uint16_t)(SerialPort1 + SerialLineCtrlReg)));

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0x03), "Nd"((uint16_t)(SerialPort1 + SerialDataReg)));

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0x00), "Nd"((uint16_t)(SerialPort1 + SerialIntEnableReg)));

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0x03), "Nd"((uint16_t)(SerialPort1 + SerialLineCtrlReg)));

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0xC7), "Nd"((uint16_t)(SerialPort1 + SerialFifoCtrlReg)));

    __asm__ volatile("outb %0, %1"
                     :
                     : "a"((uint8_t)0x0B), "Nd"((uint16_t)(SerialPort1 + SerialModemCtrlReg)));
}
