#include <KHeap.h>
#include <KrnPrintf.h>
#include <PCIBus.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGMSIC_Debug
#    define LOGMSIC_PDebug(fmt, ...) PDebug("[KERNEL>>MSI.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSIC_PDebug(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSIC_Logs
#    define LOGMSIC_PError(fmt, ...) PError("[KERNEL>>MSI.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSIC_PError(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSIC_Logs
#    define LOGMSIC_PWarn(fmt, ...) PWarn("[KERNEL>>MSI.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSIC_PWarn(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSIC_Logs
#    define LOGMSIC_PInfo(fmt, ...) PInfo("[KERNEL>>MSI.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSIC_PInfo(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMSIC_Logs
#    define LOGMSIC_PSuccess(fmt, ...) PSuccess("[KERNEL>>MSI.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMSIC_PSuccess(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
PciEnableMsi(PciDevice* __Device__, uint64_t __Address__, uint32_t __Data__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        PushError("PciEnableMsi", LOGMSIC_PError, "bad device in arguments", -BadArguments);
        return -BadArguments;
    }

    if (__Device__->MsiCapOffset == 0)
    {
        PushError("PciEnableMsi", LOGMSIC_PError, "device has no MSI support", -NoSuch);
        return -NoSuch;
    }

    uint16_t MsiControl = PciConfigRead16(
        __Device__->Bus, __Device__->Device, __Device__->Function, __Device__->MsiCapOffset + 2);

    PciConfigWrite32(__Device__->Bus,
                     __Device__->Device,
                     __Device__->Function,
                     __Device__->MsiCapOffset + 4,
                     (uint32_t)__Address__);

    /*Check if 64-bit capable*/
    if (MsiControl & (1 << 7))
    {
        /*64-bit MSI*/
        PciConfigWrite32(__Device__->Bus,
                         __Device__->Device,
                         __Device__->Function,
                         __Device__->MsiCapOffset + 8,
                         (uint32_t)(__Address__ >> 32));
        PciConfigWrite16(__Device__->Bus,
                         __Device__->Device,
                         __Device__->Function,
                         __Device__->MsiCapOffset + 12,
                         (uint16_t)__Data__);
    }
    else
    {
        /*32-bit MSI*/
        PciConfigWrite16(__Device__->Bus,
                         __Device__->Device,
                         __Device__->Function,
                         __Device__->MsiCapOffset + 8,
                         (uint16_t)__Data__);
    }

    /*Enable MSI*/
    MsiControl |= (1 << 0);
    PciConfigWrite16(__Device__->Bus,
                     __Device__->Device,
                     __Device__->Function,
                     __Device__->MsiCapOffset + 2,
                     MsiControl);

    LOGMSIC_PDebug("Enabled MSI for device %02x:%02x.%x\n",
                   __Device__->Bus,
                   __Device__->Device,
                   __Device__->Function);
    return SysOkay;
}

int
PciDisableMsi(PciDevice* __Device__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        PushError("PciDisableMsi", LOGMSIC_PError, "bad device in arguments", -BadArguments);
        return -BadArguments;
    }

    if (__Device__->MsiCapOffset == 0)
    {
        PushError("PciDisableMsi", LOGMSIC_PError, "device has no MSI support", -NoSuch);
        return -NoSuch;
    }

    uint16_t MsiControl = PciConfigRead16(
        __Device__->Bus, __Device__->Device, __Device__->Function, __Device__->MsiCapOffset + 2);

    /*Disable MSI*/
    MsiControl &= ~(1 << 0);
    PciConfigWrite16(__Device__->Bus,
                     __Device__->Device,
                     __Device__->Function,
                     __Device__->MsiCapOffset + 2,
                     MsiControl);

    return SysOkay;
}
