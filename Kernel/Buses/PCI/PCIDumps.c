#include <KHeap.h>
#include <KrnPrintf.h>
#include <PCIBus.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGPCIDUMPSC_Debug
#    define LOGPCIDUMPSC_PDebug(fmt, ...) PDebug("[KERNEL>>PCIDumps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIDUMPSC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIDUMPSC_Logs
#    define LOGPCIDUMPSC_PError(fmt, ...) PError("[KERNEL>>PCIDumps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIDUMPSC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIDUMPSC_Logs
#    define LOGPCIDUMPSC_PWarn(fmt, ...) PWarn("[KERNEL>>PCIDumps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIDUMPSC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIDUMPSC_Logs
#    define LOGPCIDUMPSC_PInfo(fmt, ...) PInfo("[KERNEL>>PCIDumps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIDUMPSC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIDUMPSC_Logs
#    define LOGPCIDUMPSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>PCIDumps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIDUMPSC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
PciDumpDevice(PciDevice* __Device__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        SlotError(__Err__, -BadArguments);
        PushError("PciDumpDevice", LOGPCIDUMPSC_PError, "bad arguments", -BadArguments);
        return;
    }

    LOGPCIDUMPSC_PInfo(
        "PCI Device %02x:%02x.%x\n", __Device__->Bus, __Device__->Device, __Device__->Function);
    LOGPCIDUMPSC_PInfo(
        "  Vendor: %04x, Device: %04x\n", __Device__->VendorId, __Device__->DeviceId);
    LOGPCIDUMPSC_PInfo("  Class: %02x, SubClass: %02x, ProgIf: %02x\n",
                       __Device__->ClassCode,
                       __Device__->SubClass,
                       __Device__->ProgInterface);
    LOGPCIDUMPSC_PInfo("  Command: %04x, Status: %04x\n", __Device__->Command, __Device__->Status);

    for (uint8_t BarIndex = 0; BarIndex < 6; BarIndex++)
    {
        if (__Device__->Bars[BarIndex] != 0)
        {
            LOGPCIDUMPSC_PInfo("  BAR%u: %016llx (Size: %016llx, Type: %u)\n",
                               BarIndex,
                               __Device__->Bars[BarIndex],
                               __Device__->BarSizes[BarIndex],
                               __Device__->BarTypes[BarIndex]);
        }
    }
}

void
PciDumpAllDevices(SysErr* __Err__)
{
    if (!PciBus.Initialized)
    {
        SlotError(__Err__, -NotInitilized);
        PushError(
            "PciDumpAllDevices", LOGPCIDUMPSC_PError, "pci bus not initialized", -NotInitilized);
        return;
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PciBus.BusLock, Error);

    for (uint32_t DeviceIndex = 0; DeviceIndex < PciBus.DeviceCount; DeviceIndex++)
    {
        PciDumpDevice(&PciBus.Devices[DeviceIndex], __Err__);
    }

    ReleaseSpinLock(&PciBus.BusLock, Error);

    LOGPCIDUMPSC_PInfo("Total devices: %u\n", PciBus.DeviceCount);
}