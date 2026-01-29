#include <KHeap.h>
#include <KrnPrintf.h>
#include <PCIBus.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGPCIBUSC_Debug
#    define LOGPCIBUSC_PDebug(fmt, ...) PDebug("[KERNEL>>PCIBus.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIBUSC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIBUSC_Logs
#    define LOGPCIBUSC_PError(fmt, ...) PError("[KERNEL>>PCIBus.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIBUSC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIBUSC_Logs
#    define LOGPCIBUSC_PWarn(fmt, ...) PWarn("[KERNEL>>PCIBus.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIBUSC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIBUSC_Logs
#    define LOGPCIBUSC_PInfo(fmt, ...) PInfo("[KERNEL>>PCIBus.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIBUSC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPCIBUSC_Logs
#    define LOGPCIBUSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>PCIBus.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPCIBUSC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

PciBusManager PciBus = {0};

int
InitializePciBus(void)
{
    if (PciBus.Initialized)
    {
        PushError("InitializePciBus", LOGPCIBUSC_PError, "pci bus already initilized", -Redefined);
        return -Redefined;
    }

    PciBus.DeviceCapacity = MaxPciDevices;
    PciBus.DeviceCount    = 0;
    PciBus.Devices        = (PciDevice*)KMalloc(sizeof(PciDevice) * MaxPciDevices);

    if (Probe_IF_Error(PciBus.Devices) || !PciBus.Devices)
    {
        PushError("InitializePciBus",
                  LOGPCIBUSC_PError,
                  "can't allocate memory for pci devices",
                  Pointer_TO_Error(PciBus.Devices));
        return -BadAllocation;
    }

    for (uint32_t Index = 0; Index < MaxPciDevices; Index++)
    {
        ((uint8_t*)&PciBus.Devices[Index])[0] = 0;
        for (size_t ByteIndex = 1; ByteIndex < sizeof(PciDevice); ByteIndex++)
        {
            ((uint8_t*)&PciBus.Devices[Index])[ByteIndex] = 0;
        }
    }

    SysErr  err;
    SysErr* Error = &err;
    InitializeSpinLock(&PciBus.BusLock, "PCIBus", Error);

    LOGPCIBUSC_PDebug("PCI Bus Manager initialized\n");

    /*Scan all buses*/
    for (uint16_t BusNumber = 0; BusNumber < 256; BusNumber++)
    {
        PciScanBus(BusNumber, Error);
    }

    PciBus.Initialized = true;
    LOGPCIBUSC_PSuccess("PCI Bus initialized with %u devices\n", PciBus.DeviceCount);
    return SysOkay;
}

void
PciScanBus(uint8_t __BusNumber__, SysErr* __Err__)
{
    for (uint8_t Device = 0; Device < 32; Device++)
    {
        uint16_t VendorId = PciConfigRead16(__BusNumber__, Device, 0, 0x00);

        if (VendorId == 0xFFFF || VendorId == 0x0000)
        {
            continue;
        }

        PciProbeFunction(__BusNumber__, Device, 0);

        uint8_t HeaderType = PciConfigRead8(__BusNumber__, Device, 0, 0x0E);

        if (HeaderType & 0x80)
        {
            for (uint8_t Function = 1; Function < 8; Function++)
            {
                uint16_t FuncVendorId = PciConfigRead16(__BusNumber__, Device, Function, 0x00);

                if (FuncVendorId != 0xFFFF && FuncVendorId != 0x0000)
                {
                    PciProbeFunction(__BusNumber__, Device, Function);
                }
            }
        }
    }
}

PciDevice*
PciFindDevice(uint16_t __VendorId__, uint16_t __DeviceId__, uint32_t __Index__)
{
    if (!PciBus.Initialized)
    {
        PushError("PciFindDevice", LOGPCIBUSC_PError, "pci bus not initialized", -NotInitilized);
        return Error_TO_Pointer(-NotInitilized);
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PciBus.BusLock, Error);

    uint32_t Found = 0;
    for (uint32_t DeviceIndex = 0; DeviceIndex < PciBus.DeviceCount; DeviceIndex++)
    {
        PciDevice* Device = &PciBus.Devices[DeviceIndex];

        if (Device->VendorId == __VendorId__ && Device->DeviceId == __DeviceId__)
        {
            if (Found == __Index__)
            {
                ReleaseSpinLock(&PciBus.BusLock, Error);
                return Device;
            }
            Found++;
        }
    }

    ReleaseSpinLock(&PciBus.BusLock, Error);
    PushError("PciFindDevice", LOGPCIBUSC_PError, "cannot find such pci device", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

PciDevice*
PciGetDevice(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__)
{
    if (!PciBus.Initialized)
    {
        PushError("PciGetDevice", LOGPCIBUSC_PError, "pci bus not initialized", -NotInitilized);
        return Error_TO_Pointer(-NotInitilized);
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PciBus.BusLock, Error);

    for (uint32_t DeviceIndex = 0; DeviceIndex < PciBus.DeviceCount; DeviceIndex++)
    {
        PciDevice* Device = &PciBus.Devices[DeviceIndex];

        if (Device->Bus == __Bus__ && Device->Device == __Device__ &&
            Device->Function == __Function__)
        {
            ReleaseSpinLock(&PciBus.BusLock, Error);
            return Device;
        }
    }

    ReleaseSpinLock(&PciBus.BusLock, Error);
    PushError("PciGetDevice", LOGPCIBUSC_PError, "cannot find such pci device", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

PciDevice*
PciFindByClass(uint8_t __ClassCode__, uint8_t __SubClass__, uint32_t __Index__)
{
    if (!PciBus.Initialized)
    {
        PushError("PciFindByClass", LOGPCIBUSC_PError, "pci bus not initialized", -NotInitilized);
        return Error_TO_Pointer(-NotInitilized);
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PciBus.BusLock, Error);

    uint32_t Found = 0;
    for (uint32_t DeviceIndex = 0; DeviceIndex < PciBus.DeviceCount; DeviceIndex++)
    {
        PciDevice* Device = &PciBus.Devices[DeviceIndex];

        if (Device->ClassCode == __ClassCode__ && Device->SubClass == __SubClass__)
        {
            if (Found == __Index__)
            {
                ReleaseSpinLock(&PciBus.BusLock, Error);
                return Device;
            }
            Found++;
        }
    }

    ReleaseSpinLock(&PciBus.BusLock, Error);
    PushError("PciFindByClass", LOGPCIBUSC_PError, "cannot find such pci device", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

int
PciEnableBusMastering(PciDevice* __Device__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        PushError("PciEnableBusMastering", LOGPCIBUSC_PError, "bad pci device", -BadArguments);
        return -BadArguments;
    }

    uint16_t Command =
        PciConfigRead16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04);
    Command |= (1 << 2);
    PciConfigWrite16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04, Command);
    __Device__->Command = Command;

    LOGPCIBUSC_PDebug("Enabled bus mastering for device %02x:%02x.%x\n",
                      __Device__->Bus,
                      __Device__->Device,
                      __Device__->Function);
    return SysOkay;
}

int
PciDisableBusMastering(PciDevice* __Device__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        PushError("PciDisableBusMastering", LOGPCIBUSC_PError, "bad pci device", -BadArguments);
        return -BadArguments;
    }

    uint16_t Command =
        PciConfigRead16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04);
    Command &= ~(1 << 2);
    PciConfigWrite16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04, Command);
    __Device__->Command = Command;
    return SysOkay;
}

int
PciEnableMemorySpace(PciDevice* __Device__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        PushError("PciEnableMemorySpace", LOGPCIBUSC_PError, "bad pci device", -BadArguments);
        return -BadArguments;
    }

    uint16_t Command =
        PciConfigRead16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04);
    Command |= (1 << 1);
    PciConfigWrite16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04, Command);
    __Device__->Command = Command;
    return SysOkay;
}

int
PciEnableIoSpace(PciDevice* __Device__)
{
    if (Probe_IF_Error(__Device__) || !__Device__)
    {
        PushError("PciEnableIoSpace", LOGPCIBUSC_PError, "bad pci device", -BadArguments);
        return -BadArguments;
    }

    uint16_t Command =
        PciConfigRead16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04);
    Command |= (1 << 0);
    PciConfigWrite16(__Device__->Bus, __Device__->Device, __Device__->Function, 0x04, Command);
    __Device__->Command = Command;
    return SysOkay;
}

uint64_t
PciGetBarAddress(PciDevice* __Device__, uint8_t __BarIndex__)
{
    if (Probe_IF_Error(__Device__) || !__Device__ || __BarIndex__ >= 6)
    {
        PushError("PciGetBarAddress", LOGPCIBUSC_PError, "bad args", -BadArguments);
        return Nothing;
    }

    return __Device__->Bars[__BarIndex__];
}

uint64_t
PciGetBarSize(PciDevice* __Device__, uint8_t __BarIndex__)
{
    if (Probe_IF_Error(__Device__) || !__Device__ || __BarIndex__ >= 6)
    {
        PushError("PciGetBarSize", LOGPCIBUSC_PError, "bad args", -BadArguments);
        return Nothing;
    }

    return __Device__->BarSizes[__BarIndex__];
}

uint32_t
PciGetBarType(PciDevice* __Device__, uint8_t __BarIndex__)
{
    if (Probe_IF_Error(__Device__) || !__Device__ || __BarIndex__ >= 6)
    {
        PushError("PciGetBarType", LOGPCIBUSC_PError, "bad args", -BadArguments);
        return Nothing;
    }

    return (uint32_t)__Device__->BarTypes[__BarIndex__];
}

uint32_t
PciMakeAddress(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__)
{
    return (1U << 31) | (((uint32_t)__Bus__) << 16) | (((uint32_t)__Device__) << 11) |
           (((uint32_t)__Function__) << 8) | (__Offset__ & 0xFC);
}

int
PciProbeFunction(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__)
{
    PciDevice Device = {0};

    Device.Bus      = __Bus__;
    Device.Device   = __Device__;
    Device.Function = __Function__;

    uint32_t VendorDevice = PciConfigRead32(__Bus__, __Device__, __Function__, 0x00);
    Device.VendorId       = (uint16_t)(VendorDevice & 0xFFFF);
    Device.DeviceId       = (uint16_t)(VendorDevice >> 16);

    if (Device.VendorId == 0xFFFF || Device.VendorId == 0x0000)
    {
        PushError("PciProbeFunction", LOGPCIBUSC_PError, "no device at this location", -NoSuch);
        return -NoSuch;
    }

    uint32_t ClassRev    = PciConfigRead32(__Bus__, __Device__, __Function__, 0x08);
    Device.Revision      = (uint8_t)(ClassRev & 0xFF);
    Device.ProgInterface = (uint8_t)((ClassRev >> 8) & 0xFF);
    Device.SubClass      = (uint8_t)((ClassRev >> 16) & 0xFF);
    Device.ClassCode     = (uint8_t)((ClassRev >> 24) & 0xFF);

    uint32_t CommandStatus = PciConfigRead32(__Bus__, __Device__, __Function__, 0x04);
    Device.Command         = (uint16_t)(CommandStatus & 0xFFFF);
    Device.Status          = (uint16_t)(CommandStatus >> 16);

    Device.HeaderType = PciConfigRead8(__Bus__, __Device__, __Function__, 0x0E);

    uint32_t InterruptInfo = PciConfigRead32(__Bus__, __Device__, __Function__, 0x3C);
    Device.InterruptLine   = (uint8_t)(InterruptInfo & 0xFF);
    Device.InterruptPin    = (uint8_t)((InterruptInfo >> 8) & 0xFF);

    SysErr  err;
    SysErr* Error = &err;
    PciReadBars(&Device, Error);
    PciReadCapabilities(&Device, Error);

    int Result = PciAddDevice(&Device);
    if (Result != SysOkay)
    {
        PushError("PciProbeFunction", LOGPCIBUSC_PError, "cannot add device to pci bus", Result);
        return Result;
    }

    LOGPCIBUSC_PDebug("Found PCI device %02x:%02x.%x - %04x:%04x (Class: %02x:%02x)\n",
                      __Bus__,
                      __Device__,
                      __Function__,
                      Device.VendorId,
                      Device.DeviceId,
                      Device.ClassCode,
                      Device.SubClass);

    return SysOkay;
}

int
PciAddDevice(PciDevice* __Device__)
{
    if (PciBus.DeviceCount >= PciBus.DeviceCapacity)
    {
        PushError("PciAddDevice", LOGPCIBUSC_PError, "too many pci devices", -TooMany);
        return -TooMany;
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&PciBus.BusLock, Error);

    PciBus.Devices[PciBus.DeviceCount] = *__Device__;
    PciBus.DeviceCount++;

    ReleaseSpinLock(&PciBus.BusLock, Error);
    return SysOkay;
}

void
PciReadBars(PciDevice* __Device__, SysErr* __Err__)
{
    for (uint8_t BarIndex = 0; BarIndex < 6; BarIndex++)
    {
        uint8_t  Offset = 0x10 + (BarIndex * 4);
        uint32_t BarValue =
            PciConfigRead32(__Device__->Bus, __Device__->Device, __Device__->Function, Offset);

        if (BarValue == 0)
        {
            __Device__->Bars[BarIndex]     = 0;
            __Device__->BarSizes[BarIndex] = 0;
            __Device__->BarTypes[BarIndex] = PciBarTypeInvalid;
            continue;
        }

        /*Determine BAR type*/
        if (BarValue & 1)
        {
            /*I/O BAR*/
            __Device__->Bars[BarIndex]     = BarValue & 0xFFFFFFFC;
            __Device__->BarTypes[BarIndex] = PciBarTypeIo;

            /*Get size*/
            PciConfigWrite32(
                __Device__->Bus, __Device__->Device, __Device__->Function, Offset, 0xFFFFFFFF);
            uint32_t SizeMask =
                PciConfigRead32(__Device__->Bus, __Device__->Device, __Device__->Function, Offset);
            PciConfigWrite32(
                __Device__->Bus, __Device__->Device, __Device__->Function, Offset, BarValue);

            __Device__->BarSizes[BarIndex] = ~(SizeMask & 0xFFFFFFFC) + 1;
        }
        else
        {
            /*Memory BAR*/
            uint8_t Type = (BarValue >> 1) & 3;

            if (Type == 2)
            {
                /*64-bit BAR*/
                if (BarIndex >= 5)
                {
                    __Device__->BarTypes[BarIndex] = PciBarTypeInvalid;
                    continue;
                }

                uint32_t BarHigh = PciConfigRead32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset + 4);
                __Device__->Bars[BarIndex] = ((uint64_t)BarHigh << 32) | (BarValue & 0xFFFFFFF0);
                __Device__->BarTypes[BarIndex] = PciBarTypeMem64;

                /*Get size*/
                PciConfigWrite32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset, 0xFFFFFFFF);
                PciConfigWrite32(__Device__->Bus,
                                 __Device__->Device,
                                 __Device__->Function,
                                 Offset + 4,
                                 0xFFFFFFFF);

                uint32_t SizeLow = PciConfigRead32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset);
                uint32_t SizeHigh = PciConfigRead32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset + 4);

                PciConfigWrite32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset, BarValue);
                PciConfigWrite32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset + 4, BarHigh);

                uint64_t SizeMask = ((uint64_t)SizeHigh << 32) | (SizeLow & 0xFFFFFFF0);
                __Device__->BarSizes[BarIndex] = ~SizeMask + 1;

                BarIndex++; /*Skip next BAR*/
            }
            else
            {
                /*32-bit BAR*/
                __Device__->Bars[BarIndex]     = BarValue & 0xFFFFFFF0;
                __Device__->BarTypes[BarIndex] = PciBarTypeMem32;

                /*Get size*/
                PciConfigWrite32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset, 0xFFFFFFFF);
                uint32_t SizeMask = PciConfigRead32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset);
                PciConfigWrite32(
                    __Device__->Bus, __Device__->Device, __Device__->Function, Offset, BarValue);

                __Device__->BarSizes[BarIndex] = ~(SizeMask & 0xFFFFFFF0) + 1;
            }
        }
    }
}

void
PciReadCapabilities(PciDevice* __Device__, SysErr* __Err__)
{
    if (!(__Device__->Status & (1 << 4)))
    {
        SlotError(__Err__, -NoOperations);
        PushError("PciReadCapabilities",
                  LOGPCIBUSC_PError,
                  "device doesn't support capabilities",
                  -NoOperations);
        return; /*No capabilities*/
    }

    __Device__->MsiCapOffset   = PciFindCapability(__Device__, 0x05);
    __Device__->MsixCapOffset  = PciFindCapability(__Device__, 0x11);
    __Device__->PcieCapOffset  = PciFindCapability(__Device__, 0x10);
    __Device__->PowerCapOffset = PciFindCapability(__Device__, 0x01);
}

uint8_t
PciFindCapability(PciDevice* __Device__, uint8_t __CapId__)
{
    uint8_t CapPtr =
        PciConfigRead8(__Device__->Bus, __Device__->Device, __Device__->Function, 0x34);

    while (CapPtr != 0)
    {
        uint8_t CapId =
            PciConfigRead8(__Device__->Bus, __Device__->Device, __Device__->Function, CapPtr);

        if (CapId == __CapId__)
        {
            return CapPtr;
        }

        CapPtr =
            PciConfigRead8(__Device__->Bus, __Device__->Device, __Device__->Function, CapPtr + 1);
    }

    PushError("PciFindCapability", LOGPCIBUSC_PError, "capability not found", -NoSuch);
    return Nothing;
}
