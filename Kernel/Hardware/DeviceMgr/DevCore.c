#include <DevMgr.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <ProbeMgr.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGDEVCOREC_Debug
#    define LOGDEVCOREC_PDebug(fmt, ...) PDebug("[KERNEL>>DevCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVCOREC_PDebug(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVCOREC_Logs
#    define LOGDEVCOREC_PError(fmt, ...) PError("[KERNEL>>DevCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVCOREC_PError(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVCOREC_Logs
#    define LOGDEVCOREC_PWarn(fmt, ...) PWarn("[KERNEL>>DevCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVCOREC_PWarn(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVCOREC_Logs
#    define LOGDEVCOREC_PInfo(fmt, ...) PInfo("[KERNEL>>DevCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVCOREC_PInfo(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDEVCOREC_Logs
#    define LOGDEVCOREC_PSuccess(fmt, ...) PSuccess("[KERNEL>>DevCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDEVCOREC_PSuccess(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*DevTree*/
DeviceTree Devices = {0};

static Device*
__FindDeviceByName__(const char* __Name__)
{
    if (!__Name__)
    {
        PushError("__FindDeviceByName__",
                  LOGDEVCOREC_PError,
                  "no name passed to __FindDeviceByName__",
                  -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    Device* cur = Devices.Devices;
    while (cur)
    {
        /* explicit compare */
        uint32_t L1 = 0, L2 = 0;
        while (__Name__[L1] != '\0')
        {
            L1++;
        }
        while (cur->Name[L2] != '\0')
        {
            L2++;
        }
        if (L1 == L2)
        {
            uint32_t eq = 1;
            for (uint32_t I = 0; I < L1; I++)
            {
                if (__Name__[I] != cur->Name[I])
                {
                    eq = 0;
                    break;
                }
            }
            if (eq)
            {
                return cur;
            }
        }
        cur = cur->Next;
    }
    PushError("__FindDeviceByName__", LOGDEVCOREC_PError, "no such device installed", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

void
InitDeviceManager(SysErr* __Err__)
{
    Devices.Devices     = NULL;
    Devices.Count       = 0;
    Devices.Initialized = 1;
    SysErr  err;
    SysErr* Error = &err;
    InitializeSpinLock(&Devices.Lock, "DeviceTree", Error);
}

int
InstallDevice(const char*  __Name__,
              DriverEntry* __Bonded__,
              BusType      __Bus__,
              DevType      __Type__,
              uint16_t     __VendorId__,
              const char*  __VendorName__,
              uint32_t     __Priority__)
{
    if (!Devices.Initialized)
    {
        PushError("InstallDevice",
                  LOGDEVCOREC_PError,
                  "device manager is not initialized",
                  -NotInitilized);
        return -NotInitilized;
    }
    if (!__Name__)
    {
        PushError(
            "InstallDevice", LOGDEVCOREC_PError, "no name passed to InstallDevice", -BadArguments);
        return -BadArguments;
    }
    if (__Bus__ != BusTypePCI && __Bus__ != BusTypeUSB && __Bus__ != BusTypeNONE)
    {
        PushError("InstallDevice",
                  LOGDEVCOREC_PError,
                  "bad bus type passed to InstallDevice",
                  -BadArguments);
        return -BadArguments;
    }
    if (__Type__ != DevChar && __Type__ != DevBlock)
    {
        PushError("InstallDevice",
                  LOGDEVCOREC_PError,
                  "bad device type passed to InstallDevice",
                  -BadArguments);
        return -BadArguments;
    }

    SysErr  err;
    SysErr* Error = &err;

    AcquireSpinLock(&Devices.Lock, Error);

    Device* Existence = __FindDeviceByName__(__Name__);
    if (!Probe_IF_Error(Existence) && Existence)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        PushError("InstallDevice", LOGDEVCOREC_PError, "device already installed", -Redefined);
        return -Redefined;
    }

    Device* Record = (Device*)KMalloc(sizeof(Device));
    if (!Record)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        PushError("InstallDevice",
                  LOGDEVCOREC_PError,
                  "can't allocate memory for new device record",
                  -BadAllocation);
        return -BadAllocation;
    }

    /* fill fields */
    uint32_t L = 0;
    while (__Name__[L] != '\0' && L < (DeviceNameMaxLen - 1))
    {
        Record->Name[L] = __Name__[L];
        L++;
    }
    Record->Name[L] = '\0';

    Record->BondedDriver = __Bonded__;
    Record->Bus          = __Bus__;
    Record->PrimaryType  = __Type__;
    Record->VendorId     = __VendorId__;

    /* vendor name copy */
    uint32_t VL = 0;
    if (__VendorName__)
    {
        while (__VendorName__[VL] != '\0' && VL < (VendorNameMaxLen - 1))
        {
            Record->VendorName[VL] = __VendorName__[VL];
            VL++;
        }
    }
    Record->VendorName[VL] = '\0';

    Record->State    = DeviceStatePending;
    Record->Priority = __Priority__;
    Record->Next     = Devices.Devices;
    Record->Prev     = NULL;

    if (Devices.Devices)
    {
        Devices.Devices->Prev = Record;
    }
    Devices.Devices = Record;
    Devices.Count++;

    ReleaseSpinLock(&Devices.Lock, Error);
    return SysOkay;
}

int
UninstallDevice(const char* __Name__)
{
    if (!Devices.Initialized)
    {
        PushError("UninstallDevice",
                  LOGDEVCOREC_PError,
                  "device manager is not initialized",
                  -NotInitilized);
        return -NotInitilized;
    }
    if (!__Name__)
    {
        PushError("UninstallDevice",
                  LOGDEVCOREC_PError,
                  "no name passed to UninstallDevice",
                  -BadArguments);
        return -BadArguments;
    }

    SysErr  err;
    SysErr* Error = &err;

    AcquireSpinLock(&Devices.Lock, Error);

    Device* Record = __FindDeviceByName__(__Name__);
    if (Probe_IF_Error(Record) || !Record)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        PushError("UninstallDevice",
                  LOGDEVCOREC_PError,
                  "no such device installed",
                  Pointer_TO_Error(Record));
        return -NoSuch;
    }

    /* unload bonded driver if present */
    if (Record->BondedDriver)
    {
        /* decrement ref and unload by name */
        DecrementDriverRef(Record->BondedDriver->Info.Name);
        UnloadDriver(Record->BondedDriver->Info.Name);
        Record->BondedDriver = NULL;
        Record->State        = DeviceStatePending;
    }

    /* detach from list */
    if (Record->Prev)
    {
        Record->Prev->Next = Record->Next;
    }
    if (Record->Next)
    {
        Record->Next->Prev = Record->Prev;
    }
    if (Devices.Devices == Record)
    {
        Devices.Devices = Record->Next;
    }

    Devices.Count--;
    ReleaseSpinLock(&Devices.Lock, Error);

    KFree(Record, NULL);
    return SysOkay;
}

int
ResolveDevice(const char* __Name__)
{
    if (!Devices.Initialized)
    {
        PushError("ResolveDevice",
                  LOGDEVCOREC_PError,
                  "device manager is not initialized",
                  -NotInitilized);
        return -NotInitilized;
    }
    if (!__Name__)
    {
        PushError(
            "ResolveDevice", LOGDEVCOREC_PError, "no name passed to ResolveDevice", -BadArguments);
        return -BadArguments;
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&Devices.Lock, Error);

    Device* Record = __FindDeviceByName__(__Name__);
    if (Probe_IF_Error(Record) || !Record)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        PushError("ResolveDevice",
                  LOGDEVCOREC_PError,
                  "no such device installed",
                  Pointer_TO_Error(Record));
        return -NoSuch;
    }

    if (!Record->BondedDriver)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        PushError("ResolveDevice", LOGDEVCOREC_PError, "device has no bonded driver", -Missing);
        return -Missing; /* no bonded driver to resolve */
    }

    ReleaseSpinLock(&Devices.Lock, Error);

    /* Load driver by bonded name if not active */
    if (Record->BondedDriver->State != DriverStateActive)
    {
        int RetStuff = LoadDriver(Record->BondedDriver->Info.Name);
        if (RetStuff != SysOkay)
        {
            Record->State = DeviceStateFailed;
            PushError(
                "ResolveDevice", LOGDEVCOREC_PError, "cannot load driver for device", RetStuff);
            return RetStuff;
        }
        IncrementDriverRef(Record->BondedDriver->Info.Name);
    }

    Record->State = DeviceStateActive;
    return SysOkay;
}

void
CheckForHardware(SysErr* __Err__)
{
    if (!Devices.Initialized)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("CheckForHardware",
                  LOGDEVCOREC_PError,
                  "device manager is not initialized",
                  -NotInitilized);
        return;
    }

    int Ret = RefreshProbes();
    if (Ret != SysOkay)
    {
        SlotError(__Err__, Ret);
        PushError("CheckForHardware", LOGDEVCOREC_PError, "cannot refresh probes", Ret);
        return;
    }
}