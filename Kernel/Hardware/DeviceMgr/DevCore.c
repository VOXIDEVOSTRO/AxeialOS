#include <DevMgr.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <ProbeMgr.h>
#include <String.h>

/*DevTree*/
DeviceTree Devices = {0};

static Device*
__FindDeviceByName__(const char* __Name__)
{
    if (!__Name__)
    {
        return Error_TO_Pointer(-BadArgs);
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
        return -NotInit;
    }
    if (!__Name__)
    {
        return -BadArgs;
    }
    if (__Bus__ != BusTypePCI && __Bus__ != BusTypeUSB && __Bus__ != BusTypeNONE)
    {
        return -BadArgs;
    }
    if (__Type__ != DevChar && __Type__ != DevBlock)
    {
        return -BadArgs;
    }

    SysErr  err;
    SysErr* Error = &err;

    AcquireSpinLock(&Devices.Lock, Error);

    Device* Existence = __FindDeviceByName__(__Name__);
    if (!Probe_IF_Error(Existence) && Existence)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        return -Redefined;
    }

    Device* Record = (Device*)KMalloc(sizeof(Device));
    if (!Record)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        return -BadAlloc;
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
        return -NotInit;
    }
    if (!__Name__)
    {
        return -BadArgs;
    }

    SysErr  err;
    SysErr* Error = &err;

    AcquireSpinLock(&Devices.Lock, Error);

    Device* Record = __FindDeviceByName__(__Name__);
    if (Probe_IF_Error(Record) || !Record)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        return Pointer_TO_Error(Record);
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
        return -NotInit;
    }
    if (!__Name__)
    {
        return -BadArgs;
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&Devices.Lock, Error);

    Device* Record = __FindDeviceByName__(__Name__);
    if (Probe_IF_Error(Record) || !Record)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        return Pointer_TO_Error(Record);
    }

    if (!Record->BondedDriver)
    {
        ReleaseSpinLock(&Devices.Lock, Error);
        return -Missing; /* no bonded driver to resolve */
    }

    /* Load driver by bonded name if not active */
    if (Record->BondedDriver->State != DriverStateActive)
    {
        int RetStuff = LoadDriver(Record->BondedDriver->Info.Name);
        if (RetStuff != SysOkay)
        {
            Record->State = DeviceStateFailed;
            ReleaseSpinLock(&Devices.Lock, Error);
            return RetStuff;
        }
        IncrementDriverRef(Record->BondedDriver->Info.Name);
    }

    Record->State = DeviceStateActive;

    ReleaseSpinLock(&Devices.Lock, Error);
    return SysOkay;
}

void
CheckForHardware(SysErr* __Err__)
{
    if (!Devices.Initialized)
    {
        SlotError(__Err__, -NotInit);
        return;
    }

    int Ret = RefreshProbes();
    if (Ret != SysOkay)
    {
        SlotError(__Err__, Ret);
        return;
    }
}