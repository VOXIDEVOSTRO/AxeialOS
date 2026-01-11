#pragma once

#include <AllTypes.h>
#include <DevFS.h>
#include <DrvMgr.h>
#include <Errnos.h>
#include <KExports.h>
#include <Sync.h>

#define MaxDevices       1024
#define DeviceNameMaxLen 64
#define VendorNameMaxLen 64

typedef enum BusType
{
    BusTypeNONE = 0,
    BusTypePCI,
    BusTypeUSB
} BusType;

typedef enum DeviceState
{
    DeviceStateNONE = 0,
    DeviceStatePending,
    DeviceStateActive,
    DeviceStateFailed
} DeviceState;

typedef struct Device
{
    char         Name[DeviceNameMaxLen];
    DriverEntry* BondedDriver;
    BusType      Bus;
    DevType      PrimaryType;
    uint16_t     VendorId;
    char         VendorName[VendorNameMaxLen];
    DeviceState  State;
    uint32_t     Priority;

    /*linked list*/
    struct Device* Next;
    struct Device* Prev;
} Device;

typedef struct DeviceTree
{
    Device*  Devices;
    uint32_t Count;
    SpinLock Lock;
    int      Initialized;
} DeviceTree;

extern DeviceTree Devices;

void InitDeviceManager(SysErr* __Err__);
int  InstallDevice(const char*  __Name__,
                   DriverEntry* __Bonded__,
                   BusType      __Bus__,
                   DevType      __Type__,
                   uint16_t     __VendorId__,
                   const char*  __VendorName__,
                   uint32_t     __Priority__);

int  UninstallDevice(const char* __Name__);
int  ResolveDevice(const char* __Name__);
void CheckForHardware(SysErr* __Err__);

KEXPORT(InstallDevice)
KEXPORT(UninstallDevice)
KEXPORT(ResolveDevice)
KEXPORT(CheckForHardware)