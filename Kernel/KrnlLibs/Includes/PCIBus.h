#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <KExports.h>
#include <Sync.h>

#define MaxPciDevices    256
#define PciConfigAddress 0xCF8
#define PciConfigData    0xCFC

typedef enum
{
    PciBarTypeIo,
    PciBarTypeMem32,
    PciBarTypeMem64,
    PciBarTypeInvalid

} PciBarType;

typedef struct
{
    uint8_t  Bus;
    uint8_t  Device;
    uint8_t  Function;
    uint16_t VendorId;
    uint16_t DeviceId;
    uint8_t  ClassCode;
    uint8_t  SubClass;
    uint8_t  ProgInterface;
    uint8_t  Revision;
    uint8_t  HeaderType;
    uint8_t  InterruptLine;
    uint8_t  InterruptPin;
    uint16_t Command;
    uint16_t Status;

    uint64_t   Bars[6];
    uint64_t   BarSizes[6];
    PciBarType BarTypes[6];

    uint8_t MsiCapOffset;
    uint8_t MsixCapOffset;
    uint8_t PcieCapOffset;
    uint8_t PowerCapOffset;

} PciDevice;

typedef struct
{
    PciDevice* Devices;
    uint32_t   DeviceCount;
    uint32_t   DeviceCapacity;
    SpinLock   BusLock;
    bool       Initialized;

} PciBusManager;

extern PciBusManager PciBus;

int  InitializePciBus(void);
void PciScanBus(uint8_t __BusNumber__, SysErr* __Err__);
uint32_t
PciConfigRead32(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__);
uint16_t
PciConfigRead16(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__);
uint8_t
     PciConfigRead8(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__);
void PciConfigWrite32(uint8_t  __Bus__,
                      uint8_t  __Device__,
                      uint8_t  __Function__,
                      uint8_t  __Offset__,
                      uint32_t __Value__);
void PciConfigWrite16(uint8_t  __Bus__,
                      uint8_t  __Device__,
                      uint8_t  __Function__,
                      uint8_t  __Offset__,
                      uint16_t __Value__);
void PciConfigWrite8(uint8_t __Bus__,
                     uint8_t __Device__,
                     uint8_t __Function__,
                     uint8_t __Offset__,
                     uint8_t __Value__);

PciDevice* PciFindDevice(uint16_t __VendorId__, uint16_t __DeviceId__, uint32_t __Index__);
PciDevice* PciGetDevice(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__);
PciDevice* PciFindByClass(uint8_t __ClassCode__, uint8_t __SubClass__, uint32_t __Index__);

int PciEnableBusMastering(PciDevice* __Device__);
int PciDisableBusMastering(PciDevice* __Device__);
int PciEnableMemorySpace(PciDevice* __Device__);
int PciEnableIoSpace(PciDevice* __Device__);
int PciEnableMsi(PciDevice* __Device__, uint64_t __Address__, uint32_t __Data__);
int PciDisableMsi(PciDevice* __Device__);

uint64_t PciGetBarAddress(PciDevice* __Device__, uint8_t __BarIndex__);
uint64_t PciGetBarSize(PciDevice* __Device__, uint8_t __BarIndex__);
uint32_t PciGetBarType(PciDevice* __Device__, uint8_t __BarIndex__);

void PciDumpDevice(PciDevice* __Device__, SysErr* __Err__);
void PciDumpAllDevices(SysErr* __Err__);

/*helpers*/
uint32_t
     PciMakeAddress(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__);
int  PciProbeFunction(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__);
int  PciAddDevice(PciDevice* __Device__);
void PciReadBars(PciDevice* __Device__, SysErr* __Err__);
void PciReadCapabilities(PciDevice* __Device__, SysErr* __Err__);
uint8_t PciFindCapability(PciDevice* __Device__, uint8_t __CapId__);

/* core init */
KEXPORT(InitializePciBus);
KEXPORT(PciScanBus);

/* config space access */
KEXPORT(PciConfigRead32);
KEXPORT(PciConfigRead16);
KEXPORT(PciConfigRead8);
KEXPORT(PciConfigWrite32);
KEXPORT(PciConfigWrite16);
KEXPORT(PciConfigWrite8);

/* device discovery */
KEXPORT(PciFindDevice);
KEXPORT(PciGetDevice);
KEXPORT(PciFindByClass);

/* feature toggles */
KEXPORT(PciEnableBusMastering);
KEXPORT(PciDisableBusMastering);
KEXPORT(PciEnableMemorySpace);
KEXPORT(PciEnableIoSpace);
KEXPORT(PciEnableMsi);
KEXPORT(PciDisableMsi);

/* BAR helpers */
KEXPORT(PciGetBarAddress);
KEXPORT(PciGetBarSize);
KEXPORT(PciGetBarType);

/* dumpers */
KEXPORT(PciDumpDevice);
KEXPORT(PciDumpAllDevices);

/* helpers */
KEXPORT(PciMakeAddress);
KEXPORT(PciProbeFunction);
KEXPORT(PciAddDevice);
KEXPORT(PciReadBars);
KEXPORT(PciReadCapabilities);
KEXPORT(PciFindCapability);