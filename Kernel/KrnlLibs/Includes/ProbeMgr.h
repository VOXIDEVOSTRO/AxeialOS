#pragma once

#include <AllTypes.h>
#include <DevMgr.h>
#include <DrvMgr.h>
#include <Errnos.h>
#include <KExports.h>
#include <Sync.h>

#define MaxProbes          256
#define ProbeDeviceNameLen 64
#define ProbePrefix        "PROBE"

typedef struct Probe
{
    char         DeviceName[ProbeDeviceNameLen]; /* device served by this probe */
    int          Blacklisted;                    /* 0/1 flag */
    DriverEntry* Driver;                         /* probe driver entry */
    Device*      Device;                         /* installed device (if any) */

    /*Linked List*/
    struct Probe* Next;
    struct Probe* Prev;
} Probe;

typedef struct ProbeManagerContext
{
    Probe*   Probes;
    uint32_t Count;
    SpinLock Lock;
    int      Initialized;
} ProbeManagerContext;

extern ProbeManagerContext ProbeManager;

void InitProbeManager(SysErr* __Err__);
int  RefreshProbes(void);

KEXPORT(InitProbeManager)
KEXPORT(RefreshProbes)