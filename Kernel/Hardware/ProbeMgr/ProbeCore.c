#include <KHeap.h>
#include <KrnPrintf.h>
#include <ProbeMgr.h>
#include <String.h>

/*Manager*/
ProbeManagerContext ProbeManager = {0};

/* Check if driver Name starts with "PROBE" */
static int
__HasProbePrefix__(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        return Nothing;
    }
    const char* P = ProbePrefix;
    uint32_t    I = 0;
    while (P[I] && __Name__[I])
    {
        char a = P[I];
        char b = __Name__[I];
        if (a >= 'a' && a <= 'z')
        {
            a -= 32;
        }
        if (b >= 'a' && b <= 'z')
        {
            b -= 32;
        }
        if (a != b)
        {
            return 0;
        }
        I++;
    }
    return P[I] == '\0';
}

static int
__RegisterProbe__(DriverEntry* __Drv__, const char* __DeviceName__)
{
    if (Probe_IF_Error(__Drv__) || !__Drv__ || Probe_IF_Error(__DeviceName__) || !__DeviceName__)
    {
        return -BadArgs;
    }

    /* duplicate check */
    Probe* Cur = ProbeManager.Probes;
    while (Cur)
    {
        if (Cur->Driver == __Drv__)
        {
            return -Redefined;
        }
        Cur = Cur->Next;
    }

    Probe* Node = (Probe*)KMalloc(sizeof(Probe));
    if (Probe_IF_Error(Node) || !Node)
    {
        return -BadAlloc;
    }

    /* copy device Name */
    uint32_t L = 0;
    while (__DeviceName__[L] != '\0' && L < (ProbeDeviceNameLen - 1))
    {
        Node->DeviceName[L] = __DeviceName__[L];
        L++;
    }
    Node->DeviceName[L] = '\0';

    Node->Blacklisted = 0;
    Node->Driver      = __Drv__;
    Node->Device      = NULL;
    Node->Next        = ProbeManager.Probes;
    Node->Prev        = NULL;
    if (ProbeManager.Probes)
    {
        ProbeManager.Probes->Prev = Node;
    }
    ProbeManager.Probes = Node;
    ProbeManager.Count++;
    return SysOkay;
}

static int
__DiscoverProbes__(void)
{
    uint32_t      Idx = 0;
    DriverEntry** All = GetAllDrivers(&Idx);
    if (Probe_IF_Error(All) || !All)
    {
        return Pointer_TO_Error(All);
    }

    for (uint32_t I = 0; I < Idx; I++)
    {
        DriverEntry* DevTree = All[I];
        if (Probe_IF_Error(DevTree) || !DevTree)
        {
            continue;
        }

        if (__HasProbePrefix__(DevTree->Info.Name))
        {
            /* extract device Name suffix after "PROBE." or "PROBE_" */
            const char* Name = DevTree->Info.Name;
            const char* DevN = NULL;
            uint32_t    KIdx = 5; /* aft of "PROBE" */
            while (Name[KIdx] == '.' || Name[KIdx] == '_' || Name[KIdx] == '-')
            {
                KIdx++;
            }
            DevN = &Name[KIdx];
            if (Probe_IF_Error(DevN) || !DevN || DevN[0] == '\0')
            {
                continue;
            }

            /* load probe driver if not active */
            if (DevTree->State != DriverStateActive)
            {
                int Ret = LoadDriver(DevTree->Info.Name);
                if (Ret != SysOkay)
                {
                    continue;
                }
                IncrementDriverRef(DevTree->Info.Name);
            }

            __RegisterProbe__(DevTree, DevN);
        }
    }
    return SysOkay;
}

static int
__InvokeProbe__(DriverEntry* __Drv__)
{
    if (Probe_IF_Error(__Drv__) || !__Drv__ || !__Drv__->Info.ModuleHandle)
    {
        return -Missing;
    }
    ModuleRecord* Module = __Drv__->Info.ModuleHandle;
    if (Probe_IF_Error(Module->ProbeFn) || !Module->ProbeFn)
    {
        return -NoOperations;
    }
    return Module->ProbeFn(); /* SysOkay if device detected */
}

void
InitProbeManager(SysErr* __Err__)
{
    ProbeManager.Probes      = NULL;
    ProbeManager.Count       = 0;
    ProbeManager.Initialized = 1;

    SysErr  err;
    SysErr* Error = &err;
    InitializeSpinLock(&ProbeManager.Lock, "ProbeManager", Error);

    int Ret = __DiscoverProbes__();
    SlotError(__Err__, Ret == SysOkay ? SysOkay : Ret);
}

int
RefreshProbes(void)
{
    if (!ProbeManager.Initialized)
    {
        return -NotInit;
    }

    SysErr  err;
    SysErr* Error = &err;

    AcquireSpinLock(&ProbeManager.Lock, Error);

    int Ret = __DiscoverProbes__();
    if (Ret != SysOkay)
    {
        ReleaseSpinLock(&ProbeManager.Lock, Error);
        return Ret;
    }

    Probe* Cur = ProbeManager.Probes;
    while (Cur)
    {
        if (!Cur->Blacklisted && Cur->Driver)
        {
            int RetP = __InvokeProbe__(Cur->Driver);
            if (RetP == SysOkay)
            {
                /* Device detected */
                DriverEntry* BingBong   = Cur->Driver;
                int          InstallRet = InstallDevice(Cur->DeviceName,
                                               BingBong,
                                               BusTypeNONE,
                                               DevChar,
                                               0,
                                               "",
                                               BingBong->Info.Priority);
                if (InstallRet == SysOkay || InstallRet != -Redefined)
                {
                    ResolveDevice(Cur->DeviceName);
                }
            }
        }
        Cur = Cur->Next;
    }

    ReleaseSpinLock(&ProbeManager.Lock, Error);
    return SysOkay;
}