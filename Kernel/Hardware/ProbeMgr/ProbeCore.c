#include <KHeap.h>
#include <KrnPrintf.h>
#include <ProbeMgr.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGPROBECOREC_Debug
#    define LOGPROBECOREC_PDebug(fmt, ...) PDebug("[KERNEL>>ProbeCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROBECOREC_PDebug(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROBECOREC_Logs
#    define LOGPROBECOREC_PError(fmt, ...) PError("[KERNEL>>ProbeCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROBECOREC_PError(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROBECOREC_Logs
#    define LOGPROBECOREC_PWarn(fmt, ...) PWarn("[KERNEL>>ProbeCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROBECOREC_PWarn(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROBECOREC_Logs
#    define LOGPROBECOREC_PInfo(fmt, ...) PInfo("[KERNEL>>ProbeCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROBECOREC_PInfo(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPROBECOREC_Logs
#    define LOGPROBECOREC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ProbeCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPROBECOREC_PSuccess(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*Manager*/
ProbeManagerContext ProbeManager = {0};

/* Check if driver Name starts with "PROBE" */
static int
__HasProbePrefix__(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        return Nothing; /*Zero is error*/
    }
    const char* P = ProbePrefix;
    uint32_t    I = 0;
    while (P[I] && __Name__[I])
    {
        char CharA = P[I];
        char CharB = __Name__[I];
        if (CharA >= 'a' && CharA <= 'z')
        {
            CharA -= 32;
        }
        if (CharB >= 'a' && CharB <= 'z')
        {
            CharB -= 32;
        }
        if (CharA != CharB)
        {
            return Nothing;
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
        PushError("__RegisterProbe__",
                  LOGPROBECOREC_PError,
                  "bad arguments in __RegisterProbe__",
                  -BadArguments);
        return -BadArguments;
    }

    /* duplicate check */
    Probe* Cur = ProbeManager.Probes;
    while (Cur)
    {
        if (Cur->Driver == __Drv__)
        {
            PushError("__RegisterProbe__",
                      LOGPROBECOREC_PError,
                      "probe already exists from __RegisterProbe__",
                      -Redefined);
            return -Redefined;
        }
        Cur = Cur->Next;
    }

    Probe* Node = (Probe*)KMalloc(sizeof(Probe));
    if (Probe_IF_Error(Node) || !Node)
    {
        PushError("__RegisterProbe__",
                  LOGPROBECOREC_PError,
                  "bad node allocated in __RegisterProbe__",
                  Pointer_TO_Error(Node));
        return -BadAllocation;
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
        PushError("__DiscoverProbes__",
                  LOGPROBECOREC_PError,
                  "cannot get all driver in __DiscoverProbe__",
                  Pointer_TO_Error(All));
        return -BadReturn;
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
        PushError("__InvokeProbe__",
                  LOGPROBECOREC_PError,
                  "bad arguments in __InvokeProbe__",
                  -BadArguments);
        return -Missing;
    }
    ModuleRecord* Module = __Drv__->Info.ModuleHandle;
    if (Probe_IF_Error(Module->ProbeFn) || !Module->ProbeFn)
    {
        PushError("__InvokeProbe__",
                  LOGPROBECOREC_PError,
                  "no probe function found in module for __InvokeProbe__",
                  -NoOperations);
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
    if (Ret != SysOkay)
    {
        SlotError(__Err__, -BadReturn);
        PushError("InitProbeManager",
                  LOGPROBECOREC_PError,
                  "cannot discover probes for InitProbeManager",
                  Ret);
        return;
    }
}

int
RefreshProbes(void)
{
    if (!ProbeManager.Initialized)
    {
        PushError("RefreshProbes",
                  LOGPROBECOREC_PError,
                  "probe mgr not init for RefreshProbes",
                  -NotInitilized);
        return -NotInitilized;
    }

    SysErr  err;
    SysErr* Error = &err;
    int     Ret   = __DiscoverProbes__();
    if (Ret != SysOkay)
    {
        PushError(
            "RefreshProbes", LOGPROBECOREC_PError, "cannot discover probes in RefreshProbes", Ret);
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
    return SysOkay;
}