#include <DrvMgr.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <String.h>
#include <Timer.h>
#include <__AXEKCONF__.h>

#ifdef LOGDRVCOREC_Debug
#    define LOGDRVCOREC_PDebug(fmt, ...) PDebug("[KERNEL>>DrvCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVCOREC_PDebug(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVCOREC_Logs
#    define LOGDRVCOREC_PError(fmt, ...) PError("[KERNEL>>DrvCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVCOREC_PError(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVCOREC_Logs
#    define LOGDRVCOREC_PWarn(fmt, ...) PWarn("[KERNEL>>DrvCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVCOREC_PWarn(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVCOREC_Logs
#    define LOGDRVCOREC_PInfo(fmt, ...) PInfo("[KERNEL>>DrvCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVCOREC_PInfo(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVCOREC_Logs
#    define LOGDRVCOREC_PSuccess(fmt, ...) PSuccess("[KERNEL>>DrvCore.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVCOREC_PSuccess(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

DriverManagerContext DriverManager = {0};

int
InitializeDriverManager(void)
{
    if (DriverManager.Initialized)
    {
        PushError("InitializeDriverManager",
                  LOGDRVCOREC_PError,
                  "driver mgr already initilized",
                  -Redefined);
        return -Redefined;
    }

    SysErr  err;
    SysErr* Error = &err;

    for (uint32_t TypeIndex = 0; TypeIndex < MaxDriverTypes; TypeIndex++)
    {
        DriverManager.Types[TypeIndex].Type        = DriverTypeDefault;
        DriverManager.Types[TypeIndex].DriverCount = 0;

        for (uint32_t DriverIndex = 0; DriverIndex < MaxDriversPerType; DriverIndex++)
        {
            DriverManager.Types[TypeIndex].Drivers[DriverIndex] = NULL;
        }

        InitializeSpinLock(&DriverManager.Types[TypeIndex].TypeLock, "DriverType", Error);
    }

    DriverManager.AllDrivers   = NULL;
    DriverManager.TotalDrivers = 0;
    DriverManager.TypeCount    = 0;

    InitializeSpinLock(&DriverManager.ManagerLock, "DriverManager", Error);

    /*Default driver types*/

    for (int I = 0; DriverTypes[I]; I++)
    {
        int Ret = RegisterDriverType(DriverTypes[I], I);
        if (Ret != SysOkay)
        {
            LOGDRVCOREC_PWarn(
                "Failed to register default driver type: %s (%d)\n", DriverTypes[I], Ret);
        }
    }

    DriverManager.Initialized = true;

    LOGDRVCOREC_PSuccess("Driver Manager initialized\n");

    /*Scan for existing drivers*/
    int ScanResult = ScanDriverDirectory();
    if (ScanResult != SysOkay)
    {
        LOGDRVCOREC_PWarn("Driver directory scan failed: %d\n", ScanResult);
    }

    return SysOkay;
}

void
ShutdownDriverManager(SysErr* __Err__)
{
    if (!DriverManager.Initialized)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("ShutdownDriverManager",
                  LOGDRVCOREC_PError,
                  "driver mgr not initilized",
                  -NotInitilized);
        return;
    }
    /*Unload all drivers*/
    DriverEntry* Current = DriverManager.AllDrivers;
    while (Current)
    {
        DriverEntry* Next = Current->Next;

        if (Current->State == DriverStateLoaded || Current->State == DriverStateActive)
        {
            UnloadDriverModule(Current);
        }

        KFree(Current, __Err__);
        Current = Next;
    }

    DriverManager.AllDrivers   = NULL;
    DriverManager.TotalDrivers = 0;
    DriverManager.Initialized  = false;
    LOGDRVCOREC_PInfo("Driver Manager shutdown complete\n");
}

int
RegisterDriverType(const char* __TypeName__, DriverType __Type__)
{
    if (Probe_IF_Error(__TypeName__) || !__TypeName__ || DriverManager.TypeCount >= MaxDriverTypes)
    {
        PushError("RegisterDriverType", LOGDRVCOREC_PError, "bad args", -BadArguments);
        return -BadArguments;
    }

    SysErr  err;
    SysErr* Error = &err;
    /*Check if type already exists*/
    for (uint32_t TypeIndex = 0; TypeIndex < DriverManager.TypeCount; TypeIndex++)
    {
        if (DriverManager.Types[TypeIndex].Type == __Type__)
        {
            PushError(
                "RegisterDriverType", LOGDRVCOREC_PError, "driver type already exists", -Redefined);
            return -Redefined;
        }
    }

    DriverTypeRegistry* Registry = &DriverManager.Types[DriverManager.TypeCount];
    strcpy(Registry->TypeName, __TypeName__, sizeof(Registry->TypeName));
    Registry->Type        = __Type__;
    Registry->DriverCount = 0;

    DriverManager.TypeCount++;
    LOGDRVCOREC_PDebug("Registered driver type: %s (%u)\n", __TypeName__, __Type__);
    return SysOkay;
}

int
UnregisterDriverType(DriverType __Type__)
{
    SysErr  err;
    SysErr* Error = &err;
    for (uint32_t TypeIndex = 0; TypeIndex < DriverManager.TypeCount; TypeIndex++)
    {
        if (DriverManager.Types[TypeIndex].Type == __Type__)
        {
            /*Check if any drivers are still using this type*/
            if (DriverManager.Types[TypeIndex].DriverCount > 0)
            {
                PushError("UnregisterDriverType",
                          LOGDRVCOREC_PError,
                          "drivers are still using this type",
                          -Busy);
                return -Busy;
            }

            /*Shift remaining types*/
            for (uint32_t ShiftIndex = TypeIndex; ShiftIndex < DriverManager.TypeCount - 1;
                 ShiftIndex++)
            {
                DriverManager.Types[ShiftIndex] = DriverManager.Types[ShiftIndex + 1];
            }

            DriverManager.TypeCount--;
            return SysOkay;
        }
    }
    PushError("UnregisterDriverType", LOGDRVCOREC_PError, "no such driver type", -NoSuch);
    return -NoSuch;
}

uint32_t
GetDriverTypeCount(void)
{
    return DriverManager.TypeCount;
}

DriverEntry*
FindDriverByName(const char* __DriverName__)
{
    if (Probe_IF_Error(__DriverName__) || !__DriverName__ || !DriverManager.Initialized)
    {
        PushError("FindDriverByName", LOGDRVCOREC_PError, "bad args", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    SysErr       err;
    SysErr*      Error   = &err;
    DriverEntry* Current = DriverManager.AllDrivers;
    while (Current)
    {
        if (strcmp(Current->Info.Name, __DriverName__) == 0)
        {
            return Current;
        }
        Current = Current->Next;
    }
    PushError("FindDriverByName", LOGDRVCOREC_PError, "no such driver", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

DriverEntry*
FindDriverByPath(const char* __FilePath__)
{
    if (Probe_IF_Error(__FilePath__) || !__FilePath__ || !DriverManager.Initialized)
    {
        PushError("FindDriverByPath", LOGDRVCOREC_PError, "bad args", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    SysErr       err;
    SysErr*      Error   = &err;
    DriverEntry* Current = DriverManager.AllDrivers;
    while (Current)
    {
        if (strcmp(Current->Info.FilePath, __FilePath__) == 0)
        {
            return Current;
        }
        Current = Current->Next;
    }
    PushError("FindDriverByPath", LOGDRVCOREC_PError, "no such driver", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

uint32_t
GetDriverRefCount(const char* __DriverName__)
{
    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver) || !Driver)
    {
        PushError("GetDriverRefCount", LOGDRVCOREC_PError, "no such driver", -NoSuch);
        return Nothing;
    }

    return Driver->RefCount;
}

int
IncrementDriverRef(const char* __DriverName__)
{
    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver))
    {
        PushError(
            "IncrementDriverRef", LOGDRVCOREC_PError, "no such driver", Pointer_TO_Error(Driver));
        return -NoSuch;
    }

    __atomic_fetch_add(&Driver->RefCount, 1, __ATOMIC_SEQ_CST);
    Driver->LastUsed = GetSystemTicks();

    return SysOkay;
}

int
DecrementDriverRef(const char* __DriverName__)
{
    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver) || !Driver)
    {
        PushError(
            "DecrementDriverRef", LOGDRVCOREC_PError, "no such driver", Pointer_TO_Error(Driver));
        return -NoSuch;
    }

    if (Driver->RefCount == 0)
    {
        PushError(
            "DecrementDriverRef", LOGDRVCOREC_PError, "ref count is already 0", -BadArguments);
        return -BadArguments;
    }

    __atomic_fetch_sub(&Driver->RefCount, 1, __ATOMIC_SEQ_CST);
    return SysOkay;
}
