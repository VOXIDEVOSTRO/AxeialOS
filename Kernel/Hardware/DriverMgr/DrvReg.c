#include <DrvMgr.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <String.h>

const char* DriverTypes[] = {
    "default", "input", "storage", "network", "graphics", "audio", "usb", "pci", "serial", NULL};

int
AddDriverToRegistry(DriverInfo* __Info__)
{
    if (Probe_IF_Error(__Info__) || !__Info__ || !DriverManager.Initialized)
    {
        return -BadArgs;
    }

    /*Check for existence*/
    DriverEntry* Existing = FindDriverByName(__Info__->Name);
    if (!Probe_IF_Error(Existing))
    {
        return -Redefined;
    }

    SysErr       err;
    SysErr*      Error     = &err;
    DriverEntry* NewDriver = (DriverEntry*)KMalloc(sizeof(DriverEntry));
    if (Probe_IF_Error(NewDriver) || !NewDriver)
    {
        return -BadAlloc;
    }

    for (size_t ByteIndex = 0; ByteIndex < sizeof(DriverEntry); ByteIndex++)
    {
        ((uint8_t*)NewDriver)[ByteIndex] = 0;
    }

    NewDriver->Info        = *__Info__;
    NewDriver->State       = DriverStateUnloaded;
    NewDriver->RefCount    = 0;
    NewDriver->LoadTime    = 0;
    NewDriver->LastUsed    = 0;
    NewDriver->PrivateData = NULL;

    /*Add to global driver list*/
    AcquireSpinLock(&DriverManager.ManagerLock, Error);

    NewDriver->Next = DriverManager.AllDrivers;
    if (DriverManager.AllDrivers)
    {
        DriverManager.AllDrivers->Prev = NewDriver;
    }
    DriverManager.AllDrivers = NewDriver;
    DriverManager.TotalDrivers++;

    /*Add to type-specific registry*/
    for (uint32_t TypeIndex = 0; TypeIndex < DriverManager.TypeCount; TypeIndex++)
    {
        DriverTypeRegistry* Registry = &DriverManager.Types[TypeIndex];

        if (Registry->Type == __Info__->Type)
        {
            AcquireSpinLock(&Registry->TypeLock, Error);

            if (Registry->DriverCount < MaxDriversPerType)
            {
                Registry->Drivers[Registry->DriverCount] = NewDriver;
                Registry->DriverCount++;
            }

            ReleaseSpinLock(&Registry->TypeLock, Error);
            break;
        }
    }

    ReleaseSpinLock(&DriverManager.ManagerLock, Error);

    PDebug("Added driver to registry: %s\n", __Info__->Name);
    return SysOkay;
}

int
RemoveDriverFromRegistry(const char* __DriverName__)
{
    if (Probe_IF_Error(__DriverName__) || !__DriverName__ || !DriverManager.Initialized)
    {
        return -BadArgs;
    }

    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver))
    {
        return Pointer_TO_Error(Driver);
    }

    if (Driver->RefCount > 0)
    {
        return -Busy;
    }

    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&DriverManager.ManagerLock, Error);

    /*Remove from global list*/
    if (Driver->Prev)
    {
        Driver->Prev->Next = Driver->Next;
    }
    else
    {
        DriverManager.AllDrivers = Driver->Next;
    }

    if (Driver->Next)
    {
        Driver->Next->Prev = Driver->Prev;
    }

    DriverManager.TotalDrivers--;

    /*Remove from type registry*/
    for (uint32_t TypeIndex = 0; TypeIndex < DriverManager.TypeCount; TypeIndex++)
    {
        DriverTypeRegistry* Registry = &DriverManager.Types[TypeIndex];

        if (Registry->Type == Driver->Info.Type)
        {
            AcquireSpinLock(&Registry->TypeLock, Error);

            for (uint32_t DriverIndex = 0; DriverIndex < Registry->DriverCount; DriverIndex++)
            {
                if (Registry->Drivers[DriverIndex] == Driver)
                {
                    /*Shift remaining drivers*/
                    for (uint32_t ShiftIndex = DriverIndex; ShiftIndex < Registry->DriverCount - 1;
                         ShiftIndex++)
                    {
                        Registry->Drivers[ShiftIndex] = Registry->Drivers[ShiftIndex + 1];
                    }
                    Registry->DriverCount--;
                    break;
                }
            }

            ReleaseSpinLock(&Registry->TypeLock, Error);
            break;
        }
    }

    ReleaseSpinLock(&DriverManager.ManagerLock, Error);

    KFree(Driver, Error);

    PDebug("Removed driver from registry: %s\n", __DriverName__);
    return SysOkay;
}

DriverEntry**
FindDriversByType(DriverType __Type__, uint32_t* __Count__)
{
    if (Probe_IF_Error(__Count__) || !__Count__)
    {
        return Error_TO_Pointer(-BadArgs);
    }

    *__Count__ = 0;

    for (uint32_t TypeIndex = 0; TypeIndex < DriverManager.TypeCount; TypeIndex++)
    {
        DriverTypeRegistry* Registry = &DriverManager.Types[TypeIndex];

        if (Registry->Type == __Type__)
        {
            *__Count__ = Registry->DriverCount;
            return Registry->Drivers;
        }
    }

    return Error_TO_Pointer(-NoSuch);
}

DriverEntry**
GetAllDrivers(uint32_t* __Count__)
{
    if (Probe_IF_Error(__Count__) || !__Count__)
    {
        return Error_TO_Pointer(-BadArgs);
    }

    *__Count__ = DriverManager.TotalDrivers;

    if (DriverManager.TotalDrivers == 0)
    {
        return Error_TO_Pointer(-NoSuch);
    }

    SysErr        err;
    SysErr*       Error = &err;
    DriverEntry** DriverArray =
        (DriverEntry**)KMalloc(sizeof(DriverEntry*) * DriverManager.TotalDrivers);
    if (Probe_IF_Error(DriverArray) || !DriverArray)
    {
        return Error_TO_Pointer(-BadAlloc);
    }

    AcquireSpinLock(&DriverManager.ManagerLock, Error);

    uint32_t     Index   = 0;
    DriverEntry* Current = DriverManager.AllDrivers;
    while (Current && Index < DriverManager.TotalDrivers)
    {
        DriverArray[Index] = Current;
        Current            = Current->Next;
        Index++;
    }

    ReleaseSpinLock(&DriverManager.ManagerLock, Error);

    return DriverArray;
}

DriverEntry**
GetLoadedDrivers(uint32_t* __Count__)
{
    if (Probe_IF_Error(__Count__) || !__Count__)
    {
        return Error_TO_Pointer(-BadArgs);
    }

    /*Count loaded drivers first*/
    uint32_t LoadedCount = 0;
    SysErr   err;
    SysErr*  Error = &err;

    AcquireSpinLock(&DriverManager.ManagerLock, Error);

    DriverEntry* Current = DriverManager.AllDrivers;
    while (Current)
    {
        if (Current->State == DriverStateLoaded || Current->State == DriverStateActive)
        {
            LoadedCount++;
        }
        Current = Current->Next;
    }

    if (LoadedCount == 0)
    {
        ReleaseSpinLock(&DriverManager.ManagerLock, Error);
        *__Count__ = 0;
        return Error_TO_Pointer(-NoSuch);
    }

    DriverEntry** LoadedArray = (DriverEntry**)KMalloc(sizeof(DriverEntry*) * LoadedCount);
    if (Probe_IF_Error(LoadedArray) || !LoadedArray)
    {
        ReleaseSpinLock(&DriverManager.ManagerLock, Error);
        return Error_TO_Pointer(-BadAlloc);
    }

    uint32_t Index = 0;
    Current        = DriverManager.AllDrivers;
    while (Current && Index < LoadedCount)
    {
        if (Current->State == DriverStateLoaded || Current->State == DriverStateActive)
        {
            LoadedArray[Index] = Current;
            Index++;
        }
        Current = Current->Next;
    }

    ReleaseSpinLock(&DriverManager.ManagerLock, Error);

    *__Count__ = LoadedCount;
    return LoadedArray;
}

int
ScanDriverDirectory(void)
{

    PDebug("Driver directory scan from base: %s\n", DriverPathBase);

    for (uint32_t TypeIdx = 0; DriverTypes[TypeIdx] != NULL; TypeIdx++)
    {
        char DirPath[DriverPathMaxLen];

        strcpy(DirPath, DriverPathBase, sizeof(DirPath));
        strcpy(DirPath + strlen(DirPath), "/", sizeof(DirPath) - strlen(DirPath));
        strcpy(DirPath + strlen(DirPath), DriverTypes[TypeIdx], sizeof(DirPath) - strlen(DirPath));

        if (VfsExists(DirPath) != SysOkay)
        {
            PWarn("Directory does not exist: %s\n", DirPath);
            continue;
        }

        if (VfsIsDir(DirPath) != SysOkay)
        {
            PWarn("Path is not a directory: %s\n", DirPath);
            continue;
        }

        VfsDirEnt DirBuffer[32];
        long      EntryCount = VfsReaddir(DirPath, DirBuffer, sizeof(DirBuffer));

        PInfo("Found %ld entries in %s\n", EntryCount, DirPath);

        if (EntryCount <= 0)
        {
            continue;
        }

        for (long EntryIdx = 0; EntryIdx < EntryCount; EntryIdx++)
        {
            SysErr  err;
            SysErr* Error = &err;

            VfsDirEnt* Entry = &DirBuffer[EntryIdx];

            PDebug("Processing entry: %s (type=%d)\n", Entry->Name, Entry->Type);

            if (Entry->Type != VNodeFILE)
            {
                PWarn("non-file entry: %s\n", Entry->Name);
                continue;
            }

            char* DotKo = strrchr(Entry->Name, '.');
            if (!DotKo || strcmp(DotKo, ".ko") != 0)
            {
                PWarn("non-.ko file: %s\n", Entry->Name);
                continue;
            }

            AcquireSpinLock(&DriverManager.ManagerLock, Error);
            char FullPath[DriverPathMaxLen];
            strcpy(FullPath, DirPath, sizeof(FullPath));
            strcpy(FullPath + strlen(FullPath), "/", sizeof(FullPath) - strlen(FullPath));
            strcpy(FullPath + strlen(FullPath), Entry->Name, sizeof(FullPath) - strlen(FullPath));
            DriverInfo Info;
            int        result = GetDriverModuleInfo(FullPath, &Info);
            ReleaseSpinLock(&DriverManager.ManagerLock, Error);

            if (result == SysOkay)
            {
                int addResult = AddDriverToRegistry(&Info);
                if (addResult == SysOkay)
                {
                    PSuccess("Registered driver: %s from %s\n", Info.Name, FullPath);
                }
            }
        }
    }

    PDebug("Registered drivers:\n");
    DriverEntry* current = DriverManager.AllDrivers;
    while (current)
    {
        PDebug(
            "  - %s (type=%d, state=%d)\n", current->Info.Name, current->Info.Type, current->State);
        current = current->Next;
    }

    return SysOkay;
}
