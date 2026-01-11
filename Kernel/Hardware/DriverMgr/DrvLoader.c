#include <DrvMgr.h>
#include <KHeap.h>
#include <KMods.h>
#include <KrnPrintf.h>
#include <String.h>
#include <Timer.h>

int
LoadDriver(const char* __DriverName__)
{
    if (Probe_IF_Error(__DriverName__) || !__DriverName__ || !DriverManager.Initialized)
    {
        return -BadArgs;
    }

    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver))
    {
        return -NoSuch;
    }

    PDebug("Found driver '%s', current state: %d\n", __DriverName__, Driver->State);

    if (Driver->State == DriverStateLoaded || Driver->State == DriverStateActive)
    {
        return -Redefined;
    }

    Driver->State = DriverStateLoading;
    PDebug("Loading module for '%s'\n", __DriverName__);

    int Result = LoadDriverModule(Driver);

    if (Result != SysOkay)
    {
        Driver->State = DriverStateFailed;
        return Result;
    }

    Driver->State    = DriverStateLoaded;
    Driver->LoadTime = GetSystemTicks();

    PSuccess("Loaded driver: %s\n", __DriverName__);
    return SysOkay;
}

int
UnloadDriver(const char* __DriverName__)
{
    if (Probe_IF_Error(__DriverName__) || !__DriverName__ || !DriverManager.Initialized)
    {
        return -BadArgs;
    }

    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver))
    {
        return -NoSuch;
    }

    if (Driver->RefCount > 0)
    {
        return -Busy;
    }

    if (Driver->State != DriverStateLoaded && Driver->State != DriverStateActive)
    {
        return -BadArgs;
    }

    Driver->State = DriverStateUnloading;

    int Result = UnloadDriverModule(Driver);
    if (Result != SysOkay)
    {
        Driver->State = DriverStateFailed;
        return Result;
    }

    Driver->State = DriverStateUnloaded;

    PSuccess("Unloaded driver: %s\n", __DriverName__);
    return SysOkay;
}

int
ReloadDriver(const char* __DriverName__)
{
    int UnloadResult = UnloadDriver(__DriverName__);
    if (UnloadResult != SysOkay && UnloadResult != -BadArgs)
    {
        return UnloadResult;
    }

    return LoadDriver(__DriverName__);
}

int
LoadDriverModule(DriverEntry* __Driver__)
{
    if (Probe_IF_Error(__Driver__) || !__Driver__)
    {
        return -BadArgs;
    }

    PDebug("Installing module from '%s'\n", __Driver__->Info.FilePath);

    int Result = InstallModule(__Driver__->Info.FilePath);

    if (Result != SysOkay)
    {
        return Result;
    }

    PDebug("Looking up module record for '%s'\n", __Driver__->Info.FilePath);

    ModuleRecord* Module = ModuleRegistryFind(__Driver__->Info.FilePath);
    if (Probe_IF_Error(Module))
    {
        UnInstallModule(__Driver__->Info.FilePath);
        return -NoSuch;
    }

    __Driver__->Info.ModuleHandle = Module;

    if (Module->InitFn)
    {
        Module->InitFn();
    }
    else
    {
        PWarn("No Init function found\n");
    }

    PDebug("Successfully loaded module\n");
    return SysOkay;
}

int
UnloadDriverModule(DriverEntry* __Driver__)
{
    if (Probe_IF_Error(__Driver__) || !__Driver__ || !__Driver__->Info.ModuleHandle)
    {
        return -BadArgs;
    }

    int Result = UnInstallModule(__Driver__->Info.FilePath);
    if (Result == SysOkay)
    {
        __Driver__->Info.ModuleHandle = NULL;
    }

    PDebug("Successfully unloaded module\n");
    return Result;
}

int
ValidateDriverBinary(const char* __FilePath__)
{
    if (Probe_IF_Error(__FilePath__) || !__FilePath__)
    {
        return -BadArgs;
    }

    /*Check if file exists and is readable*/
    if (VfsExists(__FilePath__) != SysOkay)
    {
        return -NoSuch;
    }

    /*Basic ELF header validation*/
    Elf64_Ehdr Header;
    long       HeaderLen = 0;

    if (VfsReadAll(__FilePath__, &Header, sizeof(Header), &HeaderLen) != SysOkay ||
        HeaderLen < (long)sizeof(Header))
    {
        return -BadEntity;
    }

    /* ELF magic*/
    if (Header.e_ident[0] != 0x7F || Header.e_ident[1] != 'E' || Header.e_ident[2] != 'L' ||
        Header.e_ident[3] != 'F')
    {
        return -BadEntity;
    }

    /* architecture (x86_64)*/
    if (Header.e_machine != 0x3E)
    {
        return -Dangling;
    }

    /* file type (relocatable or executable)*/
    if (Header.e_type != 1 && Header.e_type != 3)
    {
        return -Impilict;
    }

    return SysOkay;
}

int
GetDriverModuleInfo(const char* __FilePath__, DriverInfo* __Info__)
{
    if (Probe_IF_Error(__FilePath__) || !__FilePath__ || Probe_IF_Error(__Info__) || !__Info__)
    {
        return -BadArgs;
    }

    /*Validate the binary first*/
    int ValidationResult = ValidateDriverBinary(__FilePath__);
    if (ValidationResult != SysOkay)
    {
        return ValidationResult;
    }

    /*Extract driver name from file path*/
    const char* FileName  = __FilePath__;
    const char* LastSlash = __FilePath__;

    while (*FileName)
    {
        if (*FileName == '/')
        {
            LastSlash = FileName + 1;
        }
        FileName++;
    }

    /*Copy name without .ko extension*/
    strcpy(__Info__->Name, LastSlash, sizeof(__Info__->Name));
    char* DotKo = strrchr(__Info__->Name, '.');
    if (DotKo && strcmp(DotKo, ".ko") == 0)
    {
        *DotKo = '\0';
    }

    /*Copy file path*/
    strcpy(__Info__->FilePath, __FilePath__, sizeof(__Info__->FilePath));

    /*Set default values*/
    strcpy(__Info__->Description, "Kernel Module", sizeof(__Info__->Description));
    strcpy(__Info__->Author, "Unknown", sizeof(__Info__->Author));
    strcpy(__Info__->Version, "1.0", sizeof(__Info__->Version));
    __Info__->VersionCode      = 1;
    __Info__->Type             = DriverTypeDefault;
    __Info__->SubType[0]       = '\0';
    __Info__->Priority         = 50;
    __Info__->Flags            = 0;
    __Info__->SupportedVendors = NULL;
    __Info__->SupportedDevices = NULL;
    __Info__->SupportedCount   = 0;
    __Info__->ModuleHandle     = NULL;

    return SysOkay;
}
