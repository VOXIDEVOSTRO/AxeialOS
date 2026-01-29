#include <DrvMgr.h>
#include <KHeap.h>
#include <KMods.h>
#include <KrnPrintf.h>
#include <String.h>
#include <Timer.h>
#include <__AXEKCONF__.h>

#ifdef LOGDRVLOADERC_Debug
#    define LOGDRVLOADERC_PDebug(fmt, ...) PDebug("[KERNEL>>DrvLoader.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVLOADERC_PDebug(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVLOADERC_Logs
#    define LOGDRVLOADERC_PError(fmt, ...) PError("[KERNEL>>DrvLoader.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVLOADERC_PError(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVLOADERC_Logs
#    define LOGDRVLOADERC_PWarn(fmt, ...) PWarn("[KERNEL>>DrvLoader.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVLOADERC_PWarn(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVLOADERC_Logs
#    define LOGDRVLOADERC_PInfo(fmt, ...) PInfo("[KERNEL>>DrvLoader.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVLOADERC_PInfo(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGDRVLOADERC_Logs
#    define LOGDRVLOADERC_PSuccess(fmt, ...) PSuccess("[KERNEL>>DrvLoader.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGDRVLOADERC_PSuccess(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
LoadDriver(const char* __DriverName__)
{
    if (Probe_IF_Error(__DriverName__) || !__DriverName__ || !DriverManager.Initialized)
    {
        PushError("LoadDriver",
                  LOGDRVLOADERC_PError,
                  "bad driver name or driver manager not initialized",
                  -BadArguments);
        return -BadArguments;
    }

    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver) || !Driver)
    {
        PushError("LoadDriver", LOGDRVLOADERC_PError, "driver not found", Pointer_TO_Error(Driver));
        return -NoSuch;
    }

    LOGDRVLOADERC_PDebug("Found driver '%s', current state: %d\n", __DriverName__, Driver->State);

    if (Driver->State == DriverStateLoaded || Driver->State == DriverStateActive)
    {
        PushError("LoadDriver", LOGDRVLOADERC_PError, "driver already loaded", -Redefined);
        return -Redefined;
    }

    Driver->State = DriverStateLoading;
    LOGDRVLOADERC_PDebug("Loading module for '%s'\n", __DriverName__);

    int Result = LoadDriverModule(Driver);
    if (Result != SysOkay)
    {
        Driver->State = DriverStateFailed;
        PushError("LoadDriver", LOGDRVLOADERC_PError, "failed to load module", Result);
        return Result;
    }

    Driver->State    = DriverStateLoaded;
    Driver->LoadTime = GetSystemTicks();

    LOGDRVLOADERC_PSuccess("Loaded driver: %s\n", __DriverName__);
    return SysOkay;
}

int
UnloadDriver(const char* __DriverName__)
{
    if (Probe_IF_Error(__DriverName__) || !__DriverName__ || !DriverManager.Initialized)
    {
        PushError("UnloadDriver",
                  LOGDRVLOADERC_PError,
                  "bad driver name or driver manager not initialized",
                  -BadArguments);
        return -BadArguments;
    }

    DriverEntry* Driver = FindDriverByName(__DriverName__);
    if (Probe_IF_Error(Driver) || !Driver)
    {
        PushError(
            "UnloadDriver", LOGDRVLOADERC_PError, "driver not found", Pointer_TO_Error(Driver));
        return -NoSuch;
    }

    if (Driver->RefCount > 0)
    {
        PushError(
            "UnloadDriver", LOGDRVLOADERC_PError, "driver is busy, still in reference", -Busy);
        return -Busy;
    }

    if (Driver->State != DriverStateLoaded && Driver->State != DriverStateActive)
    {
        PushError("UnloadDriver", LOGDRVLOADERC_PError, "driver is not loaded", -BadArguments);
        return -BadArguments;
    }

    Driver->State = DriverStateUnloading;

    int Result = UnloadDriverModule(Driver);
    if (Result != SysOkay)
    {
        Driver->State = DriverStateFailed;
        PushError("UnloadDriver", LOGDRVLOADERC_PError, "failed to unload module", Result);
        return -BadReturn;
    }

    Driver->State = DriverStateUnloaded;

    LOGDRVLOADERC_PSuccess("Unloaded driver: %s\n", __DriverName__);
    return SysOkay;
}

int
ReloadDriver(const char* __DriverName__)
{
    int UnloadResult = UnloadDriver(__DriverName__);
    if (UnloadResult != SysOkay && UnloadResult != -BadArguments)
    {
        PushError("ReloadDriver", LOGDRVLOADERC_PError, "failed to unload driver", UnloadResult);
        return -BadReturn;
    }

    return LoadDriver(__DriverName__);
}

int
LoadDriverModule(DriverEntry* __Driver__)
{
    if (Probe_IF_Error(__Driver__) || !__Driver__)
    {
        PushError("LoadDriverModule", LOGDRVLOADERC_PError, "bad driver entry", -BadArguments);
        return -BadArguments;
    }

    LOGDRVLOADERC_PDebug("Installing module from '%s'\n", __Driver__->Info.FilePath);

    int Result = InstallModule(__Driver__->Info.FilePath);

    if (Result != SysOkay)
    {
        PushError("LoadDriverModule", LOGDRVLOADERC_PError, "failed to install module", Result);
        return -BadReturn;
    }

    LOGDRVLOADERC_PDebug("Looking up module record for '%s'\n", __Driver__->Info.FilePath);

    ModuleRecord* Module = ModuleRegistryFind(__Driver__->Info.FilePath);
    if (Probe_IF_Error(Module) || !Module)
    {
        UnInstallModule(__Driver__->Info.FilePath);
        PushError("LoadDriverModule",
                  LOGDRVLOADERC_PError,
                  "failed to find module record",
                  Pointer_TO_Error(Module));
        return -NoSuch;
    }

    __Driver__->Info.ModuleHandle = Module;

    if (Module->InitFn)
    {
        Module->InitFn();
    }
    else
    {
        LOGDRVLOADERC_PWarn("No Init function found\n");
    }

    LOGDRVLOADERC_PDebug("Successfully loaded module\n");
    return SysOkay;
}

int
UnloadDriverModule(DriverEntry* __Driver__)
{
    if (Probe_IF_Error(__Driver__) || !__Driver__ || !__Driver__->Info.ModuleHandle)
    {
        PushError("UnloadDriverModule", LOGDRVLOADERC_PError, "bad driver entry", -BadArguments);
        return -BadArguments;
    }

    int Result = UnInstallModule(__Driver__->Info.FilePath);
    if (Result == SysOkay)
    {
        __Driver__->Info.ModuleHandle = NULL;
    }

    LOGDRVLOADERC_PDebug("Successfully unloaded module\n");
    return Result;
}

int
ValidateDriverBinary(const char* __FilePath__)
{
    if (Probe_IF_Error(__FilePath__) || !__FilePath__)
    {
        PushError("ValidateDriverBinary", LOGDRVLOADERC_PError, "bad file path", -BadArguments);
        return -BadArguments;
    }

    /*Check if file exists and is readable*/
    if (VfsExists(__FilePath__) != SysOkay)
    {
        PushError("ValidateDriverBinary", LOGDRVLOADERC_PError, "file does not exist", -NoSuch);
        return -NoSuch;
    }

    /*Basic ELF header validation*/
    Elf64_Ehdr Header;
    long       HeaderLen = 0;

    if (VfsReadAll(__FilePath__, &Header, sizeof(Header), &HeaderLen) != SysOkay ||
        HeaderLen < (long)sizeof(Header))
    {
        PushError(
            "ValidateDriverBinary", LOGDRVLOADERC_PError, "failed to read elf header", -BadRead);
        return -BadRead;
    }

    /* ELF magic*/
    if (Header.e_ident[0] != 0x7F || Header.e_ident[1] != 'E' || Header.e_ident[2] != 'L' ||
        Header.e_ident[3] != 'F')
    {
        PushError("ValidateDriverBinary", LOGDRVLOADERC_PError, "bad elf magic", -BadEntity);
        return -BadEntity;
    }

    /* architecture (x86_64)*/
    if (Header.e_machine != 0x3E)
    {
        PushError(
            "ValidateDriverBinary", LOGDRVLOADERC_PError, "unsupported architecture", -Impilict);
        return -Impilict;
    }

    /* file type (relocatable or executable)*/
    if (Header.e_type != 1 && Header.e_type != 3)
    {
        PushError("ValidateDriverBinary", LOGDRVLOADERC_PError, "unsupported file type", -Impilict);
        return -Impilict;
    }

    return SysOkay;
}

int
GetDriverModuleInfo(const char* __FilePath__, DriverInfo* __Info__)
{
    if (Probe_IF_Error(__FilePath__) || !__FilePath__ || Probe_IF_Error(__Info__) || !__Info__)
    {
        PushError("GetDriverModuleInfo", LOGDRVLOADERC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    /*Validate the binary first*/
    int ValidationResult = ValidateDriverBinary(__FilePath__);
    if (ValidationResult != SysOkay)
    {
        PushError("GetDriverModuleInfo",
                  LOGDRVLOADERC_PError,
                  "binary validation failed",
                  ValidationResult);
        return -BadEntity;
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
