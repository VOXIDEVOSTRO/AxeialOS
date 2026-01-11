#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <KExports.h>
#include <KMods.h>
#include <Sync.h>
#include <VFS.h>

#define MaxDrivers        512
#define MaxDriverTypes    64
#define MaxDriversPerType 32
#define DriverPathBase    "/sys/drvs"
#define DriverNameMaxLen  64
#define DriverPathMaxLen  256

typedef enum
{
    DriverStateUnloaded,
    DriverStateLoading,
    DriverStateLoaded,
    DriverStateActive,
    DriverStateUnloading,
    DriverStateFailed

} DriverState;

typedef enum
{
    DriverTypeDefault,
    DriverTypeInput,
    DriverTypeStorage,
    DriverTypeNetwork,
    DriverTypeGraphics,
    DriverTypeAudio,
    DriverTypeUSB,
    DriverTypePCI,
    DriverTypeSerial
} DriverType;

typedef struct DriverInfo
{
    char       Name[DriverNameMaxLen];
    char       Description[128];
    char       Author[64];
    char       Version[32];
    uint32_t   VersionCode;
    DriverType Type;
    char       SubType[32];
    uint32_t   Priority;
    uint32_t   Flags;

    uint16_t* SupportedVendors;
    uint16_t* SupportedDevices;
    uint32_t  SupportedCount;

    char          FilePath[DriverPathMaxLen];
    ModuleRecord* ModuleHandle;

} DriverInfo;

typedef struct DriverEntry
{
    DriverInfo  Info;
    DriverState State;
    uint32_t    RefCount;
    uint64_t    LoadTime;
    uint64_t    LastUsed;
    void*       PrivateData;

    struct DriverEntry* Next;
    struct DriverEntry* Prev;

} DriverEntry;

typedef struct DriverTypeRegistry
{
    char         TypeName[32];
    DriverType   Type;
    DriverEntry* Drivers[MaxDriversPerType];
    uint32_t     DriverCount;
    SpinLock     TypeLock;

} DriverTypeRegistry;

typedef struct DriverManagerContext
{
    DriverTypeRegistry Types[MaxDriverTypes];
    uint32_t           TypeCount;
    DriverEntry*       AllDrivers;
    uint32_t           TotalDrivers;
    SpinLock           ManagerLock;
    bool               Initialized;

} DriverManagerContext;

extern DriverManagerContext DriverManager;
extern const char*          DriverTypes[];

int  InitializeDriverManager(void);
void ShutdownDriverManager(SysErr* __Err__);
int  ScanDriverDirectory(void);
int  RefreshDriverDatabase(void);

int      RegisterDriverType(const char* __TypeName__, DriverType __Type__);
int      UnregisterDriverType(DriverType __Type__);
uint32_t GetDriverTypeCount(void);

int           GetDriverModuleInfo(const char* __FilePath__, DriverInfo* __Info__);
int           LoadDriver(const char* __DriverName__);
int           UnloadDriver(const char* __DriverName__);
int           ReloadDriver(const char* __DriverName__);
DriverEntry*  FindDriverByName(const char* __DriverName__);
DriverEntry*  FindDriverByPath(const char* __FilePath__);
DriverEntry** FindDriversByType(DriverType __Type__, uint32_t* __Count__);

int ParseDriverManifest(const char* __FilePath__, DriverInfo* __Info__);
int ValidateDriverBinary(const char* __FilePath__);
int LoadDriverModule(DriverEntry* __Driver__);
int UnloadDriverModule(DriverEntry* __Driver__);

int AddDriverToRegistry(DriverInfo* __Info__);
int RemoveDriverFromRegistry(const char* __DriverName__);
int UpdateDriverInfo(const char* __DriverName__, DriverInfo* __NewInfo__);

uint32_t GetDriverRefCount(const char* __DriverName__);
int      IncrementDriverRef(const char* __DriverName__);
int      DecrementDriverRef(const char* __DriverName__);

DriverEntry** GetAllDrivers(uint32_t* __Count__);
DriverEntry** GetLoadedDrivers(uint32_t* __Count__);
DriverEntry** GetActiveDrivers(uint32_t* __Count__);

void DumpDriverInfo(DriverEntry* __Driver__, SysErr* __Err__);
void DumpAllDrivers(SysErr* __Err__);
void DumpDriversByType(DriverType __Type__, SysErr* __Err__);
void DumpDriverStatistics(SysErr* __Err__);

int  CreateDriverPath(DriverType  __Type__,
                      const char* __SubType__,
                      char*       __OutPath__,
                      uint32_t    __PathLen__);
int  ParseDriverPath(const char* __Path__,
                     DriverType* __Type__,
                     char*       __SubType__,
                     uint32_t    __SubTypeLen__);
bool IsValidDriverPath(const char* __Path__);

KEXPORT(InitializeDriverManager);
KEXPORT(LoadDriver);
KEXPORT(UnloadDriver);
KEXPORT(FindDriverByName);
KEXPORT(FindDriversByType);
KEXPORT(GetAllDrivers);
KEXPORT(GetLoadedDrivers);
KEXPORT(IncrementDriverRef);
KEXPORT(DecrementDriverRef);
