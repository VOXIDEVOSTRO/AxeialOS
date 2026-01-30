#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <KrnPrintf.h>
#include <LimineServices.h>

#define MaxCPUs 256

typedef enum
{

    CPU_STATUS_OFFLINE,
    CPU_STATUS_STARTING,
    CPU_STATUS_ONLINE,
    CPU_STATUS_FAILED

} CpuStatus;

typedef struct
{
    uint32_t                ApicId;
    uint32_t                CpuNumber;
    CpuStatus               Status;
    volatile uint32_t       Started;
    struct limine_smp_info* LimineInfo;

} CpuInfo;

typedef struct
{
    uint32_t CpuCount;
    uint32_t OnlineCpus;
    uint32_t BspApicId;
    CpuInfo  Cpus[MaxCPUs];

} SmpManager;

extern SmpManager        Smp;
extern volatile uint32_t CpuStartupCount;
extern volatile bool     SmpInitialized;

void     InitializeSmp(SysErr* __Err__);
void     ApEntryPoint(struct limine_smp_info* __CpuInfo__);
uint32_t GetCurrentCpuId(void);

bool InitCoreAps(SysErr* __Err__);
bool ReloadCoreAps(uint32_t __CpuNumber__);
bool SetApStack(SysErr* __Err__);
void ReloadStack(uint32_t __CpuNumber__);

void GlobalizePerCPUMem(SysErr* __Err__);