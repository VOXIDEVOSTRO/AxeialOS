#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <GDT.h>
#include <IDT.h>
#include <KrnPrintf.h>
#include <PerCPUData.h>
#include <SMP.h>

#define ApTrampolineBase    0x7000
#define ApStackSize         0x4000
#define ApStartupTimeout    10000
#define ApicDeliveryTimeout 10000

#define IpiInit         0x00C500
#define IpiInitDeassert 0x008500
#define IpiStartup      0x000600

#define ApTrampolineSignature 0xDEADBEEF

#define SMPCPUStackSize 0x4000

typedef enum
{
    AP_STATUS_OFFLINE,
    AP_STATUS_STARTING,
    AP_STATUS_ONLINE,
    AP_STATUS_FAILED
} ApStatus;

typedef struct
{
    uint32_t          ApicId;
    uint32_t          CpuNumber;
    ApStatus          Status;
    uint64_t          StackTop;
    volatile uint32_t Started;

} ApInfo;

#define TrampolineSignatureOffset 0x200
#define TrampolinePageDirOffset   0x208
#define TrampolineStackOffset     0x210
#define TrampolineEntryOffset     0x218
#define TrampolineGdtOffset       0x220
#define TrampolineGdtDescOffset   0x228

extern ApInfo            ApProcessors[MaxCPUs];
extern volatile uint32_t ApStartupCount;
extern SpinLock          SMPLock;

extern uint16_t         CpuTssSelectors[MaxCPUs];
extern TaskStateSegment CpuTssStructures[MaxCPUs];

uint32_t    GetCurrentCpuId(void);
PerCpuData* GetPerCpuData(uint32_t __CpuNumber__);

KEXPORT(GetCurrentCpuId);
KEXPORT(GetPerCpuData);