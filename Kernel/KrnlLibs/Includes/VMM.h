#pragma once

#include <AllTypes.h>
#include <KrnPrintf.h>
#include <PMM.h>

#define PageSize            4096
#define PageTableEntries    512
#define VirtualAddressSpace 0x0000800000000000ULL
#define KernelVirtualBase   0xFFFF800000000000ULL
#define UserVirtualBase     0x0000000000400000ULL

#define PTEPRESENT      (1ULL << 0)
#define PTEWRITABLE     (1ULL << 1)
#define PTEUSER         (1ULL << 2)
#define PTEWRITETHROUGH (1ULL << 3)
#define PTECACHEDISABLE (1ULL << 4)
#define PTEACCESSED     (1ULL << 5)
#define PTEDIRTY        (1ULL << 6)
#define PTEHUGEPAGE     (1ULL << 7)
#define PTEGLOBAL       (1ULL << 8)
#define PTENOEXECUTE    (1ULL << 63)

typedef struct
{
    uint64_t* Pml4;
    uint64_t  PhysicalBase;
    uint32_t  RefCount;

} VirtualMemorySpace;

typedef struct
{
    VirtualMemorySpace* KernelSpace;
    uint64_t            HhdmOffset;
    uint64_t            KernelPml4Physical;

} VirtualMemoryManager;

extern VirtualMemoryManager Vmm;

void                InitializeVmm(void);
VirtualMemorySpace* CreateVirtualSpace(void);
void                DestroyVirtualSpace(VirtualMemorySpace* __Space__);
int                 MapPage(VirtualMemorySpace* __Space__,
                            uint64_t            __VirtAddr__,
                            uint64_t            __PhysAddr__,
                            uint64_t            __Flags__);
int                 UnmapPage(VirtualMemorySpace* __Space__, uint64_t __VirtAddr__);
uint64_t            GetPhysicalAddress(VirtualMemorySpace* __Space__, uint64_t __VirtAddr__);
void                SwitchVirtualSpace(VirtualMemorySpace* __Space__);

uint64_t* GetPageTable(uint64_t* __Pml4__, uint64_t __VirtAddr__, int __Level__, int __Create__);
void      FlushTlb(uint64_t __VirtAddr__);
void      FlushAllTlb(void);

void VmmDumpSpace(VirtualMemorySpace* __Space__); //
void VmmDumpStats(void);                          //

KEXPORT(InitializeVmm);
KEXPORT(CreateVirtualSpace);
KEXPORT(DestroyVirtualSpace);
KEXPORT(SwitchVirtualSpace);
KEXPORT(MapPage);
KEXPORT(UnmapPage);
KEXPORT(GetPhysicalAddress);
KEXPORT(GetPageTable);
KEXPORT(FlushTlb);
KEXPORT(FlushAllTlb);
KEXPORT(Vmm);