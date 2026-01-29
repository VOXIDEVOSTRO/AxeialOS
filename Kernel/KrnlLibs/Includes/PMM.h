#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <KrnPrintf.h>
/*Limine*/
#include <LimineHHDM.h>
#include <LimineMmap.h>

#define PageSize          4096
#define PageSizeBits      12
#define BitsPerByte       8
#define BitsPerUint64     64
#define MaxMemoryRegions  64
#define PmmBitmapNotFound 0xFFFFFFFFFFFFFFFF

#define MemoryTypeUsable   0
#define MemoryTypeReserved 1
#define MemoryTypeKernel   2
#define MemoryTypeBad      3

#define MaxPhysPages (1ULL << 24)

typedef struct
{
    uint64_t TotalPages;
    uint64_t UsedPages;
    uint64_t FreePages;
    uint64_t ReservedPages;
    uint64_t KernelPages;
    uint64_t BitmapPages;

} PmmStats;

typedef struct
{
    uint64_t Base;
    uint64_t Length;
    uint32_t Type;

} MemoryRegion;

typedef struct
{
    uint64_t*    Bitmap;
    uint64_t     BitmapSize;
    uint64_t     TotalPages;
    uint64_t     LastAllocHint;
    uint64_t     HhdmOffset;
    MemoryRegion Regions[MaxMemoryRegions];
    uint32_t     RegionCount;
    PmmStats     Stats;

} PhysicalMemoryManager;

extern PhysicalMemoryManager Pmm;
extern _Atomic uint32_t      PageRefCounts[MaxPhysPages];

void*    PhysToVirt(uint64_t __PhysAddr__);
uint64_t VirtToPhys(void* __VirtAddr__);

void     InitializePmm(SysErr* __Err__);
uint64_t AllocPage(void);
void     FreePage(uint64_t __PhysAddr__, SysErr* __Err__);
uint64_t AllocPages(size_t __Count__);
void     FreePages(uint64_t __PhysAddr__, size_t __Count__, SysErr* __Err__);

void PmmDumpStats(SysErr* __Err__);          //
void PmmDumpRegions(SysErr* __Err__);        //
int  PmmValidatePage(uint64_t __PhysAddr__); //

void InitializeBitmap(SysErr* __Err__);                       //
void ParseMemoryMap(SysErr* __Err__);                         //
void MarkMemoryRegions(SysErr* __Err__);                      //
void SetBitmapBit(uint64_t __PageIndex__, SysErr* __Err__);   //
void ClearBitmapBit(uint64_t __PageIndex__, SysErr* __Err__); //
int  TestBitmapBit(uint64_t __PageIndex__);                   //

void     IncPageRef(uint64_t __Phys__, SysErr* __Err__);
void     DecPageRef(uint64_t __Phys__, SysErr* __Err__);
uint32_t GetPageRef(uint64_t __Phys__);

KEXPORT(InitializePmm);
KEXPORT(AllocPage);
KEXPORT(FreePage);
KEXPORT(AllocPages);
KEXPORT(FreePages);
KEXPORT(PhysToVirt);
KEXPORT(VirtToPhys);
KEXPORT(Pmm);
