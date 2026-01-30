#include <Errnos.h>
#include <PMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGMEMMAPC_Debug
#    define LOGMEMMAPC_PDebug(fmt, ...) PDebug("[KERNEL>>MemMap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMEMMAPC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMEMMAPC_Logs
#    define LOGMEMMAPC_PError(fmt, ...) PError("[KERNEL>>MemMap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMEMMAPC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMEMMAPC_Logs
#    define LOGMEMMAPC_PWarn(fmt, ...) PWarn("[KERNEL>>MemMap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMEMMAPC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMEMMAPC_Logs
#    define LOGMEMMAPC_PInfo(fmt, ...) PInfo("[KERNEL>>MemMap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMEMMAPC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMEMMAPC_Logs
#    define LOGMEMMAPC_PSuccess(fmt, ...) PSuccess("[KERNEL>>MemMap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMEMMAPC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
ParseMemoryMap(SysErr* __Err__)
{
    if (!MemmapRequest.response)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("ParseMemoryMap",
                  LOGMEMMAPC_PError,
                  "memmap request failed from bootloader[Limine]",
                  -NotInitilized);
        return;
    }

    Pmm.RegionCount            = 0;
    uint64_t HighestAddr       = 0;
    uint64_t TotalUsableMemory = 0;

    /*Process each memory map entry*/
    for (uint64_t Index = 0; Index < MemmapRequest.response->entry_count; Index++)
    {
        struct limine_memmap_entry* Entry = MemmapRequest.response->entries[Index];

        if (Pmm.RegionCount >= MaxMemoryRegions)
        {
            break;
        }

        /*Store region information*/
        Pmm.Regions[Pmm.RegionCount].Base   = Entry->base;
        Pmm.Regions[Pmm.RegionCount].Length = Entry->length;

        /*Classify region type based on Limine type*/
        switch (Entry->type)
        {
            case LIMINE_MEMMAP_USABLE:
                Pmm.Regions[Pmm.RegionCount].Type = MemoryTypeUsable;
                break;
            case LIMINE_MEMMAP_KERNEL_AND_MODULES:
                Pmm.Regions[Pmm.RegionCount].Type = MemoryTypeKernel;
                break;
            default:
                Pmm.Regions[Pmm.RegionCount].Type = MemoryTypeReserved;
                break;
        }

        /*Track the highest address seen for total memory calculation*/
        uint64_t EndAddr = Entry->base + Entry->length;
        if (EndAddr > HighestAddr)
        {
            HighestAddr = EndAddr;
        }

        if (Entry->type == LIMINE_MEMMAP_USABLE)
        {
            TotalUsableMemory += Entry->length;
        }

        Pmm.RegionCount++;

        LOGMEMMAPC_PDebug("Region %lu: 0x%016lx-0x%016lx Type=%u\n",
                          Index,
                          Entry->base,
                          EndAddr,
                          Pmm.Regions[Pmm.RegionCount - 1].Type);
    }

    /*Calculate total pages in system (round up)*/
    Pmm.TotalPages = (TotalUsableMemory + PageSize - 1) / PageSize;
    LOGMEMMAPC_PInfo(
        "Total pages: %lu (%lu MB)\n", Pmm.TotalPages, (Pmm.TotalPages * PageSize) / (1024 * 1024));
}

void
MarkMemoryRegions(SysErr* __Err__)
{
    /*default to all used*/
    for (uint64_t Index = 0; Index < Pmm.TotalPages; Index++)
    {
        SetBitmapBit(Index, __Err__);
    }

    uint64_t TotalFreePages = 0;
    for (uint32_t RegionIndex = 0; RegionIndex < Pmm.RegionCount; RegionIndex++)
    {
        if (Pmm.Regions[RegionIndex].Type == MemoryTypeUsable)
        {
            uint64_t StartPage = Pmm.Regions[RegionIndex].Base / PageSize;
            uint64_t PageCount = Pmm.Regions[RegionIndex].Length / PageSize;

            /*Mark each page in the region as free*/
            for (uint64_t Page = StartPage; Page < StartPage + PageCount; Page++)
            {
                if (Page < Pmm.TotalPages)
                {
                    ClearBitmapBit(Page, __Err__);
                }
            }

            TotalFreePages += PageCount;
            LOGMEMMAPC_PDebug(
                "Marked %lu pages free at 0x%016lx\n", PageCount, Pmm.Regions[RegionIndex].Base);
        }
    }

    uint64_t BitmapPhys      = VirtToPhys(Pmm.Bitmap);
    uint64_t BitmapStartPage = BitmapPhys / PageSize;
    uint64_t BitmapPageCount = (Pmm.BitmapSize * sizeof(uint64_t) + PageSize - 1) / PageSize;

    for (uint64_t Page = BitmapStartPage; Page < BitmapStartPage + BitmapPageCount; Page++)
    {
        SetBitmapBit(Page, __Err__);
    }

    LOGMEMMAPC_PInfo("Protected %lu bitmap pages from allocation\n", BitmapPageCount);
    LOGMEMMAPC_PSuccess("Memory regions marked: %lu pages available\n",
                        TotalFreePages - BitmapPageCount);
}
