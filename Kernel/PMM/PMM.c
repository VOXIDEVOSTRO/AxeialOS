#include <Errnos.h>
#include <PMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGPMMC_Debug
#    define LOGPMMC_PDebug(fmt, ...) PDebug("[KERNEL>>PMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMC_PDebug(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMC_Logs
#    define LOGPMMC_PError(fmt, ...) PError("[KERNEL>>PMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMC_PError(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMC_Logs
#    define LOGPMMC_PWarn(fmt, ...) PWarn("[KERNEL>>PMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMC_PWarn(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMC_Logs
#    define LOGPMMC_PInfo(fmt, ...) PInfo("[KERNEL>>PMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMC_PInfo(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMC_Logs
#    define LOGPMMC_PSuccess(fmt, ...) PSuccess("[KERNEL>>PMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMC_PSuccess(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*Atomic monsters*/
#define ATOMIC_LOAD(ptr)           atomic_load(&(ptr))
#define ATOMIC_STORE(ptr, val)     atomic_store(&(ptr), (val))
#define ATOMIC_FETCH_ADD(ptr, val) atomic_fetch_add(&(ptr), (val))
#define ATOMIC_FETCH_SUB(ptr, val) atomic_fetch_sub(&(ptr), (val))
#define ATOMIC_FETCH_OR(ptr, val)  atomic_fetch_or(&(ptr), (val))
#define ATOMIC_FETCH_AND(ptr, val) atomic_fetch_and(&(ptr), (val))
#define ATOMIC_EXCHANGE(ptr, val)  atomic_exchange(&(ptr), (val))

PhysicalMemoryManager Pmm = {0};
_Atomic uint32_t      PageRefCounts[MaxPhysPages];

uint64_t
FindFreePage(void)
{
    uint64_t StartHint  = atomic_load(&Pmm.LastAllocHint);
    uint64_t totalPages = atomic_load(&Pmm.TotalPages);

    /*Look from hint forward to end of memory*/
    for (uint64_t Index = StartHint; Index < totalPages; Index++)
    {
        if (!TestBitmapBit(Index))
        {
            atomic_store(&Pmm.LastAllocHint, Index + 1);
            return Index;
        }
    }

    /*Look from beginning to hint if not found above*/
    for (uint64_t Index = 0; Index < StartHint; Index++)
    {
        if (!TestBitmapBit(Index))
        {
            atomic_store(&Pmm.LastAllocHint, Index + 1);
            return Index;
        }
    }

    PushError("FindFreePage", LOGPMMC_PError, "pmm bitmap not found", -NoSuch);
    return PmmBitmapNotFound;
}

void
InitializePmm(SysErr* __Err__)
{
    if (!HhdmRequest.response)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("InitializePmm",
                  LOGPMMC_PError,
                  "hhdm not received from bootloader[Limine]",
                  -NotInitilized);
        return;
    }
    atomic_store(&Pmm.HhdmOffset, HhdmRequest.response->offset);
    LOGPMMC_PDebug("HHDM offset: 0x%016lx\n", atomic_load(&Pmm.HhdmOffset));

    ParseMemoryMap(__Err__);
    if (atomic_load(&Pmm.RegionCount) == 0)
    {
        SlotError(__Err__, -NoSuch);
        PushError("InitializePmm", LOGPMMC_PError, "no valid memory regions found", -NoSuch);
        return;
    }

    InitializeBitmap(__Err__);
    if (atomic_load(&Pmm.Bitmap) == 0)
    {
        SlotError(__Err__, -NotInitilized);
        PushError("InitializePmm", LOGPMMC_PError, "bitmap not initialized", -NotInitilized);
        return;
    }

    /*Markup*/
    MarkMemoryRegions(__Err__);

    /*Calculate final memory statistics*/
    atomic_store(&Pmm.Stats.TotalPages, atomic_load(&Pmm.TotalPages));
    atomic_store(&Pmm.Stats.UsedPages, 0);
    atomic_store(&Pmm.Stats.FreePages, 0);

    uint64_t totalPages = atomic_load(&Pmm.TotalPages);
    for (uint64_t Index = 0; Index < totalPages; Index++)
    {
        if (TestBitmapBit(Index))
        {
            atomic_fetch_add(&Pmm.Stats.UsedPages, 1);
        }
        else
        {
            atomic_fetch_add(&Pmm.Stats.FreePages, 1);
        }
    }

    LOGPMMC_PSuccess("PMM initialized: %lu MB total, %lu MB free\n",
                     (atomic_load(&Pmm.Stats.TotalPages) * PageSize) / (1024 * 1024),
                     (atomic_load(&Pmm.Stats.FreePages) * PageSize) / (1024 * 1024));
}

uint64_t
AllocPage(void)
{
    uint64_t PageIndex = FindFreePage();

    if (PageIndex == PmmBitmapNotFound)
    {
        PushError("AllocPage", LOGPMMC_PError, "no free page found in bitmap", -NoSuch);
        return Nothing;
    }

    SysErr  err;
    SysErr* Error = &err;

    /*Mark page as used in bitmap*/
    SetBitmapBit(PageIndex, Error);
    atomic_fetch_add(&Pmm.Stats.UsedPages, 1);
    atomic_fetch_sub(&Pmm.Stats.FreePages, 1);

    uint64_t PhysAddr = PageIndex * PageSize;
    LOGPMMC_PDebug("Allocated page: 0x%016lx (index %lu)\n", PhysAddr, PageIndex);

    return PhysAddr;
}

void
FreePage(uint64_t __PhysAddr__, SysErr* __Err__)
{
    if (PmmValidatePage(__PhysAddr__) != SysOkay)
    {
        SlotError(__Err__, -NotCanonical);
        PushError("FreePage", LOGPMMC_PError, "address is not canonical", -NotCanonical);
        return;
    }

    uint64_t PageIndex = __PhysAddr__ / PageSize;

    if (!TestBitmapBit(PageIndex))
    {
        SlotError(__Err__, -Overflow);
        PushError("FreePage", LOGPMMC_PError, "page was not allocated", -Overflow);
        return;
    }

    /*Mark page as free in bitmap*/
    ClearBitmapBit(PageIndex, __Err__);
    atomic_fetch_sub(&Pmm.Stats.UsedPages, 1);
    atomic_fetch_add(&Pmm.Stats.FreePages, 1);

    LOGPMMC_PDebug("Freed a page: 0x%016lx (index %lu)\n", __PhysAddr__, PageIndex);
}

uint64_t
AllocPages(size_t __Count__)
{
    if (__Count__ == 0)
    {
        PushError("AllocPages", LOGPMMC_PError, "count cannot be zero", -TooLess);
        return Nothing;
    }

    if (__Count__ == 1)
    {
        return AllocPage();
    }

    if (__Count__ > atomic_load(&Pmm.Stats.FreePages))
    {
        PushError("AllocPages", LOGPMMC_PError, "not enough free pages", -TooMany);
        return Nothing;
    }

    uint64_t totalPages = atomic_load(&Pmm.TotalPages);

    /*Search for contiguous free block*/
    for (uint64_t StartIndex = 0; StartIndex <= totalPages - __Count__; StartIndex++)
    {
        int Found = 1;

        for (size_t Offset = 0; Offset < __Count__; Offset++)
        {
            if (TestBitmapBit(StartIndex + Offset))
            {
                Found = 0;
                break;
            }
        }

        if (Found)
        {
            /*Mark all pages in block as used*/
            for (size_t Offset = 0; Offset < __Count__; Offset++)
            {
                SysErr  err;
                SysErr* Error = &err;
                SetBitmapBit(StartIndex + Offset, Error);
            }

            atomic_fetch_add(&Pmm.Stats.UsedPages, __Count__);
            atomic_fetch_sub(&Pmm.Stats.FreePages, __Count__);

            uint64_t PhysAddr = StartIndex * PageSize;
            LOGPMMC_PDebug("Allocated %lu contiguous pages at: 0x%016lx\n", __Count__, PhysAddr);

            return PhysAddr;
        }
    }

    PushError("AllocPages", LOGPMMC_PError, "not enough contiguous pages", -TooMany);
    return Nothing;
}

void
FreePages(uint64_t __PhysAddr__, size_t __Count__, SysErr* __Err__)
{
    if (__Count__ == 0)
    {
        SlotError(__Err__, -TooLess);
        PushError("FreePages", LOGPMMC_PError, "count cannot be zero", -TooLess);
        return;
    }

    LOGPMMC_PDebug("Freeing %lu pages starting at 0x%016lx\n", __Count__, __PhysAddr__);

    /*Linearly free*/
    for (size_t Index = 0; Index < __Count__; Index++)
    {
        FreePage(__PhysAddr__ + (Index * PageSize), __Err__);
    }
}

int
PmmValidatePage(uint64_t __PhysAddr__)
{
    if (__PhysAddr__ == 0)
    {
        PushError("PmmValidatePage", LOGPMMC_PError, "address cannot be zero", -NotCanonical);
        return -NotCanonical;
    }
    if ((__PhysAddr__ % PageSize) != 0)
    {
        PushError("PmmValidatePage", LOGPMMC_PError, "address is not page aligned", -NotCanonical);
        return -NotCanonical;
    }
    if ((__PhysAddr__ / PageSize) >= atomic_load(&Pmm.TotalPages))
    {
        PushError("PmmValidatePage", LOGPMMC_PError, "address is outside of memory map", -TooMany);
        return -TooMany;
    }
    return SysOkay;
}

void
IncPageRef(uint64_t __Phys__, SysErr* __Err__)
{
    ATOMIC_FETCH_ADD(PageRefCounts[__Phys__ >> 12], 1);
}

void
DecPageRef(uint64_t __Phys__, SysErr* __Err__)
{
    if (ATOMIC_FETCH_SUB(PageRefCounts[__Phys__ >> 12], 1) == 1)
    {
        FreePage(__Phys__, __Err__);
    }
}

uint32_t
GetPageRef(uint64_t __Phys__)
{
    return ATOMIC_LOAD(PageRefCounts[__Phys__ >> 12]);
}
