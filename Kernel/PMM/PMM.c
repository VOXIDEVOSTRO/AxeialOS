#include <Errnos.h>
#include <PMM.h>

PhysicalMemoryManager Pmm = {0};

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

    return PmmBitmapNotFound;
}

void
InitializePmm(SysErr* __Err__)
{
    if (!HhdmRequest.response)
    {
        SlotError(__Err__, -NotCanonical);
        return;
    }
    atomic_store(&Pmm.HhdmOffset, HhdmRequest.response->offset);
    PDebug("HHDM offset: 0x%016lx\n", atomic_load(&Pmm.HhdmOffset));

    ParseMemoryMap(__Err__);
    if (atomic_load(&Pmm.RegionCount) == 0)
    {
        SlotError(__Err__, -NoSuch);
        return;
    }

    InitializeBitmap(__Err__);
    if (atomic_load(&Pmm.Bitmap) == 0)
    {
        SlotError(__Err__, -NotInit);
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

    PSuccess("PMM initialized: %lu MB total, %lu MB free\n",
             (atomic_load(&Pmm.Stats.TotalPages) * PageSize) / (1024 * 1024),
             (atomic_load(&Pmm.Stats.FreePages) * PageSize) / (1024 * 1024));
}

uint64_t
AllocPage(void)
{
    uint64_t PageIndex = FindFreePage();

    if (PageIndex == PmmBitmapNotFound)
    {
        return Nothing;
    }

    SysErr  err;
    SysErr* Error = &err;

    /*Mark page as used in bitmap*/
    SetBitmapBit(PageIndex, Error);
    atomic_fetch_add(&Pmm.Stats.UsedPages, 1);
    atomic_fetch_sub(&Pmm.Stats.FreePages, 1);

    uint64_t PhysAddr = PageIndex * PageSize;
    PDebug("Allocated page: 0x%016lx (index %lu)\n", PhysAddr, PageIndex);

    return PhysAddr;
}

void
FreePage(uint64_t __PhysAddr__, SysErr* __Err__)
{
    if (PmmValidatePage(__PhysAddr__) != SysOkay)
    {
        SlotError(__Err__, -NotCanonical);
        return;
    }

    uint64_t PageIndex = __PhysAddr__ / PageSize;

    if (!TestBitmapBit(PageIndex))
    {
        SlotError(__Err__, -Overflow);
        return;
    }

    /*Mark page as free in bitmap*/
    ClearBitmapBit(PageIndex, __Err__);
    atomic_fetch_sub(&Pmm.Stats.UsedPages, 1);
    atomic_fetch_add(&Pmm.Stats.FreePages, 1);

    PDebug("Freed a page: 0x%016lx (index %lu)\n", __PhysAddr__, PageIndex);
}

uint64_t
AllocPages(size_t __Count__)
{
    if (__Count__ == 0)
    {
        return Nothing;
    }

    if (__Count__ == 1)
    {
        return AllocPage();
    }

    if (__Count__ > atomic_load(&Pmm.Stats.FreePages))
    {
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
            PDebug("Allocated %lu contiguous pages at: 0x%016lx\n", __Count__, PhysAddr);

            return PhysAddr;
        }
    }

    return Nothing;
}

void
FreePages(uint64_t __PhysAddr__, size_t __Count__, SysErr* __Err__)
{
    if (__Count__ == 0)
    {
        SlotError(__Err__, -TooLess);
        return;
    }

    PDebug("Freeing %lu pages starting at 0x%016lx\n", __Count__, __PhysAddr__);

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
        return -NotCanonical;
    }
    if ((__PhysAddr__ % PageSize) != 0)
    {
        return -NotCanonical;
    }
    if ((__PhysAddr__ / PageSize) >= atomic_load(&Pmm.TotalPages))
    {
        return -TooMany;
    }
    return SysOkay;
}