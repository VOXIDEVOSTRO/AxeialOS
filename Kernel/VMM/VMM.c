#include <VMM.h>

VirtualMemoryManager Vmm = {0};

void
InitializeVmm(void)
{
    PInfo("Initializing Virtual Memory Manager...\n");

    Vmm.HhdmOffset = Pmm.HhdmOffset;
    PDebug("Using HHDM offset: 0x%016lx\n", Vmm.HhdmOffset);

    uint64_t CurrentCr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(CurrentCr3));
    Vmm.KernelPml4Physical = CurrentCr3 & 0xFFFFFFFFFFFFF000ULL; /* Clear lower 12 bits */

    PDebug("Current PML4 at: 0x%016lx\n", Vmm.KernelPml4Physical);

    Vmm.KernelSpace = (VirtualMemorySpace*)PhysToVirt(AllocPage());
    if (!Vmm.KernelSpace)
    {
        PError("Failed to allocate kernel virtual space\n");
        return;
    }

    Vmm.KernelSpace->PhysicalBase = Vmm.KernelPml4Physical; /* Physical address of PML4 */
    Vmm.KernelSpace->Pml4 =
        (uint64_t*)PhysToVirt(Vmm.KernelPml4Physical); /* Virtual address for PML4 */
    Vmm.KernelSpace->RefCount = 1;                     /* Initialize reference count */

    PSuccess("VMM initialized with kernel space at 0x%016lx\n", Vmm.KernelPml4Physical);
}

VirtualMemorySpace*
CreateVirtualSpace(void)
{
    if (!Vmm.KernelSpace || !Vmm.KernelSpace->Pml4)
    {
        PError("VMM not properly initialized\n");
        return 0;
    }

    uint64_t SpacePhys = AllocPage();
    if (!SpacePhys)
    {
        PError("Failed to allocate virtual space structure\n");
        return 0;
    }

    VirtualMemorySpace* Space = (VirtualMemorySpace*)PhysToVirt(SpacePhys);
    if (!Space)
    {
        PError("HHDM conversion failed for space structure\n");
        FreePage(SpacePhys);
        return 0;
    }

    uint64_t Pml4Phys = AllocPage();
    if (!Pml4Phys)
    {
        PError("Failed to allocate PML4\n");
        FreePage(SpacePhys);
        return 0;
    }

    Space->PhysicalBase = Pml4Phys;
    Space->Pml4         = (uint64_t*)PhysToVirt(Pml4Phys);
    Space->RefCount     = 1;

    if (!Space->Pml4)
    {
        PError("HHDM conversion failed for PML4\n");
        FreePage(SpacePhys);
        FreePage(Pml4Phys);
        return 0;
    }

    for (uint64_t Index = 0; Index < PageTableEntries; Index++)
    {
        Space->Pml4[Index] = 0;
    }

    for (uint64_t Index = 256; Index < PageTableEntries; Index++)
    {
        Space->Pml4[Index] = Vmm.KernelSpace->Pml4[Index];
    }

    PDebug("Created virtual space: PML4=0x%016lx\n", Pml4Phys);
    return Space;
}

void
DestroyVirtualSpace(VirtualMemorySpace* __Space__)
{
    if (!__Space__ || __Space__ == Vmm.KernelSpace)
    {
        PWarn("Cannot destroy kernel space or null space\n");
        return;
    }

    __Space__->RefCount--;
    if (__Space__->RefCount > 0)
    {
        PDebug("Virtual space still has %u references\n", __Space__->RefCount);
        return;
    }

    PDebug("Destroying virtual space: PML4=0x%016lx\n", __Space__->PhysicalBase);

    for (uint64_t Pml4Index = 0; Pml4Index < 256; Pml4Index++)
    {
        /* Skip entries that are not present (not mapped) */
        if (!(__Space__->Pml4[Pml4Index] & PTEPRESENT))
        {
            continue;
        }

        uint64_t  PdptPhys = __Space__->Pml4[Pml4Index] & 0x000FFFFFFFFFF000ULL;
        uint64_t* Pdpt     = (uint64_t*)PhysToVirt(PdptPhys);
        if (!Pdpt)
        {
            continue;
        }

        for (uint64_t PdptIndex = 0; PdptIndex < PageTableEntries; PdptIndex++)
        {
            if (!(Pdpt[PdptIndex] & PTEPRESENT))
            {
                continue;
            }

            uint64_t  PdPhys = Pdpt[PdptIndex] & 0x000FFFFFFFFFF000ULL;
            uint64_t* Pd     = (uint64_t*)PhysToVirt(PdPhys);
            if (!Pd)
            {
                continue;
            }

            for (uint64_t PdIndex = 0; PdIndex < PageTableEntries; PdIndex++)
            {
                if (!(Pd[PdIndex] & PTEPRESENT))
                {
                    continue;
                }

                FreePage(Pd[PdIndex] & 0x000FFFFFFFFFF000ULL);
            }

            /* Free the Page Directory page itself */
            FreePage(PdPhys);
        }

        /* Free the Page Directory Pointer Table page */
        FreePage(PdptPhys);
    }

    /* Free the root Page Map Level 4 table */
    FreePage(__Space__->PhysicalBase);

    FreePage(VirtToPhys(__Space__));

    PDebug("Virtual space destroyed\n");
}

int
MapPage(VirtualMemorySpace* __Space__,
        uint64_t            __VirtAddr__,
        uint64_t            __PhysAddr__,
        uint64_t            __Flags__)
{
    if (!__Space__ || (__VirtAddr__ % PageSize) != 0 || (__PhysAddr__ % PageSize) != 0)
    {
        PError("Invalid parameters for MapPage\n");
        return 0;
    }

    if (__PhysAddr__ > 0x000FFFFFFFFFF000ULL)
    {
        PError("Physical address too high: 0x%016lx\n", __PhysAddr__);
        return 0;
    }

    uint64_t* Pt = GetPageTable(__Space__->Pml4, __VirtAddr__, 1, 1);
    if (!Pt)
    {
        PError("Failed to get page table for mapping\n");
        return 0;
    }

    uint64_t PtIndex = (__VirtAddr__ >> 12) & 0x1FF;

    if (Pt[PtIndex] & PTEPRESENT)
    {
        PDebug("Page already mapped at 0x%016lx\n", __VirtAddr__);
        return 1;
    }

    Pt[PtIndex] = (__PhysAddr__ & 0x000FFFFFFFFFF000ULL) | __Flags__ | PTEPRESENT;

    FlushTlb(__VirtAddr__);

    PDebug("Mapped 0x%016lx -> 0x%016lx (flags=0x%lx)\n", __VirtAddr__, __PhysAddr__, __Flags__);
    return 1;
}

int
UnmapPage(VirtualMemorySpace* __Space__, uint64_t __VirtAddr__)
{
    if (!__Space__ || (__VirtAddr__ % PageSize) != 0)
    {
        PError("Invalid parameters for UnmapPage\n");
        return 0;
    }

    uint64_t* Pt = GetPageTable(__Space__->Pml4, __VirtAddr__, 1, 0);
    if (!Pt)
    {
        PWarn("No page table for address 0x%016lx\n", __VirtAddr__);
        return 0;
    }

    /* Calculate the page table index for this virtual address */
    uint64_t PtIndex = (__VirtAddr__ >> 12) & 0x1FF;

    if (!(Pt[PtIndex] & PTEPRESENT))
    {
        PWarn("Page not mapped at 0x%016lx\n", __VirtAddr__);
        return 0;
    }

    Pt[PtIndex] = 0;

    FlushTlb(__VirtAddr__);

    /* Log the successful unmapping operation */
    PDebug("Unmapped 0x%016lx\n", __VirtAddr__);
    return 1;
}

uint64_t
GetPhysicalAddress(VirtualMemorySpace* __Space__, uint64_t __VirtAddr__)
{
    if (!__Space__)
    {
        PError("Invalid space for GetPhysicalAddress\n");
        return 0;
    }

    uint64_t* Pt = GetPageTable(__Space__->Pml4, __VirtAddr__, 1, 0);
    if (!Pt)
    {
        return 0;
    }

    /* Calculate the index in the page table */
    uint64_t PtIndex = (__VirtAddr__ >> 12) & 0x1FF;

    if (!(Pt[PtIndex] & PTEPRESENT))
    {
        return 0;
    }

    uint64_t PhysBase = Pt[PtIndex] & 0x000FFFFFFFFFF000ULL;

    uint64_t Offset = __VirtAddr__ & 0xFFF;

    return PhysBase + Offset;
}

void
SwitchVirtualSpace(VirtualMemorySpace* __Space__)
{
    if (!__Space__)
    {
        PError("Cannot switch to null virtual space\n");
        return;
    }

    __asm__ volatile("mov %0, %%cr3" ::"r"(__Space__->PhysicalBase) : "memory");

    PDebug("Switched to virtual space: PML4=0x%016lx\n", __Space__->PhysicalBase);
}
