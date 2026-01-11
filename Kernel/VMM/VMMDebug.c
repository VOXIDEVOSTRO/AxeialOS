#include <VMM.h>

static int
IsValidPhysicalAddress(uint64_t __PhysAddr__)
{
    _Atomic uint64_t PhysAddr = ATOMIC_VAR_INIT(__PhysAddr__);

    if (atomic_load(&PhysAddr) == 0)
    {
        return -NotCanonical;
    }

    if ((atomic_load(&PhysAddr) & 0xFFF) != 0)
    {
        return -NotCanonical;
    }

    for (uint32_t Index = 0; Index < Pmm.RegionCount; Index++)
    {
        _Atomic uint64_t RegionStart = ATOMIC_VAR_INIT(Pmm.Regions[Index].Base);
        _Atomic uint64_t RegionEnd =
            ATOMIC_VAR_INIT(Pmm.Regions[Index].Base + Pmm.Regions[Index].Length);

        if (atomic_load(&PhysAddr) >= atomic_load(&RegionStart) &&
            atomic_load(&PhysAddr) < atomic_load(&RegionEnd))
        {
            return SysOkay;
        }
    }

    return -NotCanonical;
}

static int
IsValidHhdmAddress(uint64_t __VirtAddr__)
{
    _Atomic uint64_t VirtAddr = ATOMIC_VAR_INIT(__VirtAddr__);

    if (atomic_load(&VirtAddr) < Vmm.HhdmOffset)
    {
        return -NotCanonical;
    }

    uint64_t PhysAddr = atomic_load(&VirtAddr) - Vmm.HhdmOffset;

    return IsValidPhysicalAddress(PhysAddr);
}

static int
IsSafeToAccess(uint64_t* __Ptr__)
{
    _Atomic uint64_t* PtrAtomic = (_Atomic uint64_t*)__Ptr__;

    if (Probe_IF_Error(__Ptr__) || !PtrAtomic)
    {
        return -BadArgs;
    }

    _Atomic uint64_t VirtAddr = ATOMIC_VAR_INIT((uint64_t)__Ptr__);

    return IsValidHhdmAddress(atomic_load(&VirtAddr));
}

void
VmmDumpSpace(VirtualMemorySpace* __Space__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Space__) || !__Space__)
    {
        SlotError(__Err__, -NotCanonical);
        return;
    }

    if (!IsValidPhysicalAddress(__Space__->PhysicalBase))
    {
        SlotError(__Err__, -NotCanonical);
        return;
    }

    if (Probe_IF_Error(__Space__->Pml4) || !__Space__->Pml4 ||
        !IsValidHhdmAddress((uint64_t)__Space__->Pml4))
    {
        SlotError(__Err__, -NotCanonical);
        return;
    }

    PInfo("Virtual Memory Space Information:\n");
    KrnPrintf("  PML4 Physical: 0x%016lx\n", __Space__->PhysicalBase);
    KrnPrintf("  PML4 Virtual:  0x%016lx\n", (uint64_t)__Space__->Pml4);
    KrnPrintf("  Reference Count: %u\n", __Space__->RefCount);

    _Atomic uint64_t MappedPages     = ATOMIC_VAR_INIT(0);
    _Atomic uint64_t ValidatedTables = ATOMIC_VAR_INIT(0);
    _Atomic uint64_t SkippedTables   = ATOMIC_VAR_INIT(0);

    for (uint64_t Pml4Index = 0; Pml4Index < PageTableEntries; Pml4Index++)
    {
        _Atomic uint64_t* Pml4Atomic = (_Atomic uint64_t*)__Space__->Pml4;
        uint64_t          Pml4Entry  = atomic_load(&Pml4Atomic[Pml4Index]);

        if (!(Pml4Entry & PTEPRESENT))
        {
            continue;
        }

        uint64_t PdptPhys = Pml4Entry & 0x000FFFFFFFFFF000ULL;
        if (!IsValidPhysicalAddress(PdptPhys))
        {
            atomic_fetch_add(&SkippedTables, 1);
            continue;
        }

        uint64_t* Pdpt = (uint64_t*)PhysToVirt(PdptPhys);
        if (!IsSafeToAccess(Pdpt))
        {
            atomic_fetch_add(&SkippedTables, 1);
            continue;
        }

        atomic_fetch_add(&ValidatedTables, 1);

        for (uint64_t PdptIndex = 0; PdptIndex < PageTableEntries; PdptIndex++)
        {
            _Atomic uint64_t* PdptAtomic = (_Atomic uint64_t*)Pdpt;
            uint64_t          PdptEntry  = atomic_load(&PdptAtomic[PdptIndex]);

            if (!(PdptEntry & PTEPRESENT))
            {
                continue;
            }

            if (PdptEntry & PTEHUGEPAGE)
            {
                atomic_fetch_add(&MappedPages, 262144);
                continue;
            }

            uint64_t PdPhys = PdptEntry & 0x000FFFFFFFFFF000ULL;
            if (!IsValidPhysicalAddress(PdPhys))
            {
                continue;
            }

            uint64_t* Pd = (uint64_t*)PhysToVirt(PdPhys);
            if (!IsSafeToAccess(Pd))
            {
                continue;
            }

            for (uint64_t PdIndex = 0; PdIndex < PageTableEntries; PdIndex++)
            {
                _Atomic uint64_t* PdAtomic = (_Atomic uint64_t*)Pd;
                uint64_t          PdEntry  = atomic_load(&PdAtomic[PdIndex]);

                if (!(PdEntry & PTEPRESENT))
                {
                    continue;
                }

                if (PdEntry & PTEHUGEPAGE)
                {
                    atomic_fetch_add(&MappedPages, 512);
                    continue;
                }

                uint64_t PtPhys = PdEntry & 0x000FFFFFFFFFF000ULL;
                if (!IsValidPhysicalAddress(PtPhys))
                {
                    continue;
                }

                uint64_t* Pt = (uint64_t*)PhysToVirt(PtPhys);
                if (!IsSafeToAccess(Pt))
                {
                    continue;
                }

                for (uint64_t PtIndex = 0; PtIndex < PageTableEntries; PtIndex++)
                {
                    _Atomic uint64_t* PtAtomic = (_Atomic uint64_t*)Pt;
                    if (atomic_load(&PtAtomic[PtIndex]) & PTEPRESENT)
                    {
                        atomic_fetch_add(&MappedPages, 1);
                    }
                }
            }
        }
    }

    KrnPrintf("  Validated Tables: %lu\n", atomic_load(&ValidatedTables));
    KrnPrintf("  Skipped Tables: %lu\n", atomic_load(&SkippedTables));
    KrnPrintf(
        "  Mapped Pages: %lu (%lu KB)\n", atomic_load(&MappedPages), atomic_load(&MappedPages) * 4);
}

void
VmmDumpStats(SysErr* __Err__)
{
    if (!Vmm.HhdmOffset)
    {
        SlotError(__Err__, -NotCanonical);
        return;
    }

    PInfo("VMM Statistics:\n");
    KrnPrintf("  HHDM Offset: 0x%016lx\n", Vmm.HhdmOffset);
    KrnPrintf("  Kernel PML4: 0x%016lx\n", Vmm.KernelPml4Physical);

    KrnPrintf("  Memory Map Regions: %u\n", Pmm.RegionCount);
    for (uint32_t Index = 0; Index < Pmm.RegionCount && Index < 5; Index++)
    {
        KrnPrintf("    [%u] 0x%016lx-0x%016lx (%lu MB)\n",
                  Index,
                  Pmm.Regions[Index].Base,
                  Pmm.Regions[Index].Base + Pmm.Regions[Index].Length,
                  Pmm.Regions[Index].Length / (1024 * 1024));
    }
    if (Pmm.RegionCount > 5)
    {
        KrnPrintf("    ... and %u more regions\n", Pmm.RegionCount - 5);
    }

    if (Vmm.KernelSpace)
    {
        KrnPrintf("  Kernel Space: 0x%016lx\n", (uint64_t)Vmm.KernelSpace);
        VmmDumpSpace(Vmm.KernelSpace, __Err__);
    }
    else
    {
        PWarn("  No kernel space available\n");
    }
}