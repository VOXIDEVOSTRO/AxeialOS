#include <String.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGVMMC_Debug
#    define LOGVMMC_PDebug(fmt, ...) PDebug("[KERNEL>>VMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVMMC_PDebug(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVMMC_Logs
#    define LOGVMMC_PError(fmt, ...) PError("[KERNEL>>VMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVMMC_PError(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVMMC_Logs
#    define LOGVMMC_PWarn(fmt, ...) PWarn("[KERNEL>>VMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVMMC_PWarn(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVMMC_Logs
#    define LOGVMMC_PInfo(fmt, ...) PInfo("[KERNEL>>VMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVMMC_PInfo(fmt, ...)                                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGVMMC_Logs
#    define LOGVMMC_PSuccess(fmt, ...) PSuccess("[KERNEL>>VMM.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGVMMC_PSuccess(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

VirtualMemoryManager Vmm = {0};

void
InitializeVmm(SysErr* __Err__)
{
    __atomic_store_n(&Vmm.HhdmOffset, Pmm.HhdmOffset, __ATOMIC_SEQ_CST);
    LOGVMMC_PDebug("HHDM offset: 0x%016lx\n", __atomic_load_n(&Vmm.HhdmOffset, __ATOMIC_SEQ_CST));

    uint64_t CurrentCr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(CurrentCr3));
    uint64_t KernelPml4Physical = CurrentCr3 & 0xFFFFFFFFFFFFF000ULL;
    __atomic_store_n(&Vmm.KernelPml4Physical, KernelPml4Physical, __ATOMIC_SEQ_CST);

    LOGVMMC_PDebug("Present PML4 at: 0x%016lx\n",
                   __atomic_load_n(&Vmm.KernelPml4Physical, __ATOMIC_SEQ_CST));

    VirtualMemorySpace* KernelSpace = (VirtualMemorySpace*)PhysToVirt(AllocPage());
    if (!KernelSpace)
    {
        PushError("InitializeVmm",
                  LOGVMMC_PError,
                  "failed to allocate memory for kernel virtual space",
                  -BadAllocation);
        SlotError(__Err__, -BadAllocation);
        return;
    }
    __atomic_store_n(&Vmm.KernelSpace, KernelSpace, __ATOMIC_SEQ_CST);

    __atomic_store_n(&KernelSpace->PhysicalBase,
                     __atomic_load_n(&Vmm.KernelPml4Physical, __ATOMIC_SEQ_CST),
                     __ATOMIC_SEQ_CST);
    uint64_t* Pml4Virt =
        (uint64_t*)PhysToVirt(__atomic_load_n(&Vmm.KernelPml4Physical, __ATOMIC_SEQ_CST));
    __atomic_store_n(&KernelSpace->Pml4, Pml4Virt, __ATOMIC_SEQ_CST);
    __atomic_store_n(&KernelSpace->RefCount, 1, __ATOMIC_SEQ_CST);

    PublishBspKernelCr3();

    LOGVMMC_PSuccess("VMM active with Kernel space at 0x%016lx\n",
                     __atomic_load_n(&Vmm.KernelPml4Physical, __ATOMIC_SEQ_CST));
}

VirtualMemorySpace*
CreateVirtualSpace(void)
{
    VirtualMemorySpace* KernelSpace = __atomic_load_n(&Vmm.KernelSpace, __ATOMIC_SEQ_CST);
    if (!KernelSpace || !__atomic_load_n(&KernelSpace->Pml4, __ATOMIC_SEQ_CST))
    {
        PushError("CreateVirtualSpace", LOGVMMC_PError, "no kernel space available", -NotCanonical);
        return Error_TO_Pointer(-NotCanonical);
    }

    uint64_t SpacePhys = AllocPage();
    if (!SpacePhys)
    {
        PushError("CreateVirtualSpace",
                  LOGVMMC_PError,
                  "failed to allocate physical page for virtual space",
                  -NotCanonical);
        return Error_TO_Pointer(-NotCanonical);
    }

    SysErr  err;
    SysErr* Error = &err;

    VirtualMemorySpace* Space = (VirtualMemorySpace*)PhysToVirt(SpacePhys);
    if (Probe_IF_Error(Space) || !Space)
    {
        PushError("CreateVirtualSpace",
                  LOGVMMC_PError,
                  "failed to map virtual space struct",
                  -NotCanonical);
        FreePage(SpacePhys, Error);
        return Error_TO_Pointer(-NotCanonical);
    }

    uint64_t Pml4Phys = AllocPage();
    if (!Pml4Phys)
    {
        PushError("CreateVirtualSpace",
                  LOGVMMC_PError,
                  "failed to allocate physical page for PML4",
                  -NotCanonical);
        FreePage(SpacePhys, Error);
        return Error_TO_Pointer(-NotCanonical);
    }

    __atomic_store_n(&Space->PhysicalBase, Pml4Phys, __ATOMIC_SEQ_CST);
    uint64_t* Pml4Ptr = (uint64_t*)PhysToVirt(Pml4Phys);
    __atomic_store_n(&Space->Pml4, Pml4Ptr, __ATOMIC_SEQ_CST);
    __atomic_store_n(&Space->RefCount, 1, __ATOMIC_SEQ_CST);

    if (Probe_IF_Error(__atomic_load_n(&Space->Pml4, __ATOMIC_SEQ_CST)) ||
        !__atomic_load_n(&Space->Pml4, __ATOMIC_SEQ_CST))
    {
        PushError("CreateVirtualSpace",
                  LOGVMMC_PError,
                  "failed to map virtual space PML4",
                  -NotCanonical);
        FreePage(SpacePhys, Error);
        FreePage(Pml4Phys, Error);
        return Error_TO_Pointer(-NotCanonical);
    }

    uint64_t* Pml4 = __atomic_load_n(&Space->Pml4, __ATOMIC_SEQ_CST);
    for (uint64_t Index = 0; Index < PageTableEntries; Index++)
    {
        __atomic_store_n(&Pml4[Index], 0ULL, __ATOMIC_SEQ_CST);
    }

    uint64_t* KernelPml4 = __atomic_load_n(&KernelSpace->Pml4, __ATOMIC_SEQ_CST);
    for (uint64_t Index = 256; Index < PageTableEntries; Index++)
    {
        uint64_t val = __atomic_load_n(&KernelPml4[Index], __ATOMIC_SEQ_CST);
        __atomic_store_n(&Pml4[Index], val, __ATOMIC_SEQ_CST);
    }

    LOGVMMC_PDebug("Created virtual space: PML4=0x%016lx\n", Pml4Phys);
    return Space;
}

void
DestroyVirtualSpace(VirtualMemorySpace* __Space__, SysErr* __Err__)
{
    VirtualMemorySpace* KernelSpace = __atomic_load_n(&Vmm.KernelSpace, __ATOMIC_SEQ_CST);
    if (Probe_IF_Error(__Space__) || !__Space__ || __Space__ == KernelSpace)
    {
        PushError("DestroyVirtualSpace", LOGVMMC_PError, "bad virtual memory space", -NotCanonical);
        SlotError(__Err__, -NotCanonical);
        return;
    }

    SysErr  err;
    SysErr* Error = &err;

    uint32_t old = __atomic_fetch_sub(&__Space__->RefCount, 1, __ATOMIC_SEQ_CST);
    if (old > 1)
    {
        PushError(
            "DestroyVirtualSpace", LOGVMMC_PError, "virtual space still has references", -Dangling);
        SlotError(__Err__, -Dangling);
        LOGVMMC_PDebug("Virtual space still has %u references\n",
                       __atomic_load_n(&__Space__->RefCount, __ATOMIC_SEQ_CST));
        return;
    }

    LOGVMMC_PDebug("Destroying virtual space: PML4=0x%016lx\n",
                   __atomic_load_n(&__Space__->PhysicalBase, __ATOMIC_SEQ_CST));

    uint64_t* Pml4 = __atomic_load_n(&__Space__->Pml4, __ATOMIC_SEQ_CST);
    for (uint64_t Pml4Index = 0; Pml4Index < 256; Pml4Index++)
    {
        uint64_t pml4e = __atomic_load_n(&Pml4[Pml4Index], __ATOMIC_SEQ_CST);
        if (!(pml4e & PTEPRESENT))
        {
            continue;
        }

        uint64_t  PdptPhys = pml4e & 0x000FFFFFFFFFF000ULL;
        uint64_t* Pdpt     = (uint64_t*)PhysToVirt(PdptPhys);
        if (Probe_IF_Error(Pdpt) || !Pdpt)
        {
            continue;
        }

        for (uint64_t PdptIndex = 0; PdptIndex < PageTableEntries; PdptIndex++)
        {
            uint64_t pdpte = __atomic_load_n(&Pdpt[PdptIndex], __ATOMIC_SEQ_CST);
            if (!(pdpte & PTEPRESENT))
            {
                continue;
            }

            uint64_t  PdPhys = pdpte & 0x000FFFFFFFFFF000ULL;
            uint64_t* Pd     = (uint64_t*)PhysToVirt(PdPhys);
            if (Probe_IF_Error(Pd) || !Pd)
            {
                continue;
            }

            for (uint64_t PdIndex = 0; PdIndex < PageTableEntries; PdIndex++)
            {
                uint64_t pde = __atomic_load_n(&Pd[PdIndex], __ATOMIC_SEQ_CST);
                if (!(pde & PTEPRESENT))
                {
                    continue;
                }

                FreePage(pde & 0x000FFFFFFFFFF000ULL, Error);
            }

            FreePage(PdPhys, Error);
        }

        FreePage(PdptPhys, Error);
    }

    FreePage(__atomic_load_n(&__Space__->PhysicalBase, __ATOMIC_SEQ_CST), Error);

    FreePage(VirtToPhys(__Space__), Error);
}

int
MapPage(VirtualMemorySpace* __Space__,
        uint64_t            __VirtAddr__,
        uint64_t            __PhysAddr__,
        uint64_t            __Flags__)
{
    if (Probe_IF_Error(__Space__) || !__Space__ || (__VirtAddr__ % PageSize) != 0 ||
        (__PhysAddr__ % PageSize) != 0)
    {
        PushError("MapPage", LOGVMMC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    if (__PhysAddr__ > 0x000FFFFFFFFFF000ULL)
    {
        PushError("MapPage", LOGVMMC_PError, "physical address out of range", -NotCanonical);
        return -NotCanonical;
    }

    uint64_t* Pml4 = __atomic_load_n(&__Space__->Pml4, __ATOMIC_SEQ_CST);
    uint64_t* Pt   = GetPageTable(Pml4, __VirtAddr__, 1, 1);
    if (Probe_IF_Error(Pt) || !Pt)
    {
        PushError("MapPage",
                  LOGVMMC_PError,
                  "failed to get page table for virtual address",
                  -NotCanonical);
        return -NotCanonical;
    }

    uint64_t PtIndex = (__VirtAddr__ >> 12) & 0x1FF;

    uint64_t Entry = __atomic_load_n(&Pt[PtIndex], __ATOMIC_SEQ_CST);
    if (Entry & PTEPRESENT)
    {
        LOGVMMC_PDebug("Page already mapped at 0x%016lx\n", __VirtAddr__);
        return SysOkay;
    }

    uint64_t newe = (__PhysAddr__ & 0x000FFFFFFFFFF000ULL) | __Flags__ | PTEPRESENT;
    __atomic_store_n(&Pt[PtIndex], newe, __ATOMIC_SEQ_CST);

    SysErr  err;
    SysErr* Error = &err;
    FlushTlb(__VirtAddr__, Error);

    LOGVMMC_PDebug(
        "Mapped 0x%016lx -> 0x%016lx (flags=0x%lx)\n", __VirtAddr__, __PhysAddr__, __Flags__);
    return SysOkay;
}

int
MapRangeZeroed(VirtualMemorySpace* __Space__,
               uint64_t            __VaStart__,
               uint64_t            __Len__,
               uint64_t            __Flags__)
{
    uint64_t Pages = (__Len__ + PageSize - 1) / PageSize;
    uint64_t Phys  = AllocPages(Pages);
    if (!Phys)
    {
        PushError("MapRangeZeroed",
                  LOGVMMC_PError,
                  "failed to allocate physical pages for mapping",
                  -NotCanonical);
        return -NotCanonical;
    }

    uint64_t Va   = __VaStart__;
    uint64_t Pcur = Phys;
    uint64_t I    = 0;

    for (I = 0; I < Pages; I++)
    {
        if (MapPage(__Space__, Va, Pcur, __Flags__) != SysOkay)
        {
            PushError("MapRangeZeroed", LOGVMMC_PError, "failed to map page in range", -BadReturn);
            return -BadReturn;
        }
        memset(PhysToVirt(Pcur), 0, PageSize);
        Va += PageSize;
        Pcur += PageSize;
    }
    return SysOkay;
}

int
UnmapPage(VirtualMemorySpace* __Space__, uint64_t __VirtAddr__)
{
    if (Probe_IF_Error(__Space__) || !__Space__ || (__VirtAddr__ % PageSize) != 0)
    {
        PushError("UnmapPage", LOGVMMC_PError, "bad arguments", -BadArguments);
        return -BadArguments;
    }

    uint64_t* Pml4 = __atomic_load_n(&__Space__->Pml4, __ATOMIC_SEQ_CST);
    uint64_t* Pt   = GetPageTable(Pml4, __VirtAddr__, 1, 0);
    if (Probe_IF_Error(Pt) || !Pt)
    {
        PushError("UnmapPage",
                  LOGVMMC_PError,
                  "failed to get page table for virtual address",
                  -NotCanonical);
        return -NotCanonical;
    }

    uint64_t PtIndex = (__VirtAddr__ >> 12) & 0x1FF;

    uint64_t Entry = __atomic_load_n(&Pt[PtIndex], __ATOMIC_SEQ_CST);
    if (!(Entry & PTEPRESENT))
    {
        PushError("UnmapPage", LOGVMMC_PError, "page not mapped", -Dangling);
        return -Dangling;
    }

    __atomic_store_n(&Pt[PtIndex], 0ULL, __ATOMIC_SEQ_CST);

    SysErr  err;
    SysErr* Error = &err;
    FlushTlb(__VirtAddr__, Error);

    LOGVMMC_PDebug("Unmapped 0x%016lx\n", __VirtAddr__);
    return SysOkay;
}

uint64_t
GetPhysicalAddress(VirtualMemorySpace* __Space__, uint64_t __VirtAddr__)
{
    if (Probe_IF_Error(__Space__) || !__Space__)
    {
        PushError("GetPhysicalAddress", LOGVMMC_PError, "bad virtual memory space", -NotCanonical);
        return -NotCanonical;
    }

    uint64_t* Pml4 = __atomic_load_n(&__Space__->Pml4, __ATOMIC_SEQ_CST);
    uint64_t* Pt   = GetPageTable(Pml4, __VirtAddr__, 1, 0);
    if (Probe_IF_Error(Pt) || !Pt)
    {
        PushError("GetPhysicalAddress",
                  LOGVMMC_PError,
                  "failed to get page table for virtual address",
                  -NotCanonical);
        return -NotCanonical;
    }

    uint64_t PtIndex = (__VirtAddr__ >> 12) & 0x1FF;

    uint64_t Entry = __atomic_load_n(&Pt[PtIndex], __ATOMIC_SEQ_CST);
    if (!(Entry & PTEPRESENT))
    {
        PushError("GetPhysicalAddress", LOGVMMC_PError, "page not mapped", -Dangling);
        return -Dangling;
    }

    uint64_t PhysBase = Entry & 0x000FFFFFFFFFF000ULL;

    uint64_t Offset = __VirtAddr__ & 0xFFF;

    return PhysBase + Offset;
}

void
SwitchVirtualSpace(VirtualMemorySpace* __Space__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Space__) || !__Space__)
    {
        PushError("SwitchVirtualSpace", LOGVMMC_PError, "bad virtual memory space", -NotCanonical);
        SlotError(__Err__, -NotCanonical);
        return;
    }

    uint64_t phys = __atomic_load_n(&__Space__->PhysicalBase, __ATOMIC_SEQ_CST);
    __asm__ volatile("mov %0, %%cr3" ::"r"(phys) : "memory");

    LOGVMMC_PDebug("Switched to virtual space: PML4=0x%016lx\n", phys);
}