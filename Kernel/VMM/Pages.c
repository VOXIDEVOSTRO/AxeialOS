#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGPAGESC_Debug
#    define LOGPAGESC_PDebug(fmt, ...) PDebug("[KERNEL>>Pages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPAGESC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPAGESC_Logs
#    define LOGPAGESC_PError(fmt, ...) PError("[KERNEL>>Pages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPAGESC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPAGESC_Logs
#    define LOGPAGESC_PWarn(fmt, ...) PWarn("[KERNEL>>Pages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPAGESC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPAGESC_Logs
#    define LOGPAGESC_PInfo(fmt, ...) PInfo("[KERNEL>>Pages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPAGESC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPAGESC_Logs
#    define LOGPAGESC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Pages.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPAGESC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

uint64_t*
GetPageTable(uint64_t* __Pml4__, uint64_t __VirtAddr__, int __Level__, int __Create__)
{
    uint32_t  Pml4Index    = (__VirtAddr__ >> 39) & 0x1FF;
    uint32_t  PdptIndex    = (__VirtAddr__ >> 30) & 0x1FF;
    uint32_t  PdIndex      = (__VirtAddr__ >> 21) & 0x1FF;
    uint64_t* CurrentTable = __Pml4__;
    uint32_t  CurrentIndex = Pml4Index;

    for (int Level = 4; Level > __Level__; Level--)
    {
        uint64_t Entry = __atomic_load_n(&CurrentTable[CurrentIndex], __ATOMIC_SEQ_CST);
        if (!(Entry & PTEPRESENT))
        {
            if (!__Create__)
            {
                PushError("GetPageTable",
                          LOGPAGESC_PError,
                          "page table entry not present",
                          -BadAllocation);
                return Error_TO_Pointer(-BadAllocation);
            }

            uint64_t NewTablePhys = AllocPage();
            if (!NewTablePhys)
            {
                PushError("GetPageTable",
                          LOGPAGESC_PError,
                          "failed to allocate page for new page table",
                          -BadAllocation);
                return Error_TO_Pointer(-BadAllocation);
            }

            uint64_t* NewTable = (uint64_t*)PhysToVirt(NewTablePhys);

            for (uint32_t Index = 0; Index < PageTableEntries; Index++)
            {
                __atomic_store_n(&NewTable[Index], 0ULL, __ATOMIC_SEQ_CST);
            }

            uint64_t NewEntry = NewTablePhys | PTEPRESENT | PTEWRITABLE | PTEUSER;
            __atomic_store_n(&CurrentTable[CurrentIndex], NewEntry, __ATOMIC_SEQ_CST);

            LOGPAGESC_PDebug("Created page table at level %d: 0x%016lx\n", Level - 1, NewTablePhys);
            Entry = NewEntry;
        }

        uint64_t NextTablePhys = Entry & 0xFFFFFFFFFFFFF000ULL;
        CurrentTable           = (uint64_t*)PhysToVirt(NextTablePhys);

        switch (Level - 1)
        {
            case 3:
                CurrentIndex = PdptIndex;
                break;
            case 2:
                CurrentIndex = PdIndex;
                break;
            case 1:
                return CurrentTable;
        }
    }

    return CurrentTable;
}

void
FlushTlb(uint64_t __VirtAddr__, SysErr* __Err__ __attribute((unused)))
{
    __asm__ volatile("invlpg (%0)" ::"r"(__VirtAddr__) : "memory");
}

void
FlushAllTlb(SysErr* __Err__ __attribute((unused)))
{
    uint64_t Cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(Cr3));
    __asm__ volatile("mov %0, %%cr3" ::"r"(Cr3) : "memory");
}

_Atomic uint64_t BspKernelCr3 = 0;

void /*For the APs*/
PublishBspKernelCr3(void)
{
    uint64_t CR3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(CR3));
    atomic_store_explicit(&BspKernelCr3, CR3, memory_order_release);
}
