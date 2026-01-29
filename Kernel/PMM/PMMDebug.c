#include <Errnos.h>
#include <PMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGPMMDEBUGC_Debug
#    define LOGPMMDEBUGC_PDebug(fmt, ...) PDebug("[KERNEL>>PMMDebug.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMDEBUGC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMDEBUGC_Logs
#    define LOGPMMDEBUGC_PError(fmt, ...) PError("[KERNEL>>PMMDebug.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMDEBUGC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMDEBUGC_Logs
#    define LOGPMMDEBUGC_PWarn(fmt, ...) PWarn("[KERNEL>>PMMDebug.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMDEBUGC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMDEBUGC_Logs
#    define LOGPMMDEBUGC_PInfo(fmt, ...) PInfo("[KERNEL>>PMMDebug.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMDEBUGC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPMMDEBUGC_Logs
#    define LOGPMMDEBUGC_PSuccess(fmt, ...) PSuccess("[KERNEL>>PMMDebug.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPMMDEBUGC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
PmmDumpStats(SysErr* __Err__)
{
    LOGPMMDEBUGC_PInfo("PMM Statistics:\n");

    unsigned long totalPages = atomic_load(&Pmm.Stats.TotalPages);
    unsigned long usedPages  = atomic_load(&Pmm.Stats.UsedPages);
    unsigned long freePages  = atomic_load(&Pmm.Stats.FreePages);
    unsigned long bitmapSize = atomic_load(&Pmm.BitmapSize);
#ifdef LOGPMMDEBUGC_Logs
    KrnPrintf("  Total Pages: %lu (%lu MB)\n", totalPages, (totalPages * PageSize) / (1024 * 1024));
    KrnPrintf("  Used Pages:  %lu (%lu MB)\n", usedPages, (usedPages * PageSize) / (1024 * 1024));
    KrnPrintf("  Free Pages:  %lu (%lu MB)\n", freePages, (freePages * PageSize) / (1024 * 1024));
    KrnPrintf("  Memory Usage: %lu%%\n", (usedPages * 100) / totalPages);
    KrnPrintf("  Bitmap Size: %lu entries (%lu KB)\n",
              bitmapSize,
              (bitmapSize * sizeof(uint64_t)) / 1024);
#endif
}

void
PmmDumpRegions(SysErr* __Err__)
{
    unsigned int regionCount = atomic_load(&Pmm.RegionCount);
    LOGPMMDEBUGC_PInfo("Memory Regions (%u total):\n", regionCount);

    const char* TypeNames[] = {"Usable", "Reserved", "Kernel", "Bad"};

    for (uint32_t Index = 0; Index < regionCount; Index++)
    {
        unsigned long base   = atomic_load(&Pmm.Regions[Index].Base);
        unsigned long length = atomic_load(&Pmm.Regions[Index].Length);
        unsigned int  type   = atomic_load(&Pmm.Regions[Index].Type);
#ifdef LOGPMMDEBUGC_Logs
        KrnPrintf("  [%u] 0x%016lx-0x%016lx %s (%lu MB)\n",
                  Index,
                  base,
                  base + length,
                  TypeNames[type],
                  length / (1024 * 1024));
#endif
    }
}