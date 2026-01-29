#include <Errnos.h>
#include <PMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGBITMAPC_Debug
#    define LOGBITMAPC_PDebug(fmt, ...) PDebug("[KERNEL>>Bitmap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBITMAPC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBITMAPC_Logs
#    define LOGBITMAPC_PError(fmt, ...) PError("[KERNEL>>Bitmap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBITMAPC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBITMAPC_Logs
#    define LOGBITMAPC_PWarn(fmt, ...) PWarn("[KERNEL>>Bitmap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBITMAPC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBITMAPC_Logs
#    define LOGBITMAPC_PInfo(fmt, ...) PInfo("[KERNEL>>Bitmap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBITMAPC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBITMAPC_Logs
#    define LOGBITMAPC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Bitmap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBITMAPC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
InitializeBitmap(SysErr* __Err__)
{
    /*In 64-bit entries*/
    atomic_store(&Pmm.BitmapSize,
                 (atomic_load(&Pmm.TotalPages) + BitsPerUint64 - 1) / BitsPerUint64);
    uint64_t bitmapSize  = atomic_load(&Pmm.BitmapSize);
    uint64_t BitmapBytes = bitmapSize * sizeof(uint64_t);

    uint64_t BitmapPhys  = 0;
    uint32_t regionCount = atomic_load(&Pmm.RegionCount);

    for (uint32_t Index = 0; Index < regionCount; Index++)
    {
        uint32_t type   = atomic_load(&Pmm.Regions[Index].Type);
        uint64_t length = atomic_load(&Pmm.Regions[Index].Length);

        if (type == MemoryTypeUsable && length >= BitmapBytes)
        {
            BitmapPhys = atomic_load(&Pmm.Regions[Index].Base);
            LOGBITMAPC_PDebug("Found bitmap location in region %u\n", Index);
            break;
        }
    }

    if (BitmapPhys == 0)
    {
        SlotError(__Err__, -NoSuch);
        PushError(
            "InitializeBitmap", LOGBITMAPC_PError, "Failed to find memory for bitmap", -NoSuch);
        return;
    }

    atomic_store(&Pmm.Bitmap, (uint64_t*)PhysToVirt(BitmapPhys));

    /*Initialize all bits to 0 (free)*/
    for (uint64_t Index = 0; Index < bitmapSize; Index++)
    {
        atomic_store(&Pmm.Bitmap[Index], 0);
    }

    LOGBITMAPC_PSuccess("Bitmap initialized at 0x%016lx\n", BitmapPhys);
}

void
SetBitmapBit(uint64_t __PageIndex__, SysErr* __Err__)
{
    uint64_t ByteIndex = __PageIndex__ / BitsPerUint64;
    uint64_t BitIndex  = __PageIndex__ % BitsPerUint64;

    atomic_fetch_or(&Pmm.Bitmap[ByteIndex], (1ULL << BitIndex));
}

void
ClearBitmapBit(uint64_t __PageIndex__, SysErr* __Err__)
{
    uint64_t ByteIndex = __PageIndex__ / BitsPerUint64;
    uint64_t BitIndex  = __PageIndex__ % BitsPerUint64;

    atomic_fetch_and(&Pmm.Bitmap[ByteIndex], ~(1ULL << BitIndex));
}

int
TestBitmapBit(uint64_t __PageIndex__)
{
    uint64_t ByteIndex = __PageIndex__ / BitsPerUint64;
    uint64_t BitIndex  = __PageIndex__ % BitsPerUint64;

    uint64_t Value = atomic_load(&Pmm.Bitmap[ByteIndex]);
    return (Value & (1ULL << BitIndex)) != Nothing;
}