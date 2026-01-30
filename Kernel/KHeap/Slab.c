#include <Errnos.h>
#include <KHeap.h>
#include <__AXEKCONF__.h>

#ifdef LOGSLABC_Debug
#    define LOGSLABC_PDebug(fmt, ...) PDebug("[KERNEL>>Slab.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSLABC_PDebug(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSLABC_Logs
#    define LOGSLABC_PError(fmt, ...) PError("[KERNEL>>Slab.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSLABC_PError(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSLABC_Logs
#    define LOGSLABC_PWarn(fmt, ...) PWarn("[KERNEL>>Slab.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSLABC_PWarn(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSLABC_Logs
#    define LOGSLABC_PInfo(fmt, ...) PInfo("[KERNEL>>Slab.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSLABC_PInfo(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSLABC_Logs
#    define LOGSLABC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Slab.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSLABC_PSuccess(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

SlabCache*
GetSlabCache(size_t __Size__)
{
    /*Find the smallest cache that can fit the requested size*/
    for (uint32_t Index = 0; Index < MaxSlabSizes; Index++)
    {
        if (__Size__ <= KHeap.SlabSizes[Index])
        {
            return &KHeap.Caches[Index];
        }
    }
    PushError("GetSlabCache", LOGSLABC_PError, "no suitable cache found in GetSlabCache", -NoSuch);
    return Error_TO_Pointer(-NoSuch); /*No suitable cache found*/
}

Slab*
AllocateSlab(uint32_t __ObjectSize__)
{
    SysErr  err;
    SysErr* Error = &err;

    uint64_t PhysAddr = AllocPage();
    if (!PhysAddr)
    {
        PushError(
            "AllocateSlab", LOGSLABC_PError, "out of physical memory in AllocateSlab", -Depleted);
        return Error_TO_Pointer(-Depleted); /*Out of memory*/
    }

    Slab* NewSlab = (Slab*)PhysToVirt(PhysAddr);

    NewSlab->Next       = 0; /*Not linked yet*/
    NewSlab->FreeList   = 0; /*Will be set after creating objects*/
    NewSlab->ObjectSize = __ObjectSize__;
    NewSlab->FreeCount  = 0;         /*Will be incremented as objects are added*/
    NewSlab->Magic      = SlabMagic; /*Validation marker*/

    uint8_t*    ObjectPtr  = (uint8_t*)NewSlab + sizeof(Slab);
    uint8_t*    SlabEnd    = (uint8_t*)NewSlab + PageSize;
    SlabObject* PrevObject = 0; /*Previous object in free list*/

    uint32_t AlignedSize = (__ObjectSize__ + 15) & ~15;

    /*Link in reverse order*/
    while ((ObjectPtr + AlignedSize) <= SlabEnd)
    {
        SlabObject* Object = (SlabObject*)ObjectPtr;
        Object->Next       = PrevObject;
        Object->Magic      = FreeObjectMagic;
        PrevObject         = Object;
        ObjectPtr += AlignedSize;
        NewSlab->FreeCount++;
    }

    NewSlab->FreeList = PrevObject;

    return NewSlab;
}

void
FreeSlab(Slab* __Slab__, SysErr* __Err__)
{
    if (!__Slab__)
    {
        SlotError(__Err__, -BadArguments);
        PushError("FreeSlab",
                  LOGSLABC_PError,
                  "bad slab pointer in arguments of FreeSlab",
                  -BadArguments);
        return;
    }

    uint64_t PhysAddr = VirtToPhys(__Slab__);
    FreePage(PhysAddr, __Err__);
}
