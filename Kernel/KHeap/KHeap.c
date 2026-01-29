#include <Errnos.h>
#include <KHeap.h>
#include <__AXEKCONF__.h>

#ifdef LOGKHEAPC_Debug
#    define LOGKHEAPC_PDebug(fmt, ...) PDebug("[KERNEL>>KHeap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKHEAPC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKHEAPC_Logs
#    define LOGKHEAPC_PError(fmt, ...) PError("[KERNEL>>KHeap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKHEAPC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKHEAPC_Logs
#    define LOGKHEAPC_PWarn(fmt, ...) PWarn("[KERNEL>>KHeap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKHEAPC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKHEAPC_Logs
#    define LOGKHEAPC_PInfo(fmt, ...) PInfo("[KERNEL>>KHeap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKHEAPC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKHEAPC_Logs
#    define LOGKHEAPC_PSuccess(fmt, ...) PSuccess("[KERNEL>>KHeap.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKHEAPC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

KernelHeapManager KHeap;
SpinLock          KHeapLock;

void
InitializeKHeap(SysErr* __Err__ _unused)
{
    /*?^2*/
    KHeap.SlabSizes[0] = 16;
    KHeap.SlabSizes[1] = 32;
    KHeap.SlabSizes[2] = 64;
    KHeap.SlabSizes[3] = 128;
    KHeap.SlabSizes[4] = 256;
    KHeap.SlabSizes[5] = 512;
    KHeap.SlabSizes[6] = 1024;
    KHeap.SlabSizes[7] = 2048;
    KHeap.CacheCount   = MaxSlabSizes;

    for (uint32_t Index = 0; Index < MaxSlabSizes; Index++)
    {
        SlabCache* Cache      = &KHeap.Caches[Index];
        Cache->Slabs          = 0; /*No slabs allocated initially*/
        Cache->ObjectSize     = KHeap.SlabSizes[Index];
        Cache->ObjectsPerSlab = (PageSize - sizeof(Slab)) / Cache->ObjectSize;

        /* One object per slab */
        if (Cache->ObjectsPerSlab == 0)
        {
            Cache->ObjectsPerSlab = 1;
        }
    }

    LOGKHEAPC_PSuccess("KHeap initialized with %u slab caches\n", KHeap.CacheCount);
}

void*
KMalloc(size_t __Size__)
{
    if (__Size__ == 0)
    {
        PushError("KMalloc", LOGKHEAPC_PError, "bad arguments in KMalloc", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    /*Large allocations bypass slab and go directly to PMM*/
    if (__Size__ > 2048)
    {
        /*Calculate pages needed, rounding up*/
        uint64_t Pages    = (__Size__ + PageSize - 1) / PageSize;
        uint64_t PhysAddr = AllocPages(Pages);
        if (!PhysAddr)
        {
            PushError("KMalloc", LOGKHEAPC_PError, "out of memory in KMalloc", -Depleted);
            return Error_TO_Pointer(-Depleted); /*Out of memory*/
        }
        return PhysToVirt(PhysAddr);
    }

    SlabCache* Cache = GetSlabCache(__Size__);
    if (!Cache)
    {
        PushError("KMalloc",
                  LOGKHEAPC_PError,
                  "cannot fine a suitable cache in KMalloc",
                  Pointer_TO_Error(Cache));
        return Error_TO_Pointer(-NoSuch); /*No suitable cache found*/
    }

    SysErr  err;
    SysErr* Error = &err;

    Slab* CurrentSlab = Cache->Slabs;
    while (CurrentSlab)
    {
        if (CurrentSlab->FreeCount > 0)
        {
            break; /*Found a slab with free objects*/
        }
        CurrentSlab = CurrentSlab->Next;
    }

    /*Alloc one if none*/
    if (!CurrentSlab)
    {
        CurrentSlab = AllocateSlab(Cache->ObjectSize);
        if (!CurrentSlab)
        {
            PushError("KMalloc",
                      LOGKHEAPC_PError,
                      "bad allocation for slab in KMalloc",
                      Pointer_TO_Error(CurrentSlab));
            return Error_TO_Pointer(-BadAllocation); /*Failed to allocate new slab*/
        }

        CurrentSlab->Next = Cache->Slabs;
        Cache->Slabs      = CurrentSlab;
    }

    SlabObject* Object = CurrentSlab->FreeList;
    if (!Object)
    {
        PushError("KMalloc",
                  LOGKHEAPC_PError,
                  "bad object in current slab free list in KMalloc",
                  -NotCanonical);
        return Error_TO_Pointer(-NotCanonical); /*Should not happen if FreeCount > 0*/
    }

    CurrentSlab->FreeList = Object->Next;
    CurrentSlab->FreeCount--;

    uint8_t* ObjectBytes = (uint8_t*)Object;
    for (uint32_t Index = 0; Index < Cache->ObjectSize; Index++)
    {
        ObjectBytes[Index] = 0;
    }

    return (void*)Object;
}

void
KFree(void* __Ptr__, SysErr* __Err__)
{
    if (!__Ptr__)
    {
        SlotError(__Err__, -BadArguments);
        PushError("KFree", LOGKHEAPC_PError, "bad arguments in KFree", -BadArguments);
        return;
    }

    /*Mask off the page offset*/
    uint64_t ObjectAddr = (uint64_t)__Ptr__;
    uint64_t SlabAddr   = ObjectAddr & ~(PageSize - 1);
    Slab*    TargetSlab = (Slab*)SlabAddr;

    if (TargetSlab->Magic != SlabMagic)
    {
        /*Large?*/
        uint64_t PhysAddr = VirtToPhys(__Ptr__);
        FreePage(PhysAddr, __Err__);
        SlotError(__Err__, -NotCanonical);
        PushError("KFree", LOGKHEAPC_PError, "bad magic in slab in KFree", -NotCanonical);
        return;
    }

    SlabObject* Object   = (SlabObject*)__Ptr__;
    Object->Next         = TargetSlab->FreeList;
    Object->Magic        = FreeObjectMagic;
    TargetSlab->FreeList = Object;
    TargetSlab->FreeCount++;
}
