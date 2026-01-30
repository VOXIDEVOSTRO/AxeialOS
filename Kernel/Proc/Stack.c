#include <AllTypes.h>
#include <ELFL.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <PMM.h>
#include <String.h>
#include <VFS.h>
#include <VMM.h>
#include <__AXEKCONF__.h>

#ifdef LOGSTACKC_Debug
#    define LOGSTACKC_PDebug(fmt, ...) PDebug("[KERNEL>>Stack.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSTACKC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSTACKC_Logs
#    define LOGSTACKC_PError(fmt, ...) PError("[KERNEL>>Stack.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSTACKC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSTACKC_Logs
#    define LOGSTACKC_PWarn(fmt, ...) PWarn("[KERNEL>>Stack.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSTACKC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSTACKC_Logs
#    define LOGSTACKC_PInfo(fmt, ...) PInfo("[KERNEL>>Stack.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSTACKC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSTACKC_Logs
#    define LOGSTACKC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Stack.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSTACKC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#define __STACK_BASE__ 0x0000000001000000ULL
#define __STACK_SIZE__ 0x0000000000010000ULL
#define __ARG_AREA__   0x0000000000F00000ULL

static inline uint64_t
__AlignUp__(uint64_t __V__, uint64_t __A__)
{
    _Atomic uint64_t v   = __V__;
    _Atomic uint64_t a   = __A__;
    uint64_t         av  = atomic_load_explicit(&v, memory_order_relaxed);
    uint64_t         aa  = atomic_load_explicit(&a, memory_order_relaxed);
    uint64_t         tmp = (av + (aa - 1)) & ~(aa - 1);
    return tmp;
}

static uint64_t
__PushStrings__(VirtualMemorySpace* __Space__,
                const char* const*  __List__,
                uint64_t            __AreaBase__,
                uint64_t            __AreaSize__,
                uint64_t*           __OutPtrs__,
                long                __Max__)
{
    _Atomic uint64_t AreaEnd = __AreaBase__ + __AreaSize__;
    _Atomic uint64_t Cur     = atomic_load_explicit(&AreaEnd, memory_order_relaxed);
    atomic_long      Count   = 0;

    if (Probe_IF_Error(__List__) || !__List__)
    {
        PushError(
            "__PushStrings__", LOGSTACKC_PError, "Bad args to __PushStrings__", -BadArguments);
        return Nothing;
    }

    /* count entries */
    while (__List__[atomic_load_explicit(&Count, memory_order_relaxed)] &&
           atomic_load_explicit(&Count, memory_order_relaxed) < __Max__)
    {
        atomic_fetch_add_explicit(&Count, 1, memory_order_relaxed);
    }

    /* push strings in reverse order */
    long localCount = (long)atomic_load_explicit(&Count, memory_order_relaxed);
    for (long i = localCount - 1; i >= 0; --i)
    {
        size_t   Len = strlen(__List__[i]) + 1;
        uint64_t Dec = (uint64_t)Len;
        atomic_fetch_sub_explicit(&Cur, Dec, memory_order_relaxed);
        uint64_t CurVirt = atomic_load_explicit(&Cur, memory_order_relaxed);

        uint64_t PhysAddr = GetPhysicalAddress(__Space__, CurVirt);
        if (!PhysAddr)
        {
            PushError("__PushStrings__", LOGSTACKC_PError, "bad virtual address", -NotCanonical);
            return Nothing;
        }
        void* kaddr = PhysToVirt(PhysAddr);
        if (Probe_IF_Error(kaddr) || !kaddr)
        {
            PushError(
                "__PushStrings__", LOGSTACKC_PError, "bad kernel address", Pointer_TO_Error(kaddr));
            return Nothing;
        }

        memcpy(kaddr, __List__[i], Len);

        uint64_t PhysCheck    = GetPhysicalAddress(__Space__, CurVirt);
        void*    KrnAddrCheck = PhysCheck ? PhysToVirt(PhysCheck) : NULL;
        LOGSTACKC_PDebug("CurVirt=0x%llx PhysAddr=0x%llx kaddr=%p wrote_len=%zu\n",
                         (unsigned long long)CurVirt,
                         (unsigned long long)PhysCheck,
                         KrnAddrCheck,
                         (size_t)Len);
        if (KrnAddrCheck)
        {
            LOGSTACKC_PDebug("first bytes: %02x %02x %02x %02x\n",
                             ((unsigned char*)KrnAddrCheck)[0],
                             ((unsigned char*)KrnAddrCheck)[1],
                             ((unsigned char*)KrnAddrCheck)[2],
                             ((unsigned char*)KrnAddrCheck)[3]);
        }

        atomic_store_explicit((_Atomic uint64_t*)&__OutPtrs__[i], CurVirt, memory_order_relaxed);
    }

    return (uint64_t)localCount;
}

static inline int
__Write64__(VirtualMemorySpace* __Sp__, uint64_t __Va__, uint64_t __Val__)
{
    _Atomic uint64_t va = __Va__;
    uint64_t __Pa__ = GetPhysicalAddress(__Sp__, atomic_load_explicit(&va, memory_order_relaxed));
    if (!__Pa__)
    {
        PushError(
            "__Write64__", LOGSTACKC_PError, "bad virtual address in __Write64__", -NotCanonical);
        return -NotCanonical;
    }
    uint64_t* __Ka__ = (uint64_t*)PhysToVirt(__Pa__);
    if (Probe_IF_Error(__Ka__) || !__Ka__)
    {
        PushError("__Write64__",
                  LOGSTACKC_PError,
                  "bad kernel address in __Write64__",
                  Pointer_TO_Error(__Ka__));
        return -NotCanonical;
    }
    atomic_store_explicit((_Atomic uint64_t*)__Ka__, __Val__, memory_order_release);
    return SysOkay;
}

static inline int
__Push64__(VirtualMemorySpace* __Sp__, uint64_t* __Rsp__, uint64_t __LimitBase__, uint64_t __Val__)
{
    _Atomic uint64_t  limit = __LimitBase__;
    _Atomic uint64_t* rsp   = (_Atomic uint64_t*)__Rsp__;
    uint64_t          next  = atomic_load_explicit(rsp, memory_order_relaxed) - 8;
    if (next < atomic_load_explicit(&limit, memory_order_relaxed))
    {
        PushError("__Push64__", LOGSTACKC_PError, "Stack overflow in __Push64__", -NotCanonical);
        return -NotCanonical;
    }
    atomic_store_explicit(rsp, next, memory_order_relaxed);
    return __Write64__(__Sp__, atomic_load_explicit(rsp, memory_order_relaxed), __Val__);
}

static inline int
__PushNull__(VirtualMemorySpace* __Sp__, uint64_t* __Rsp__, uint64_t __LimitBase__)
{
    return __Push64__(__Sp__, __Rsp__, __LimitBase__, 0);
}

uint64_t
SetStack(VirtualMemorySpace* __Space__,
         const char* const*  __Argv__,
         const char* const*  __Envp__,
         int                 __Nx__,
         uint64_t*           __OutRsp__)
{
    if (Probe_IF_Error(__Space__) || !__Space__ || __Space__->PhysicalBase == 0)
    {
        PushError(
            "SetStack", LOGSTACKC_PError, "bad virtual memory space in SetStack", -NotCanonical);
        return Nothing;
    }

    _Atomic uint64_t __StackFlags__ = PTEPRESENT | PTEWRITABLE | PTEUSER;
    if (__Nx__)
    {
        atomic_fetch_or_explicit(&__StackFlags__, PTENOEXECUTE, memory_order_relaxed);
    }

    LOGSTACKC_PDebug(
        "Mapping stack base=0x%llx size=0x%llx flags=0x%llx nx=%d\n",
        (unsigned long long)__STACK_BASE__,
        (unsigned long long)__STACK_SIZE__,
        (unsigned long long)atomic_load_explicit(&__StackFlags__, memory_order_relaxed),
        __Nx__);

    int Map0 = MapRangeZeroed(__Space__,
                              __STACK_BASE__,
                              __STACK_SIZE__,
                              atomic_load_explicit(&__StackFlags__, memory_order_relaxed));
    if (Map0 != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to map stack in SetStack", Map0);
        return Nothing;
    }
    LOGSTACKC_PDebug("stack mapped OK\n");

    LOGSTACKC_PDebug(
        "mapping arg area base=0x%llx size=0x%llx flags=0x%llx\n",
        (unsigned long long)__ARG_AREA__,
        (unsigned long long)__STACK_SIZE__,
        (unsigned long long)atomic_load_explicit(&__StackFlags__, memory_order_relaxed));

    int Map1 = MapRangeZeroed(__Space__,
                              __ARG_AREA__,
                              __STACK_SIZE__,
                              atomic_load_explicit(&__StackFlags__, memory_order_relaxed));
    if (Map1 != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to map arg area in SetStack", Map1);
        return Nothing;
    }

    uint64_t* __ArgPtrs__ = KMalloc(128 * sizeof(uint64_t));
    uint64_t* __EnvPtrs__ = KMalloc(128 * sizeof(uint64_t));
    memset(__ArgPtrs__, 0, 128 * sizeof(uint64_t));
    memset(__EnvPtrs__, 0, 128 * sizeof(uint64_t));
    _Atomic uint64_t __ArgCount__ =
        __PushStrings__(__Space__, __Argv__, __ARG_AREA__, __STACK_SIZE__ / 2, __ArgPtrs__, 128);
    _Atomic uint64_t __EnvCount__ = __PushStrings__(__Space__,
                                                    __Envp__,
                                                    __ARG_AREA__ + (__STACK_SIZE__ / 2),
                                                    __STACK_SIZE__ / 2,
                                                    __EnvPtrs__,
                                                    128);
    enum
    {
        EnumAT_NULL   = 0,
        EnumAT_PAGESZ = 6,
        EnumAT_EXECFN = 31
    };
    _Atomic uint64_t __AuxPairs__ = 2;

    _Atomic uint64_t __TotalQwords__ =
        1 + atomic_load_explicit(&__ArgCount__, memory_order_relaxed) + 1 +
        atomic_load_explicit(&__EnvCount__, memory_order_relaxed) + 1 +
        (2 * atomic_load_explicit(&__AuxPairs__, memory_order_relaxed)) + 2;

    _Atomic uint64_t __Rsp__ = (__STACK_BASE__ + __STACK_SIZE__) & ~0xFULL;
    LOGSTACKC_PDebug("Initial RSP aligned=0x%llx (top=0x%llx)\n",
                     (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed),
                     (unsigned long long)(__STACK_BASE__ + __STACK_SIZE__));

    atomic_int __NeedShim__ =
        (((atomic_load_explicit(&__TotalQwords__, memory_order_relaxed) & 1ULL) != 0) ? true
                                                                                      : false);

    LOGSTACKC_PDebug(
        "total_qwords=%llu parity=%s need_shim=%d\n",
        (unsigned long long)atomic_load_explicit(&__TotalQwords__, memory_order_relaxed),
        ((atomic_load_explicit(&__TotalQwords__, memory_order_relaxed) & 1ULL) ? "odd" : "even"),
        atomic_load_explicit(&__NeedShim__, memory_order_relaxed));

    if (atomic_load_explicit(&__NeedShim__, memory_order_relaxed))
    {
        int RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, 0);
        if (RIdx != SysOkay)
        {
            PushError("SetStack", LOGSTACKC_PError, "Failed to push shim in SetStack", RIdx);
            return Nothing;
        }
        LOGSTACKC_PDebug("Shim pushed; RSP=0x%llx\n",
                         (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    int RIdx = SysOkay;
    RIdx     = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)EnumAT_PAGESZ);
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push auxv AT_PAGESZ in SetStack", RIdx);
        return Nothing;
    }
    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)PageSize);
    if (RIdx != SysOkay)
    {
        PushError(
            "SetStack", LOGSTACKC_PError, "Failed to push auxv pagesize value in SetStack", RIdx);
        return Nothing;
    }

    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)EnumAT_EXECFN);
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push auxv AT_EXECFN in SetStack", RIdx);
        return Nothing;
    }
    {
        _Atomic uint64_t __Execfn__ =
            (atomic_load_explicit(&__ArgCount__, memory_order_relaxed) > 0) ? __ArgPtrs__[0] : 0;
        RIdx = __Push64__(__Space__,
                          (uint64_t*)&__Rsp__,
                          __STACK_BASE__,
                          atomic_load_explicit(&__Execfn__, memory_order_relaxed));
        if (RIdx != SysOkay)
        {
            PushError(
                "SetStack", LOGSTACKC_PError, "Failed to push auxv execfn value in SetStack", RIdx);
            return Nothing;
        }
    }

    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)EnumAT_NULL);
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push auxv AT_NULL in SetStack", RIdx);
        return Nothing;
    }
    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, 0);
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push auxv null value in SetStack", RIdx);
        return Nothing;
    }

    LOGSTACKC_PDebug("auxv pushed; RSP=0x%llx\n",
                     (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));

    RIdx = __PushNull__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__);
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push null after envp in SetStack", RIdx);
        return Nothing;
    }

    /* push envp pointers in reverse for memory order envp[0], envp[1], ..., NULL */
    for (int64_t J = (int64_t)atomic_load_explicit(&__EnvCount__, memory_order_relaxed) - 1; J >= 0;
         --J)
    {
        RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, __EnvPtrs__[J]);
        if (RIdx != SysOkay)
        {
            PushError("SetStack", LOGSTACKC_PError, "Failed to push envp in SetStack", RIdx);
            return Nothing;
        }
        LOGSTACKC_PDebug("envp[%lld]=0x%llx pushed; RSP=0x%llx\n",
                         (long long)J,
                         (unsigned long long)__EnvPtrs__[J],
                         (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    RIdx = __PushNull__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__);
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push null after argv in SetStack", RIdx);
        return Nothing;
    }

    /* push argv pointers in reverse so memory order is argv[0], argv[1], ..., NULL */
    for (int64_t I = (int64_t)atomic_load_explicit(&__ArgCount__, memory_order_relaxed) - 1; I >= 0;
         --I)
    {
        RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, __ArgPtrs__[I]);
        if (RIdx != SysOkay)
        {
            PushError("SetStack", LOGSTACKC_PError, "Failed to push argv in SetStack", RIdx);
            return Nothing;
        }
        LOGSTACKC_PDebug("argv[%lld]=0x%llx pushed; RSP=0x%llx\n",
                         (long long)I,
                         (unsigned long long)__ArgPtrs__[I],
                         (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    /* push argc last */
    RIdx = __Push64__(__Space__,
                      (uint64_t*)&__Rsp__,
                      __STACK_BASE__,
                      (uint64_t)atomic_load_explicit(&__ArgCount__, memory_order_relaxed));
    if (RIdx != SysOkay)
    {
        PushError("SetStack", LOGSTACKC_PError, "Failed to push argc in SetStack", RIdx);
        return Nothing;
    }
    LOGSTACKC_PDebug("argc=%llu pushed, RSP=0x%llx\n",
                     (unsigned long long)atomic_load_explicit(&__ArgCount__, memory_order_relaxed),
                     (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));

    if (__OutRsp__)
    {
        atomic_store_explicit((_Atomic uint64_t*)__OutRsp__,
                              atomic_load_explicit(&__Rsp__, memory_order_relaxed),
                              memory_order_relaxed);
        LOGSTACKC_PDebug("Out RSP stored (argc slot)=0x%llx\n",
                         (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    _Atomic uint64_t ModIdx = atomic_load_explicit(&__Rsp__, memory_order_relaxed) & 0xFULL;
    if (atomic_load_explicit(&ModIdx, memory_order_relaxed) != 0)
    {
        PushError("SetStack",
                  LOGSTACKC_PError,
                  "Final RSP alignment incorrect in SetStack",
                  -NotCanonical);
        return Nothing;
    }

    SysErr Err;
    LOGSTACKC_PSuccess(
        "Success argc=%llu envc=%llu total_qwords=%llu shim=%d RSP=0x%llx\n",
        (unsigned long long)atomic_load_explicit(&__ArgCount__, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&__EnvCount__, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&__TotalQwords__, memory_order_relaxed),
        atomic_load_explicit(&__NeedShim__, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    return atomic_load_explicit(&__Rsp__, memory_order_relaxed);
}