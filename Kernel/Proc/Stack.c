#include <AllTypes.h>
#include <ELFL.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <PMM.h>
#include <String.h>
#include <VFS.h>
#include <VMM.h>

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
        return Nothing;
    }

    while (__List__[atomic_load_explicit(&Count, memory_order_relaxed)] &&
           atomic_load_explicit(&Count, memory_order_relaxed) < __Max__)
    {
        atomic_fetch_add_explicit(&Count, 1, memory_order_relaxed);
    }

    atomic_long I = atomic_load_explicit(&Count, memory_order_relaxed) - 1;
    for (; atomic_load_explicit(&I, memory_order_relaxed) >= 0;
         atomic_fetch_sub_explicit(&I, 1, memory_order_relaxed))
    {
        atomic_long Len =
            (long)strlen(__List__[atomic_load_explicit(&I, memory_order_relaxed)]) + 1;
        atomic_fetch_sub_explicit(
            &Cur, (uint64_t)atomic_load_explicit(&Len, memory_order_relaxed), memory_order_relaxed);
        uint64_t curv = atomic_load_explicit(&Cur, memory_order_relaxed);
        memcpy((void*)curv,
               __List__[atomic_load_explicit(&I, memory_order_relaxed)],
               (size_t)atomic_load_explicit(&Len, memory_order_relaxed));
        atomic_store_explicit(
            (_Atomic uint64_t*)&__OutPtrs__[atomic_load_explicit(&I, memory_order_relaxed)],
            curv,
            memory_order_relaxed);
    }

    return (uint64_t)atomic_load_explicit(&Count, memory_order_relaxed);
}

static inline int
__Write64__(VirtualMemorySpace* __Sp__, uint64_t __Va__, uint64_t __Val__)
{
    _Atomic uint64_t va = __Va__;
    uint64_t __Pa__ = GetPhysicalAddress(__Sp__, atomic_load_explicit(&va, memory_order_relaxed));
    if (!__Pa__)
    {
        return -NotCanonical;
    }
    uint64_t* __Ka__ = (uint64_t*)PhysToVirt(__Pa__);
    if (Probe_IF_Error(__Ka__) || !__Ka__)
    {
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
        return Nothing;
    }

    _Atomic uint64_t __StackFlags__ = PTEPRESENT | PTEWRITABLE | PTEUSER;
    if (__Nx__)
    {
        atomic_fetch_or_explicit(&__StackFlags__, PTENOEXECUTE, memory_order_relaxed);
    }

    PDebug("Mapping stack base=0x%llx size=0x%llx flags=0x%llx nx=%d\n",
           (unsigned long long)__STACK_BASE__,
           (unsigned long long)__STACK_SIZE__,
           (unsigned long long)atomic_load_explicit(&__StackFlags__, memory_order_relaxed),
           __Nx__);

    int m0 = MapRangeZeroed(__Space__,
                            __STACK_BASE__,
                            __STACK_SIZE__,
                            atomic_load_explicit(&__StackFlags__, memory_order_relaxed));
    if (m0 != SysOkay)
    {
        return Nothing;
    }
    PDebug("stack mapped OK\n");

    PDebug("mapping arg area base=0x%llx size=0x%llx flags=0x%llx\n",
           (unsigned long long)__ARG_AREA__,
           (unsigned long long)__STACK_SIZE__,
           (unsigned long long)atomic_load_explicit(&__StackFlags__, memory_order_relaxed));

    int m1 = MapRangeZeroed(__Space__,
                            __ARG_AREA__,
                            __STACK_SIZE__,
                            atomic_load_explicit(&__StackFlags__, memory_order_relaxed));
    if (m1 != SysOkay)
    {
        return Nothing;
    }

    uint64_t __ArgPtrs__[128] = {0};
    uint64_t __EnvPtrs__[128] = {0};

    _Atomic uint64_t __ArgCount__ =
        __PushStrings__(__Space__, __Argv__, __ARG_AREA__, __STACK_SIZE__, __ArgPtrs__, 128);
    _Atomic uint64_t __EnvCount__ =
        __PushStrings__(__Space__, __Envp__, __ARG_AREA__, __STACK_SIZE__, __EnvPtrs__, 128);

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
    PDebug("Initial RSP aligned=0x%llx (top=0x%llx)\n",
           (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed),
           (unsigned long long)(__STACK_BASE__ + __STACK_SIZE__));

    atomic_int __NeedShim__ =
        (((atomic_load_explicit(&__TotalQwords__, memory_order_relaxed) & 1ULL) == 0) ? true
                                                                                      : false);
    PDebug("total_qwords=%llu parity=%s need_shim=%d\n",
           (unsigned long long)atomic_load_explicit(&__TotalQwords__, memory_order_relaxed),
           ((atomic_load_explicit(&__TotalQwords__, memory_order_relaxed) & 1ULL) ? "odd" : "even"),
           atomic_load_explicit(&__NeedShim__, memory_order_relaxed));

    if (atomic_load_explicit(&__NeedShim__, memory_order_relaxed))
    {
        int RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, 0);
        if (RIdx != SysOkay)
        {
            return Nothing;
        }
        PDebug("Shim pushed; RSP=0x%llx\n",
               (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    int RIdx = __Push64__(__Space__,
                          (uint64_t*)&__Rsp__,
                          __STACK_BASE__,
                          (uint64_t)atomic_load_explicit(&__ArgCount__, memory_order_relaxed));
    if (RIdx != SysOkay)
    {
        return Nothing;
    }
    PDebug("argc=%llu pushed; RSP=0x%llx\n",
           (unsigned long long)atomic_load_explicit(&__ArgCount__, memory_order_relaxed),
           (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));

    for (_Atomic uint64_t I = 0; atomic_load_explicit(&I, memory_order_relaxed) <
                                 atomic_load_explicit(&__ArgCount__, memory_order_relaxed);
         atomic_fetch_add_explicit(&I, 1, memory_order_relaxed))
    {
        uint64_t idx = atomic_load_explicit(&I, memory_order_relaxed);
        RIdx         = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, __ArgPtrs__[idx]);
        if (RIdx != SysOkay)
        {
            return Nothing;
        }
        PDebug("argv[%llu]=0x%llx pushed; RSP=0x%llx\n",
               (unsigned long long)idx,
               (unsigned long long)__ArgPtrs__[idx],
               (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    RIdx = __PushNull__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__);
    if (RIdx != SysOkay)
    {
        return Nothing;
    }

    for (_Atomic uint64_t J = 0; atomic_load_explicit(&J, memory_order_relaxed) <
                                 atomic_load_explicit(&__EnvCount__, memory_order_relaxed);
         atomic_fetch_add_explicit(&J, 1, memory_order_relaxed))
    {
        uint64_t jdx = atomic_load_explicit(&J, memory_order_relaxed);
        RIdx         = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, __EnvPtrs__[jdx]);
        if (RIdx != SysOkay)
        {
            return Nothing;
        }
        PDebug("envp[%llu]=0x%llx pushed; RSP=0x%llx\n",
               (unsigned long long)jdx,
               (unsigned long long)__EnvPtrs__[jdx],
               (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    RIdx = __PushNull__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__);
    if (RIdx != SysOkay)
    {
        return Nothing;
    }

    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)EnumAT_PAGESZ);
    if (RIdx != SysOkay)
    {
        return 0;
    }
    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)PageSize);
    if (RIdx != SysOkay)
    {
        return 0;
    }

    PDebug("auxv EnumAT_PAGESZ=%llu pushed; RSP=0x%llx\n",
           (unsigned long long)PageSize,
           (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));

    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)EnumAT_EXECFN);
    if (RIdx != SysOkay)
    {
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
            return 0;
        }
        PDebug("auxv EnumAT_EXECFN=0x%llx pushed; RSP=0x%llx\n",
               (unsigned long long)atomic_load_explicit(&__Execfn__, memory_order_relaxed),
               (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, (uint64_t)EnumAT_NULL);
    if (RIdx != SysOkay)
    {
        return Nothing;
    }
    RIdx = __Push64__(__Space__, (uint64_t*)&__Rsp__, __STACK_BASE__, 0);
    if (RIdx != SysOkay)
    {
        return Nothing;
    }

    _Atomic uint64_t ModIdx = atomic_load_explicit(&__Rsp__, memory_order_relaxed) & 0xFULL;
    if (atomic_load_explicit(&ModIdx, memory_order_relaxed) != 8)
    {
        return Nothing;
    }

    if (__OutRsp__)
    {
        atomic_store_explicit((_Atomic uint64_t*)__OutRsp__,
                              atomic_load_explicit(&__Rsp__, memory_order_relaxed),
                              memory_order_relaxed);
        PDebug("Out RSP stored=0x%llx\n",
               (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));
    }

    PSuccess("Success argc=%llu envc=%llu total_qwords=%llu shim=%d RSP=0x%llx\n",
             (unsigned long long)atomic_load_explicit(&__ArgCount__, memory_order_relaxed),
             (unsigned long long)atomic_load_explicit(&__EnvCount__, memory_order_relaxed),
             (unsigned long long)atomic_load_explicit(&__TotalQwords__, memory_order_relaxed),
             atomic_load_explicit(&__NeedShim__, memory_order_relaxed),
             (unsigned long long)atomic_load_explicit(&__Rsp__, memory_order_relaxed));

    return atomic_load_explicit(&__Rsp__, memory_order_relaxed);
}