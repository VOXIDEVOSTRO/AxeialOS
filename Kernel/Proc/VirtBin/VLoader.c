#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <PMM.h>
#include <String.h>
#include <VFS.h>
#include <VMM.h>
#include <VirtBin.h>

#define __STACK_BASE__ 0x0000000001000000ULL
#define __STACK_SIZE__ 0x0000000000010000ULL
#define __ARG_AREA__   0x0000000000F00000ULL

static inline uint64_t
__AlignUp__(uint64_t __V__, uint64_t __A__)
{
    return (__V__ + (__A__ - 1)) & ~(__A__ - 1);
}

VirtualMemorySpace*
VirtCreateSpace(void)
{
    return CreateVirtualSpace();
}

int
VirtMapPage(VirtualMemorySpace* __Space__, uint64_t __Va__, uint64_t __Phys__, uint64_t __Flags__)
{
    return MapPage(__Space__, __Va__, __Phys__, __Flags__);
}

int
VirtMapRangeZeroed(VirtualMemorySpace* __Space__,
                   uint64_t            __VaStart__,
                   uint64_t            __Len__,
                   uint64_t            __Flags__)
{
    uint64_t Pages = (__Len__ + PageSize - 1) / PageSize;
    uint64_t Phys  = AllocPages(Pages);
    if (!Phys)
    {
        return -1;
    }

    uint64_t Va   = __VaStart__;
    uint64_t Pcur = Phys;
    uint64_t I    = 0;

    for (I = 0; I < Pages; I++)
    {
        if (MapPage(__Space__, Va, Pcur, __Flags__) != 1)
        {
            return -1;
        }
        memset(PhysToVirt(Pcur), 0, PageSize);
        Va += PageSize;
        Pcur += PageSize;
    }
    return 0;
}

static uint64_t
__PushStrings__(VirtualMemorySpace* __Space__,
                const char* const*  __List__,
                uint64_t            __AreaBase__,
                uint64_t            __AreaSize__,
                uint64_t*           __OutPtrs__,
                long                __Max__)
{
    uint64_t AreaEnd = __AreaBase__ + __AreaSize__;
    uint64_t Cur     = AreaEnd;
    long     Count   = 0;

    if (!__List__)
    {
        return 0;
    }

    while (__List__[Count] && Count < __Max__)
    {
        Count++;
    }

    long I;
    for (I = Count - 1; I >= 0; I--)
    {
        long Len = (long)strlen(__List__[I]) + 1;
        Cur -= (uint64_t)Len;
        __builtin_memcpy((void*)Cur, __List__[I], (size_t)Len);
        __OutPtrs__[I] = Cur;
    }

    return (uint64_t)Count;
}

static inline int
__Write64__(VirtualMemorySpace* __Sp__, uint64_t __Va__, uint64_t __Val__)
{
    uint64_t __Pa__ = GetPhysicalAddress(__Sp__, __Va__);
    if (!__Pa__)
    {
        return -1;
    }
    uint64_t* __Ka__ = (uint64_t*)PhysToVirt(__Pa__);
    if (!__Ka__)
    {
        return -1;
    }
    *__Ka__ = __Val__;
    return 0;
}

static inline int
__Push64__(VirtualMemorySpace* __Sp__, uint64_t* __Rsp__, uint64_t __LimitBase__, uint64_t __Val__)
{
    if ((*__Rsp__ - 8) < __LimitBase__)
    {
        return -1;
    }
    *__Rsp__ -= 8;
    return __Write64__(__Sp__, *__Rsp__, __Val__);
}

static inline int
__PushNull__(VirtualMemorySpace* __Sp__, uint64_t* __Rsp__, uint64_t __LimitBase__)
{
    return __Push64__(__Sp__, __Rsp__, __LimitBase__, 0);
}

uint64_t
VirtSetupStack(VirtualMemorySpace* __Space__,
               const char* const*  __Argv__,
               const char* const*  __Envp__,
               int                 __Nx__,
               uint64_t*           __OutRsp__)
{
    if (!__Space__ || __Space__->PhysicalBase == 0)
    {
        PError("VirtSetupStack: bad space (ptr=%p pd=0x%llx)\n",
               (void*)__Space__,
               (unsigned long long)(__Space__ ? __Space__->PhysicalBase : 0ULL));
        return 0;
    }

    uint64_t __StackFlags__ = PTEPRESENT | PTEWRITABLE | PTEUSER;
    if (__Nx__)
    {
        __StackFlags__ |= PTENOEXECUTE;
    }

    PDebug("VirtSetupStack: mapping stack base=0x%llx size=0x%llx flags=0x%llx nx=%d\n",
           (unsigned long long)__STACK_BASE__,
           (unsigned long long)__STACK_SIZE__,
           (unsigned long long)__StackFlags__,
           __Nx__);

    int m0 = VirtMapRangeZeroed(__Space__, __STACK_BASE__, __STACK_SIZE__, __StackFlags__);
    if (m0 != 0)
    {
        PError("VirtSetupStack: map(stack) failed RIdx=%d\n", m0);
        return 0;
    }
    PDebug("VirtSetupStack: stack mapped OK\n");

    PDebug("VirtSetupStack: mapping arg area base=0x%llx size=0x%llx flags=0x%llx\n",
           (unsigned long long)__ARG_AREA__,
           (unsigned long long)__STACK_SIZE__,
           (unsigned long long)__StackFlags__);

    int m1 = VirtMapRangeZeroed(__Space__, __ARG_AREA__, __STACK_SIZE__, __StackFlags__);
    if (m1 != 0)
    {
        PError("VirtSetupStack: map(arg) failed RIdx=%d\n", m1);
        return 0;
    }
    PDebug("VirtSetupStack: arg area mapped OK\n");

    uint64_t __ArgPtrs__[128] = {0};
    uint64_t __EnvPtrs__[128] = {0};

    PDebug("VirtSetupStack: pushing argv strings into arg area\n");
    uint64_t __ArgCount__ =
        __PushStrings__(__Space__, __Argv__, __ARG_AREA__, __STACK_SIZE__, __ArgPtrs__, 128);
    PDebug("VirtSetupStack: argv pushed: count=%llu\n", (unsigned long long)__ArgCount__);

    PDebug("VirtSetupStack: pushing envp strings into arg area\n");
    uint64_t __EnvCount__ =
        __PushStrings__(__Space__, __Envp__, __ARG_AREA__, __STACK_SIZE__, __EnvPtrs__, 128);
    PDebug("VirtSetupStack: envp pushed: count=%llu\n", (unsigned long long)__EnvCount__);

    enum
    {
        AT_NULL   = 0,
        AT_PAGESZ = 6,
        AT_EXECFN = 31
    };
    uint64_t __AuxPairs__ = 2; /* PAGESZ, EXECFN */

    /* total qwords to push (excluding optional shim) */
    uint64_t __TotalQwords__ = 1 /*argc*/ + __ArgCount__ + 1 /*argv NULL*/ + __EnvCount__ +
                               1 /*envp NULL*/ + (2 * __AuxPairs__) /*aux pairs*/ +
                               2 /*AT_NULL pair*/;

    uint64_t __Rsp__ = (__STACK_BASE__ + __STACK_SIZE__) & ~0xFULL;
    PDebug("VirtSetupStack: initial RSP aligned=0x%llx (top=0x%llx)\n",
           (unsigned long long)__Rsp__,
           (unsigned long long)(__STACK_BASE__ + __STACK_SIZE__));

    /* if parity requires it */
    int __NeedShim__ = (((__TotalQwords__ & 1ULL) == 0) ? 1 : 0);
    PDebug("VirtSetupStack: total_qwords=%llu parity=%s need_shim=%d\n",
           (unsigned long long)__TotalQwords__,
           ((__TotalQwords__ & 1ULL) ? "odd" : "even"),
           __NeedShim__);

    if (__NeedShim__)
    {
        int RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, 0);
        if (RIdx != 0)
        {
            PError("VirtSetupStack: push shim failed RIdx=%d RSP=0x%llx\n",
                   RIdx,
                   (unsigned long long)__Rsp__);
            return 0;
        }
        PDebug("VirtSetupStack: shim pushed; RSP=0x%llx\n", (unsigned long long)__Rsp__);
    }

    /* argc */
    int RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, (uint64_t)__ArgCount__);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push argc failed RIdx=%d\n", RIdx);
        return 0;
    }
    PDebug("VirtSetupStack: argc=%llu pushed; RSP=0x%llx\n",
           (unsigned long long)__ArgCount__,
           (unsigned long long)__Rsp__);

    /* argv[] */
    for (uint64_t I = 0; I < __ArgCount__; I++)
    {
        RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, __ArgPtrs__[I]);
        if (RIdx != 0)
        {
            PError("VirtSetupStack: push argv[%llu]=0x%llx failed RIdx=%d\n",
                   (unsigned long long)I,
                   (unsigned long long)__ArgPtrs__[I],
                   RIdx);
            return 0;
        }
        PDebug("VirtSetupStack: argv[%llu]=0x%llx pushed; RSP=0x%llx\n",
               (unsigned long long)I,
               (unsigned long long)__ArgPtrs__[I],
               (unsigned long long)__Rsp__);
    }

    /* argv NULL */
    RIdx = __PushNull__(__Space__, &__Rsp__, __STACK_BASE__);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push argv NULL failed RIdx=%d\n", RIdx);
        return 0;
    }
    PDebug("VirtSetupStack: argv NULL pushed; RSP=0x%llx\n", (unsigned long long)__Rsp__);

    /* envp[] (maybe zero) */
    for (uint64_t J = 0; J < __EnvCount__; J++)
    {
        RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, __EnvPtrs__[J]);
        if (RIdx != 0)
        {
            PError("VirtSetupStack: push envp[%llu]=0x%llx failed RIdx=%d\n",
                   (unsigned long long)J,
                   (unsigned long long)__EnvPtrs__[J],
                   RIdx);
            return 0;
        }
        PDebug("VirtSetupStack: envp[%llu]=0x%llx pushed; RSP=0x%llx\n",
               (unsigned long long)J,
               (unsigned long long)__EnvPtrs__[J],
               (unsigned long long)__Rsp__);
    }

    /* envp NULL */
    RIdx = __PushNull__(__Space__, &__Rsp__, __STACK_BASE__);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push envp NULL failed RIdx=%d\n", RIdx);
        return 0;
    }
    PDebug("VirtSetupStack: envp NULL pushed; RSP=0x%llx\n", (unsigned long long)__Rsp__);

    /* auxv: AT_PAGESZ, PageSize */
    RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, (uint64_t)AT_PAGESZ);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push AT_PAGESZ key failed RIdx=%d\n", RIdx);
        return 0;
    }
    RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, (uint64_t)PageSize);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push AT_PAGESZ val=%llu failed RIdx=%d\n",
               (unsigned long long)PageSize,
               RIdx);
        return 0;
    }
    PDebug("VirtSetupStack: auxv AT_PAGESZ=%llu pushed; RSP=0x%llx\n",
           (unsigned long long)PageSize,
           (unsigned long long)__Rsp__);

    /* auxv: AT_EXECFN, argv[0] or 0 */
    RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, (uint64_t)AT_EXECFN);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push AT_EXECFN key failed RIdx=%d\n", RIdx);
        return 0;
    }
    {
        uint64_t __Execfn__ = (__ArgCount__ > 0) ? __ArgPtrs__[0] : 0;
        RIdx                = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, __Execfn__);
        if (RIdx != 0)
        {
            PError("VirtSetupStack: push AT_EXECFN val=0x%llx failed RIdx=%d\n",
                   (unsigned long long)__Execfn__,
                   RIdx);
            return 0;
        }
        PDebug("VirtSetupStack: auxv AT_EXECFN=0x%llx pushed; RSP=0x%llx\n",
               (unsigned long long)__Execfn__,
               (unsigned long long)__Rsp__);
    }

    /* auxv: AT_NULL terminator pair */
    RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, (uint64_t)AT_NULL);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push AT_NULL key failed RIdx=%d\n", RIdx);
        return 0;
    }
    RIdx = __Push64__(__Space__, &__Rsp__, __STACK_BASE__, 0);
    if (RIdx != 0)
    {
        PError("VirtSetupStack: push AT_NULL val failed RIdx=%d\n", RIdx);
        return 0;
    }
    PDebug("VirtSetupStack: auxv AT_NULL pushed; RSP=0x%llx\n", (unsigned long long)__Rsp__);

    /* Assert ABI invariant: RSP % 16 == 8 at entry */
    uint64_t ModIdx = (__Rsp__ & 0xFULL);
    if (ModIdx != 8)
    {
        PError("VirtSetupStack: ABI alignment fail (RSP%%16=0x%llx expected 0x8) RSP=0x%llx "
               "total_qwords=%llu need_shim=%d\n",
               (unsigned long long)ModIdx,
               (unsigned long long)__Rsp__,
               (unsigned long long)__TotalQwords__,
               __NeedShim__);
        return 0;
    }

    if (__OutRsp__)
    {
        *__OutRsp__ = __Rsp__;
        PDebug("VirtSetupStack: out RSP stored=0x%llx\n", (unsigned long long)__Rsp__);
    }

    PSuccess("VirtSetupStack: success argc=%llu envc=%llu total_qwords=%llu shim=%d RSP=0x%llx\n",
             (unsigned long long)__ArgCount__,
             (unsigned long long)__EnvCount__,
             (unsigned long long)__TotalQwords__,
             __NeedShim__,
             (unsigned long long)__Rsp__);

    return __Rsp__;
}

int
VirtLoad(const VirtRequest* __Req__, VirtImage* __OutImg__)
{
    if (!__Req__ || !__Req__->File || !__OutImg__ || !__OutImg__->Space)
    {
        PError("VirtLoad: bad args (Req=%p File=%p OutImg=%p Space=%p)\n",
               __Req__,
               __Req__ ? __Req__->File : NULL,
               __OutImg__,
               __OutImg__ ? __OutImg__->Space : NULL);
        return -1;
    }

    VirtualMemorySpace* Space = __OutImg__->Space;

    __OutImg__->Entry      = 0;
    __OutImg__->UserSp     = 0;
    __OutImg__->LoadBase   = 0;
    __OutImg__->Flags      = 0;
    __OutImg__->LoaderPriv = NULL;
    __OutImg__->Auxv.Buf   = NULL;
    __OutImg__->Auxv.Cap   = 0;
    __OutImg__->Auxv.Len   = 0;

    const DynLoader* Ldr = DynLoaderSelect(__Req__->File);
    if (!Ldr)
    {
        PError("VirtLoad: no loader matched file\n");
        return -1;
    }

    void* ImagePriv = KMalloc(4096);
    if (!ImagePriv)
    {
        PError("VirtLoad: KMalloc failed for loader-private buffer\n");
        return -1;
    }

    if (Ldr->Ops.Load(__Req__->File, Space, ImagePriv) != 0)
    {
        PError("VirtLoad: loader->Ops.Load failed\n");
        KFree(ImagePriv);
        return -1;
    }

    VirtImage* Loaded      = (VirtImage*)ImagePriv;
    __OutImg__->LoaderPriv = ImagePriv;
    __OutImg__->Entry      = Loaded->Entry;
    __OutImg__->LoadBase   = Loaded->LoadBase;

    if (Ldr->Ops.BuildAux)
    {
        uint64_t auxBuf[64] = {0};
        if (Ldr->Ops.BuildAux(__Req__->File, __OutImg__, auxBuf, (long)sizeof(auxBuf)) == 0)
        {
            __OutImg__->Auxv.Buf = (uint64_t*)KMalloc(sizeof(auxBuf));
            __OutImg__->Auxv.Cap = (long)(sizeof(auxBuf) / sizeof(uint64_t));
            __OutImg__->Auxv.Len = ((VirtImage*)__OutImg__)->Auxv.Len;
            __builtin_memcpy(__OutImg__->Auxv.Buf, auxBuf, sizeof(auxBuf));
        }
    }

    /* Stack setup into the same Space */
    uint64_t Rsp = 0;
    if (VirtSetupStack(Space, __Req__->Argv, __Req__->Envp, 1, &Rsp) == 0)
    {
        PError("VirtLoad: VirtSetupStack failed\n");
        return -1;
    }
    __OutImg__->UserSp = Rsp;

    PSuccess("VirtLoad: completed (Entry=0x%llx Base=0x%llx SpacePml4=0x%llx)\n",
             (unsigned long long)__OutImg__->Entry,
             (unsigned long long)__OutImg__->LoadBase,
             (unsigned long long)Space->PhysicalBase);
    return 0;
}

int
VirtCommit(VirtImage* __Img__)
{
    if (!__Img__ || !__Img__->Space)
    {
        return -1;
    }
    /*Stubber and can be used to make something*/
    return 0;
}