#include <AllTypes.h>
#include <KHeap.h>
#include <KMods.h>
#include <KrnPrintf.h>
#include <ModELF.h>
#include <ModMemMgr.h>
#include <String.h>
#include <VFS.h>
#include <__AXEKCONF__.h>

#ifdef LOGLINKERC_Debug
#    define LOGLINKERC_PDebug(fmt, ...) PDebug("[KERNEL>>Linker.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLINKERC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLINKERC_Logs
#    define LOGLINKERC_PError(fmt, ...) PError("[KERNEL>>Linker.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLINKERC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLINKERC_Logs
#    define LOGLINKERC_PWarn(fmt, ...) PWarn("[KERNEL>>Linker.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLINKERC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLINKERC_Logs
#    define LOGLINKERC_PInfo(fmt, ...) PInfo("[KERNEL>>Linker.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLINKERC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGLINKERC_Logs
#    define LOGLINKERC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Linker.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGLINKERC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
InstallModule(const char* __Path__)
{
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        PushError(
            "InstallModule", LOGLINKERC_PError, "bad arguments to InstallModule", -BadArguments);
        return -BadArguments;
    }

    static uint8_t ZeroStub[1] = {0};

    SysErr  err;
    SysErr* Error = &err;

    Elf64_Ehdr Hdr;
    long       HdrLen = 0;

    if (VfsReadAll(__Path__, &Hdr, (long)sizeof(Hdr), &HdrLen) != SysOkay ||
        HdrLen < (long)sizeof(Hdr))
    {
        PushError("InstallModule", LOGLINKERC_PError, "failed to read elf header", -BadRead);
        return -BadRead;
    }

    if (Hdr.e_ident[0] != 0x7F || Hdr.e_ident[1] != 'E' || Hdr.e_ident[2] != 'L' ||
        Hdr.e_ident[3] != 'F')
    {
        PushError("InstallModule", LOGLINKERC_PError, "not a valid ELF entity", -BadEntity);
        return -BadEntity;
    }

    if (Hdr.e_ident[4] != 2)
    {
        PushError("InstallModule", LOGLINKERC_PError, "not a 64-bit entity", -Impilict);
        return -Impilict;
    }

    if (Hdr.e_machine != 0x3E)
    {
        PushError("InstallModule", LOGLINKERC_PError, "not an x86-64 entity", -Impilict);
        return -Impilict;
    }

    if (Hdr.e_type != 1 && Hdr.e_type != 3)
    {
        PushError(
            "InstallModule", LOGLINKERC_PError, "not a relocatable or shared object", -Impilict);
        return -Impilict;
    }

    long ShNum = (long)Hdr.e_shnum;
    if (ShNum <= 0)
    {
        PushError("InstallModule", LOGLINKERC_PError, "section count is not positive", -Limits);
        return -Limits;
    }

    long        ShtBytes = ShNum * (long)sizeof(Elf64_Shdr);
    Elf64_Shdr* ShTbl    = (Elf64_Shdr*)KMalloc((size_t)ShtBytes);
    if (Probe_IF_Error(ShTbl) || !ShTbl)
    {
        PushError(
            "InstallModule", LOGLINKERC_PError, "cannot allocate ShTbl", Pointer_TO_Error(ShTbl));
        return -BadAllocation;
    }

    {
        File* F = VfsOpen(__Path__, VFlgRDONLY);
        if (Probe_IF_Error(F) || !F)
        {
            KFree(ShTbl, Error);
            PushError(
                "InstallModule", LOGLINKERC_PError, "failed to open file", Pointer_TO_Error(F));
            return -NotCanonical;
        }
        if (VfsLseek(F, (long)Hdr.e_shoff, VSeekSET) < 0)
        {
            VfsClose(F);
            KFree(ShTbl, Error);
            PushError("InstallModule",
                      LOGLINKERC_PError,
                      "failed to seek to section header table",
                      -BadRead);
            return -BadRead;
        }
        long Rd = VfsRead(F, ShTbl, ShtBytes);
        VfsClose(F);
        if (Rd < ShtBytes)
        {
            KFree(ShTbl, Error);
            PushError("InstallModule",
                      LOGLINKERC_PError,
                      "failed to read section header table",
                      -BadRead);
            return -BadRead;
        }
    }

    long SymtabIdx = -1, StrtabIdx = -1;
    for (long I = 0; I < ShNum; I++)
    {
        uint32_t T = ShTbl[I].sh_type;
        if (T == (uint32_t)2U && SymtabIdx < 0)
        {
            SymtabIdx = I;
        }
        else if (T == (uint32_t)3U && StrtabIdx < 0)
        {
            StrtabIdx = I;
        }
    }
    if (SymtabIdx < 0 || StrtabIdx < 0)
    {
        KFree(ShTbl, Error);
        PushError("InstallModule", LOGLINKERC_PError, "missing symbol or string table", -Missing);
        return -Missing;
    }

    const Elf64_Shdr* SymSh = &ShTbl[SymtabIdx];
    const Elf64_Shdr* StrSh = &ShTbl[StrtabIdx];

    Elf64_Sym* SymBuf = (Elf64_Sym*)KMalloc((size_t)SymSh->sh_size);
    char*      StrBuf = (char*)KMalloc((size_t)StrSh->sh_size);
    if (Probe_IF_Error(SymBuf) || !SymBuf || Probe_IF_Error(StrBuf) || !StrBuf)
    {
        if (SymBuf)
        {
            KFree(SymBuf, Error);
        }
        if (StrBuf)
        {
            KFree(StrBuf, Error);
        }
        KFree(ShTbl, Error);
        PushError(
            "InstallModule", LOGLINKERC_PError, "cannot allocate Sym/Str buffers", -BadAllocation);
        return -BadAllocation;
    }

    {
        File* F = VfsOpen(__Path__, VFlgRDONLY);
        if (Probe_IF_Error(F) || !F)
        {
            KFree(SymBuf, Error);
            KFree(StrBuf, Error);
            KFree(ShTbl, Error);
            PushError(
                "InstallModule", LOGLINKERC_PError, "failed to open file", Pointer_TO_Error(F));
            return -NotCanonical;
        }
        if (VfsLseek(F, (long)SymSh->sh_offset, VSeekSET) < 0)
        {
            VfsClose(F);
            KFree(SymBuf, Error);
            KFree(StrBuf, Error);
            KFree(ShTbl, Error);
            PushError("InstallModule", LOGLINKERC_PError, "failed to seek to symtab", -BadRead);
            return -BadRead;
        }
        long RdS = VfsRead(F, SymBuf, (long)SymSh->sh_size);
        if (VfsLseek(F, (long)StrSh->sh_offset, VSeekSET) < 0)
        {
            VfsClose(F);
            KFree(SymBuf, Error);
            KFree(StrBuf, Error);
            KFree(ShTbl, Error);
            PushError("InstallModule", LOGLINKERC_PError, "failed to seek to strtab", -BadRead);
            return -BadRead;
        }
        long RdT = VfsRead(F, StrBuf, (long)StrSh->sh_size);
        VfsClose(F);
        if (RdS < (long)SymSh->sh_size || RdT < (long)StrSh->sh_size)
        {
            KFree(SymBuf, Error);
            KFree(StrBuf, Error);
            KFree(ShTbl, Error);
            PushError("InstallModule", LOGLINKERC_PError, "failed to read symtab/strtab", -BadRead);
            return -BadRead;
        }
    }

    long           SymCount = (long)((long)SymSh->sh_size / (long)sizeof(Elf64_Sym));
    __ElfSymbol__* Syms = (__ElfSymbol__*)KMalloc((size_t)(SymCount * (long)sizeof(__ElfSymbol__)));
    if (Probe_IF_Error(Syms) || !Syms)
    {
        KFree(SymBuf, Error);
        KFree(StrBuf, Error);
        KFree(ShTbl, Error);
        PushError(
            "InstallModule", LOGLINKERC_PError, "cannot allocate Syms", Pointer_TO_Error(Syms));
        return -BadAllocation;
    }

    for (long I = 0; I < SymCount; I++)
    {
        uint32_t    NameOff = SymBuf[I].st_name;
        const char* Nm      = (NameOff < (uint32_t)StrSh->sh_size) ? (StrBuf + NameOff) : Nothing;

        Syms[I].Name         = Nm;
        Syms[I].Value        = SymBuf[I].st_value;
        Syms[I].Shndx        = SymBuf[I].st_shndx;
        Syms[I].Info         = SymBuf[I].st_info;
        Syms[I].ResolvedAddr = 0ULL;
    }

    void** SectionBases = (void**)KMalloc((size_t)(ShNum * (long)sizeof(void*)));
    if (Probe_IF_Error(SectionBases) || !SectionBases)
    {
        KFree(Syms, Error);
        KFree(SymBuf, Error);
        KFree(StrBuf, Error);
        KFree(ShTbl, Error);
        PushError("InstallModule",
                  LOGLINKERC_PError,
                  "cannot allocate SectionBases",
                  Pointer_TO_Error(SectionBases));
        return -BadAllocation;
    }
    memset(SectionBases, 0, (size_t)(ShNum * (long)sizeof(void*)));

    for (long I = 0; I < ShNum; I++)
    {
        const Elf64_Shdr* S     = &ShTbl[I];
        long              Size  = (long)S->sh_size;
        uint32_t          Type  = S->sh_type;
        uint64_t          Flags = S->sh_flags;

        if (Size <= 0)
        {
            SectionBases[I] = (void*)ZeroStub;
            continue;
        }
        {
            int      IsText = (Flags & (uint64_t)0x4ULL) ? true : false;
            size_t   Bytes  = (size_t)Size;
            size_t   Pages  = (Bytes + (size_t)PageSize - 1) / (size_t)PageSize;
            uint64_t Phys   = AllocPages(Pages);
            if (!Phys)
            {
                /* rollback any previously mapped sections */
                for (long J = 0; J < ShNum; J++)
                {
                    if (SectionBases[J] && SectionBases[J] != (void*)ZeroStub)
                    {
                        long SzJ = (long)ShTbl[J].sh_size;
                        if (SzJ > 0)
                        {
                            size_t   PgJ = (size_t)((SzJ + PageSize - 1) / PageSize);
                            uint64_t VaJ = (uint64_t)SectionBases[J];
                            for (size_t off = 0; off < PgJ * PageSize; off += PageSize)
                            {
                                uint64_t PaJ = GetPhysicalAddress(Vmm.KernelSpace, VaJ + off);
                                UnmapPage(Vmm.KernelSpace, VaJ + off);
                                if (PaJ)
                                {
                                    FreePage(PaJ, Error);
                                }
                            }
                        }
                    }
                }
                KFree(SectionBases, Error);
                KFree(Syms, Error);
                KFree(SymBuf, Error);
                KFree(StrBuf, Error);
                KFree(ShTbl, Error);
                PushError(
                    "InstallModule", LOGLINKERC_PError, "cannot map sections", -BadAllocation);
                return -BadAllocation;
            }

            uint64_t VaBase =
                IsText ? (ModTextBase + ModMem.TextCursor) : (ModDataBase + ModMem.DataCursor);

            uint64_t MapFlags = PTEPRESENT;
            if (IsText)
            {
                /* load-time writable (for reloc), executable */
                MapFlags |= PTEWRITABLE;
            }
            else
            {
                /* data/bss: RW, NX */
                MapFlags |= PTEWRITABLE | PTENOEXECUTE;
            }

            size_t Mapped = 0;
            for (size_t off = 0; off < Pages * PageSize; off += PageSize)
            {
                int RetC = MapPage(Vmm.KernelSpace, VaBase + off, Phys + off, MapFlags);
                if (RetC != SysOkay)
                {
                    /* rollback this section */
                    for (size_t roff = 0; roff < off; roff += PageSize)
                    {
                        UnmapPage(Vmm.KernelSpace, VaBase + roff);
                    }
                    FreePages(Phys, Pages, Error);
                    /* rollback previously mapped sections */
                    for (long J = 0; J < I; J++)
                    {
                        if (SectionBases[J] && SectionBases[J] != (void*)ZeroStub)
                        {
                            long SzJ = (long)ShTbl[J].sh_size;
                            if (SzJ > 0)
                            {
                                size_t   PgJ = (size_t)((SzJ + PageSize - 1) / PageSize);
                                uint64_t VaJ = (uint64_t)SectionBases[J];
                                for (size_t o2 = 0; o2 < PgJ * PageSize; o2 += PageSize)
                                {
                                    uint64_t PaJ = GetPhysicalAddress(Vmm.KernelSpace, VaJ + o2);
                                    UnmapPage(Vmm.KernelSpace, VaJ + o2);
                                    if (PaJ)
                                    {
                                        FreePage(PaJ, Error);
                                    }
                                }
                            }
                        }
                    }
                    KFree(SectionBases, Error);
                    KFree(Syms, Error);
                    KFree(SymBuf, Error);
                    KFree(StrBuf, Error);
                    KFree(ShTbl, Error);
                    return -BadAllocation;
                }
                Mapped += PageSize;
            }

            if (IsText)
            {
                ModMem.TextCursor += (uint64_t)(Pages * PageSize);
            }
            else
            {
                ModMem.DataCursor += (uint64_t)(Pages * PageSize);
            }

            SectionBases[I] = (void*)VaBase;

            if (Type == (uint32_t)8U)
            {
                memset((void*)VaBase, 0, (size_t)Size);
            }
            else
            {
                File* F = VfsOpen(__Path__, VFlgRDONLY);
                if (Probe_IF_Error(F) || !F)
                {
                    KFree(SectionBases, Error);
                    KFree(Syms, Error);
                    KFree(SymBuf, Error);
                    KFree(StrBuf, Error);
                    KFree(ShTbl, Error);
                    PushError("InstallModule",
                              LOGLINKERC_PError,
                              "failed to open file",
                              Pointer_TO_Error(F));
                    return -NotCanonical;
                }
                if (VfsLseek(F, (long)S->sh_offset, VSeekSET) < 0)
                {
                    VfsClose(F);
                    KFree(SectionBases, Error);
                    KFree(Syms, Error);
                    KFree(SymBuf, Error);
                    KFree(StrBuf, Error);
                    KFree(ShTbl, Error);
                    PushError("InstallModule",
                              LOGLINKERC_PError,
                              "failed to seek to relocation data",
                              -BadRead);
                    return -BadRead;
                }
                long Rd = VfsRead(F, (void*)VaBase, Size);
                VfsClose(F);
                if (Rd < Size)
                {
                    KFree(SectionBases, Error);
                    KFree(Syms, Error);
                    KFree(SymBuf, Error);
                    KFree(StrBuf, Error);
                    KFree(ShTbl, Error);
                    PushError("InstallModule",
                              LOGLINKERC_PError,
                              "failed to read section data",
                              -BadRead);
                    return -BadRead;
                }
            }
        }
    }

    for (long I = 0; I < SymCount; I++)
    {
        uint16_t Sh   = Syms[I].Shndx;
        uint64_t Base = 0;

        if (Sh == 0)
        {
            Base = 0;
        }
        else if (Sh < (uint16_t)ShNum)
        {
            Base = (uint64_t)SectionBases[Sh];
        }

        Syms[I].ResolvedAddr = Base ? (Base + Syms[I].Value) : 0ULL;
    }

    typedef struct
    {
        uint64_t r_offset;
        uint64_t r_info;
    } Elf64_Rel;

    for (long RIdx = 0; RIdx < ShNum; RIdx++)
    {
        const Elf64_Shdr* RelSh      = &ShTbl[RIdx];
        uint64_t          RelSecType = RelSh->sh_type;

        if (RelSecType != (uint64_t)4ULL && RelSecType != (uint64_t)9ULL)
        {
            continue;
        }

        uint32_t TgtIdx = RelSh->sh_info;
        if (TgtIdx >= (uint32_t)ShNum)
        {
            continue;
        }

        if (!SectionBases[TgtIdx])
        {
            SectionBases[TgtIdx] = (void*)ZeroStub;
        }

        long EntSz =
            (RelSecType == (uint64_t)4ULL) ? (long)sizeof(Elf64_Rela) : (long)sizeof(Elf64_Rel);
        long RelCnt = (long)((long)RelSh->sh_size / EntSz);
        if (RelCnt <= 0)
        {
            continue;
        }

        void* RelBuf = KMalloc((size_t)RelSh->sh_size);
        if (Probe_IF_Error(RelBuf) || !RelBuf)
        {
            continue;
        }

        File* RF = VfsOpen(__Path__, VFlgRDONLY);
        if (Probe_IF_Error(RF) || !RF)
        {
            KFree(RelBuf, Error);
            continue;
        }
        if (VfsLseek(RF, (long)RelSh->sh_offset, VSeekSET) < 0)
        {
            VfsClose(RF);
            KFree(RelBuf, Error);
            continue;
        }
        long RdRel = VfsRead(RF, RelBuf, (long)RelSh->sh_size);
        VfsClose(RF);
        if (RdRel < (long)RelSh->sh_size)
        {
            KFree(RelBuf, Error);
            continue;
        }

        for (long I = 0; I < RelCnt; I++)
        {
            uint32_t Type, SymIndex;
            uint64_t A;
            uint8_t* Loc;
            if (RelSecType == (uint64_t)4ULL)
            {
                const Elf64_Rela* R = &((Elf64_Rela*)RelBuf)[I];
                Type                = (uint32_t)(R->r_info & 0xffffffffU);
                SymIndex            = (uint32_t)(R->r_info >> 32);
                A                   = R->r_addend;
                Loc                 = ((uint8_t*)SectionBases[TgtIdx]) + R->r_offset;
            }
            else
            {
                const Elf64_Rel* R = &((Elf64_Rel*)RelBuf)[I];
                Type               = (uint32_t)(R->r_info & 0xffffffffU);
                SymIndex           = (uint32_t)(R->r_info >> 32);
                Loc                = ((uint8_t*)SectionBases[TgtIdx]) + R->r_offset;
                if (Type == 1U || Type == 8U)
                {
                    A = *(uint64_t*)Loc;
                }
                else if (Type == 2U || Type == 4U || Type == 10U || Type == 11U)
                {
                    A = (uint64_t)*(int32_t*)Loc;
                }
                else
                {
                    A = 0;
                }
            }

            if (SymIndex >= (uint32_t)SymCount)
            {
                continue;
            }

            const __ElfSymbol__* Sym = &Syms[SymIndex];
            uint64_t             S   = Sym->ResolvedAddr;

            if (!S && Sym->Shndx == 0)
            {
                void* Ext = KexpLookup(Sym->Name);
                S         = (uint64_t)Ext;
                if (Probe_IF_Error(Ext) || !Ext)
                {
                    continue;
                }
            }

            switch (Type)
            {
                case 1U:
                    *(uint64_t*)Loc = S + A;
                    break;

                case 2U:
                case 4U:
                    {
                        int64_t P      = (int64_t)((uint64_t)Loc + 4);
                        int64_t Disp64 = (int64_t)S - P;
                        *(int32_t*)Loc = (int32_t)Disp64;
                        break;
                    }

                case 8U:
                    *(uint64_t*)Loc = (uint64_t)SectionBases[TgtIdx] + A;
                    break;

                case 9U:
                    {
                        int64_t  P       = (int64_t)((uint64_t)Loc + 4);
                        __int128 S128    = (__int128)((int64_t)S);
                        __int128 A128    = (__int128)((int64_t)A);
                        __int128 P128    = (__int128)P;
                        __int128 Disp128 = S128 + A128 - P128;
                        int32_t  Disp32  = (int32_t)Disp128;
                        *(int32_t*)Loc   = Disp32;
                        break;
                    }

                case 10U:
                    {
                        uint64_t Val    = S + A;
                        *(uint32_t*)Loc = (uint32_t)Val;
                        break;
                    }

                case 11U:
                    {
                        int64_t Val    = (int64_t)(S + A);
                        *(int32_t*)Loc = (int32_t)Val;
                        break;
                    }

                default:
                    break;
            }
        }

        KFree(RelBuf, Error);
    }
    const __ElfSymbol__* InitSym  = 0;
    const __ElfSymbol__* ExitSym  = 0;
    const __ElfSymbol__* ProbeSym = 0;

    for (long I = 0; I < SymCount; I++)
    {
        /*init*/
        if (Syms[I].Name && strcmp(Syms[I].Name, "module_init") == Nothing)
        {
            InitSym = &Syms[I];
        }

        /*exit*/
        else if (Syms[I].Name && strcmp(Syms[I].Name, "module_exit") == Nothing)
        {
            ExitSym = &Syms[I];
        }

        /*probe*/
        else if (Syms[I].Name && strcmp(Syms[I].Name, "module_probe") ==
                                     Nothing) /*For polling and probemgr may handle it*/
        {
            ProbeSym = &Syms[I];
        }
    }
    if (Probe_IF_Error(InitSym) || !InitSym)
    {
        for (long J = 0; J < ShNum; J++)
        {
            if (SectionBases[J] && SectionBases[J] != (void*)ZeroStub)
            {
                long SzJ = (long)ShTbl[J].sh_size;
                if (SzJ > 0)
                {
                    size_t   PgJ = (size_t)((SzJ + PageSize - 1) / PageSize);
                    uint64_t VaJ = (uint64_t)SectionBases[J];
                    for (size_t off = 0; off < PgJ * PageSize; off += PageSize)
                    {
                        uint64_t PaJ = GetPhysicalAddress(Vmm.KernelSpace, VaJ + off);
                        UnmapPage(Vmm.KernelSpace, VaJ + off);
                        if (PaJ)
                        {
                            FreePage(PaJ, Error);
                        }
                    }
                }
            }
        }
        KFree(SectionBases, Error);
        KFree(Syms, Error);
        KFree(StrBuf, Error);
        KFree(SymBuf, Error);
        KFree(ShTbl, Error);
        PushError("InstallModule", LOGLINKERC_PError, "no init symbol found", -Missing);
        return -Missing;
    }

    void (*InitFn)(void) = 0;
    void (*ExitFn)(void) = 0;
    int (*ProbeFn)(void) = 0;

    /*init*/
    if (InitSym->ResolvedAddr)
    {
        InitFn = (void (*)(void))(uintptr_t)InitSym->ResolvedAddr;
    }
    else
    {
        uint8_t* Base =
            (uint8_t*)((InitSym->Shndx < (uint16_t)ShNum) ? SectionBases[InitSym->Shndx] : Nothing);

        InitFn = (void (*)(void))(Base ? (Base + InitSym->Value) : (uint8_t*)InitSym->Value);
    }

    /*exit*/
    if (ExitSym)
    {
        if (ExitSym->ResolvedAddr)
        {
            ExitFn = (void (*)(void))(uintptr_t)ExitSym->ResolvedAddr;
        }
        else
        {
            uint8_t* BaseE =
                (uint8_t*)((ExitSym->Shndx < (uint16_t)ShNum) ? SectionBases[ExitSym->Shndx]
                                                              : Nothing);

            ExitFn = (void (*)(void))(BaseE ? (BaseE + ExitSym->Value) : (uint8_t*)ExitSym->Value);
        }
    }

    /*probe*/
    if (ProbeSym)
    {
        if (ProbeSym->ResolvedAddr)
        {
            ProbeFn = (int (*)(void))(uintptr_t)ProbeSym->ResolvedAddr;
        }
        else
        {
            uint8_t* BaseP =
                (uint8_t*)((ProbeSym->Shndx < (uint16_t)ShNum) ? SectionBases[ProbeSym->Shndx]
                                                               : Nothing);
            ProbeFn =
                (int (*)(void))(BaseP ? (BaseP + ProbeSym->Value) : (uint8_t*)ProbeSym->Value);
        }
    }

    /*InitFn();*/ // No need for calling it here, DriverManager handles it

    ModuleRecord* Rec = (ModuleRecord*)KMalloc(sizeof(ModuleRecord));
    if (Probe_IF_Error(Rec) || !Rec)
    {
        /*its fine*/
        LOGLINKERC_PWarn(
            "failed to allocate memory for module record, module installed but can't be removed\n");
        return SysOkay;
    }

    Rec->Name         = __Path__;
    Rec->SectionBases = SectionBases;
    Rec->ShTbl        = ShTbl;
    Rec->Syms         = Syms;
    Rec->SymBuf       = SymBuf;
    Rec->StrBuf       = StrBuf;
    Rec->SectionCount = ShNum;
    Rec->ZeroStub     = ZeroStub;
    Rec->InitFn       = InitFn;
    Rec->ExitFn       = ExitFn;
    Rec->ProbeFn      = ProbeFn;
    Rec->RefCount     = 1;
    Rec->Next         = 0;

    ModuleRegistryAdd(Rec);
    LOGLINKERC_PSuccess("Installed %s\n", __Path__);
    return SysOkay;
}

int
UnInstallModule(const char* __Path__)
{
    if (Probe_IF_Error(__Path__) || !__Path__)
    {
        PushError("UnInstallModule", LOGLINKERC_PError, "bad path", -BadArguments);
        return -BadArguments;
    }

    ModuleRecord* Rec = ModuleRegistryFind(__Path__);
    if (Probe_IF_Error(Rec) || !Rec)
    {
        PushError(
            "UnInstallModule", LOGLINKERC_PError, "module not recorded", Pointer_TO_Error(Rec));
        return -NotRecorded;
    }

    if (Rec->RefCount > 1)
    {
        PushError("UnInstallModule", LOGLINKERC_PError, "module is busy, in reference", -Busy);
        return -Busy;
    }

    /*
    if (Rec->ExitFn)
    {
        Rec->ExitFn();
    }
    */ // DriverManager handles it

    SysErr  err;
    SysErr* Error = &err;

    for (long I = 0; I < Rec->SectionCount; I++)
    {
        if (Rec->SectionBases[I] && Rec->SectionBases[I] != (void*)Rec->ZeroStub)
        {
            long Sz = (long)Rec->ShTbl[I].sh_size;
            if (Sz > 0)
            {
                size_t   Pages = (size_t)((Sz + PageSize - 1) / PageSize);
                uint64_t Va    = (uint64_t)Rec->SectionBases[I];
                for (size_t off = 0; off < Pages * PageSize; off += PageSize)
                {
                    uint64_t Pa = GetPhysicalAddress(Vmm.KernelSpace, Va + off);
                    UnmapPage(Vmm.KernelSpace, Va + off);
                    if (Pa)
                    {
                        FreePage(Pa, Error);
                    }
                }
            }
        }
    }

    ModuleRegistryRemove(Rec);
    KFree(Rec->SectionBases, Error);
    KFree(Rec->Syms, Error);
    KFree(Rec->SymBuf, Error);
    KFree(Rec->StrBuf, Error);
    KFree(Rec->ShTbl, Error);
    KFree(Rec, Error);

    LOGLINKERC_PSuccess("Uninstalled %s\n", __Path__);
    return SysOkay;
}