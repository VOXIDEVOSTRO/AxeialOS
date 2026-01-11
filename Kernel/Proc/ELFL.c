#include <ELFL.h>

/*fun fact: this ELF loader was once a Kernel Module (.ko)*/

/*Global errno*/
SysErr  err;
SysErr* Error = &err;

static inline uint64_t
__AlignDown(uint64_t v, uint64_t a)
{
    return v & ~(a - 1);
}
static inline uint64_t
__AlignUp(uint64_t v, uint64_t a)
{
    return (v + (a - 1)) & ~(a - 1);
}

static int
ReadExact(File* __File__, uint64_t __Offset__, void* __Buff__, long __Len__)
{
    if (VfsLseek(__File__, (long)__Offset__, VSeekSET) < 0)
    {
        PError("Seek failed __Offset__=%llu\n", HEX64(__Offset__));
        return -ErrReturn;
    }
    long rd = VfsRead(__File__, __Buff__, __Len__);
    if (rd != __Len__)
    {
        PError("Read failed want=%ld got=%ld at __Offset__=%llu\n", __Len__, rd, HEX64(__Offset__));
        return -Dangling;
    }
    return SysOkay;
}

int
Elf64Probe(File* __File__)
{
    Elf64_EhdrMOD Eh = {0};
    if (ReadExact(__File__, 0, &Eh, (long)sizeof(Eh)) != SysOkay)
    {
        PError("header read failed\n");
        return -NoSuch;
    }

    if (Eh.e_ident[EI_MAG0] != ELFMAG0 || Eh.e_ident[EI_MAG1] != ELFMAG1 ||
        Eh.e_ident[EI_MAG2] != ELFMAG2 || Eh.e_ident[EI_MAG3] != ELFMAG3)
    {
        PError("bad magic\n");
        return -BadEntity;
    }
    if (Eh.e_ident[EI_CLASS] != ELFCLASS64 || Eh.e_ident[EI_DATA] != ELFDATA2LSB)
    {
        PError(
            "unsupported class/data class=%u data=%u\n", Eh.e_ident[EI_CLASS], Eh.e_ident[EI_DATA]);
        return -Impilict;
    }
    if (Eh.e_machine != EM_X86_64)
    {
        PError("unsupported machine=%u\n", Eh.e_machine);
        return -Impilict;
    }

    PDebug("entry=%llu phoff=%llu phnum=%u phentsize=%u\n",
           HEX64(Eh.e_entry),
           HEX64(Eh.e_phoff),
           Eh.e_phnum,
           Eh.e_phentsize);
    return SysOkay;
}

int
Elf64Load(File* __File__, VirtualMemorySpace* __Space__, void* __Out__)
{
    if (Probe_IF_Error(__File__) || !__File__ || Probe_IF_Error(__Space__) || !__Space__ ||
        Probe_IF_Error(__Out__) || !__Out__)
    {
        PError("bad args __File__=%p __Space__=%p __Out__=%p\n", __File__, __Space__, __Out__);
        return -BadArgs;
    }

    ELFImage*     Img = (ELFImage*)__Out__;
    Elf64_EhdrMOD Eh  = {0};

    if (ReadExact(__File__, 0, &Eh, (long)sizeof(Eh)) != SysOkay)
    {
        PError("header read failed\n");
        return -NoRead;
    }

    long     phnum   = (long)Eh.e_phnum;
    long     phsize  = (long)Eh.e_phentsize;
    uint64_t phoff   = Eh.e_phoff;
    uint64_t tblsize = (uint64_t)phnum * (uint64_t)phsize;

    if (phnum <= 0 || phsize <= 0 || tblsize == 0)
    {
        PError("invalid program header table phnum=%ld phsize=%ld\n", phnum, phsize);
        return -BadEntry;
    }

    PDebug("entry=%llu phoff=%llu phnum=%ld phentsize=%ld\n",
           HEX64(Eh.e_entry),
           HEX64(phoff),
           phnum,
           phsize);

    uint8_t* phtbl = (uint8_t*)KMalloc((size_t)tblsize);
    if (Probe_IF_Error(phtbl) || !phtbl)
    {
        PError("phtbl alloc failed size=%llu\n", HEX64(tblsize));
        return -BadAlloc;
    }

    if (ReadExact(__File__, phoff, phtbl, (long)tblsize) != SysOkay)
    {
        KFree(phtbl, Error);
        PError("program headers read failed\n");
        return -NoRead;
    }

    uint64_t Firstbase = 0;

    for (long Idx = 0; Idx < phnum; Idx++)
    {
        Elf64_Phdr* Ph = (Elf64_Phdr*)(phtbl + (Idx * phsize));

        PDebug("PH[%ld]: type=%u flags=%x __Offset__=%llu vaddr=%llu FSize=%llu MSize=%llu \n"
               "align=%llu",
               Idx,
               Ph->p_type,
               Ph->p_flags,
               HEX64(Ph->p_offset),
               HEX64(Ph->p_vaddr),
               HEX64(Ph->p_filesz),
               HEX64(Ph->p_memsz),
               HEX64(Ph->p_align));

        if (Ph->p_type != PT_LOAD)
        {
            continue;
        }

        if (Ph->p_memsz == 0)
        {
            PError("PH[%ld]: MSize=0 for PT_LOAD; skipping\n", Idx);
            continue;
        }
        if (Ph->p_filesz > Ph->p_memsz)
        {
            PError("PH[%ld]: FSize(%llu) > MSize(%llu)\n",
                   Idx,
                   HEX64(Ph->p_filesz),
                   HEX64(Ph->p_memsz));
            KFree(phtbl, Error);
            return -1;
        }
        if (Ph->p_align && (Ph->p_align & (Ph->p_align - 1)))
        {
            PError("PH[%ld]: non-power-of-two align=%llu\n", Idx, HEX64(Ph->p_align));
            KFree(phtbl, Error);
            return -1;
        }

        uint64_t Virt       = Ph->p_vaddr;
        uint64_t FSize      = Ph->p_filesz;
        uint64_t MSize      = Ph->p_memsz;
        uint64_t __Offset__ = Ph->p_offset;
        uint64_t VirtStart  = __AlignDown(Virt, PageSize);
        uint64_t VirtEnd    = __AlignUp(Virt + MSize, PageSize);
        uint64_t MapRange   = VirtEnd - VirtStart;

        /* Page flags for user segments: present + user; write if PF_W; NX if !PF_X.*/
        uint64_t flags = PTEPRESENT | PTEUSER;
        if (Ph->p_flags & PF_W)
        {
            flags |= PTEWRITABLE;
        }
        if (Ph->p_flags & PF_X)
        {
            flags &= ~PTENOEXECUTE;
        }
        else
        {
            flags |= PTENOEXECUTE;
        }

        PDebug("Virt=[%llu..%llu) __Len__=%llu flags=%llx data-range=[%llu..%llu)\n",
               HEX64(VirtStart),
               HEX64(VirtEnd),
               HEX64(MapRange),
               HEX64(flags),
               HEX64(Virt),
               HEX64(Virt + FSize));

        if (MapRangeZeroed(__Space__, VirtStart, (long)MapRange, flags) != 0)
        {
            PError("MapRangeZeroed failed Virt=%llu __Len__=%llu flags=%llx\n",
                   HEX64(VirtStart),
                   HEX64(MapRange),
                   HEX64(flags));
            KFree(phtbl, Error);
            return -Dangling;
        }

        uint8_t* BufferForSegment = NULL;
        if (FSize)
        {
            BufferForSegment = (uint8_t*)KMalloc((size_t)FSize);
            if (Probe_IF_Error(BufferForSegment) || !BufferForSegment)
            {
                PError("PH[%ld]: BufferForSegment alloc failed size=%llu\n", Idx, HEX64(FSize));
                KFree(phtbl, Error);
                return -BadAlloc;
            }
            if (ReadExact(__File__, __Offset__, BufferForSegment, (long)FSize) != 0)
            {
                PError("PH[%ld]: segment read failed __Offset__=%llu size=%llu\n",
                       Idx,
                       HEX64(__Offset__),
                       HEX64(FSize));
                KFree(BufferForSegment, Error);
                KFree(phtbl, Error);
                return -NoRead;
            }
        }

        uint64_t Cpy = 0;
        while (Cpy < MSize)
        {
            uint64_t DESTVa = Virt + Cpy;
            uint64_t Phys   = GetPhysicalAddress(__Space__, DESTVa);
            if (!Phys)
            {
                PError("PH[%ld]: no Phys for Virt=%llu (Cpy=%llu of %llu)\n",
                       Idx,
                       HEX64(DESTVa),
                       HEX64(Cpy),
                       HEX64(MSize));
                if (BufferForSegment)
                {
                    KFree(BufferForSegment, Error);
                }
                KFree(phtbl, Error);
                return -Dangling;
            }

            uint64_t PageialOffset = DESTVa & (PageSize - 1);
            uint64_t BigChunk      = PageSize - PageialOffset;
            uint64_t LeftOver      = MSize - Cpy;
            if (BigChunk > LeftOver)
            {
                BigChunk = LeftOver;
            }

            uint8_t* KrnVirt = (uint8_t*)PhysToVirt(Phys);
            if (Probe_IF_Error(KrnVirt) || !KrnVirt)
            {
                PError("PH[%ld]: PhysToVirt failed Phys=%llu\n", Idx, HEX64(Phys));
                if (BufferForSegment)
                {
                    KFree(BufferForSegment, Error);
                }
                KFree(phtbl, Error);
                return -Dangling;
            }
            KrnVirt += PageialOffset;

            size_t fileChunk = 0;
            if (Cpy < FSize && BufferForSegment)
            {
                uint64_t fremain = FSize - Cpy;
                fileChunk        = (size_t)(BigChunk > fremain ? fremain : BigChunk);
                memcpy(KrnVirt, BufferForSegment + Cpy, fileChunk);
            }
            if (BigChunk > fileChunk)
            {
                memset(KrnVirt + fileChunk, 0, (size_t)(BigChunk - fileChunk));
            }

            PDebug("Virt=%llu Phys=%llu PageialOffset=%llu BigChunk=%llu fileChunk=%zu\n",
                   HEX64(DESTVa),
                   HEX64(Phys),
                   HEX64(PageialOffset),
                   HEX64(BigChunk),
                   fileChunk);

            Cpy += BigChunk;
        }

        if (BufferForSegment)
        {
            KFree(BufferForSegment, Error);
        }

        if (Firstbase == 0)
        {
            Firstbase = VirtStart;
        }
    }

    Img->Space    = __Space__;
    Img->Entry    = Eh.e_entry;
    Img->LoadBase = Firstbase;
    Img->Flags    = 0;

    PDebug("Entry=%llu Base=%llu\n", HEX64(Img->Entry), HEX64(Img->LoadBase));

    KFree(phtbl, Error);
    return SysOkay;
}

int
Elf64BuildAux(File* __File__, void* __Img__, void* __AuxB__, long __AuxC__)
{
    ELFImage* Img      = (ELFImage*)__Img__;
    uint64_t* Aux      = (uint64_t*)__AuxB__;
    long      HatORCap = __AuxC__ / (long)sizeof(uint64_t);

    if (HatORCap < 2 * 10)
    {
        PError("auxv too small HatORCap=%ld\n", HatORCap);
        return -TooSmall;
    }

    long n   = 0;
    Aux[n++] = AT_PHDR;
    Aux[n++] = 0; /*Optional?*/
    Aux[n++] = AT_PHENT;
    Aux[n++] = (uint64_t)sizeof(Elf64_Phdr);
    Aux[n++] = AT_PHNUM;
    Aux[n++] = 0; /*Optional?*/
    Aux[n++] = AT_PAGESZ;
    Aux[n++] = PageSize;
    Aux[n++] = AT_BASE;
    Aux[n++] = Img->LoadBase;
    Aux[n++] = AT_ENTRY;
    Aux[n++] = Img->Entry;
    Aux[n++] = AT_EXECFN;
    Aux[n++] = 0;
    Aux[n++] = AT_NULL;
    Aux[n++] = 0;

    Img->Auxv.Buf = Aux;
    Img->Auxv.Cap = HatORCap;
    Img->Auxv.Len = n;

    PDebug("AT_BASE=%llu AT_ENTRY=%llu\n", HEX64(Img->LoadBase), HEX64(Img->Entry));
    return SysOkay;
}