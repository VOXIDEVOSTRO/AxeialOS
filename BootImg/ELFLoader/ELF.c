#include <Dev.h>
#include <EveryType.h>
#include <Heaps.h>
#include <Loader.h>
#include <Logings.h>
#include <Memory.h>
#include <StrHelp.h>
#include <SyncSys.h>
#include <ThrdSys.h>
#include <Vfs.h>

#define __attribute_unused__ __attribute__((unused))

typedef struct
{
    unsigned char e_ident[16];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    uint64_t      e_entry;
    uint64_t      e_phoff;
    uint64_t      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} Elf64_Ehdr;

typedef struct
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

#define EI_MAG0    0
#define EI_MAG1    1
#define EI_MAG2    2
#define EI_MAG3    3
#define EI_CLASS   4
#define EI_DATA    5
#define EI_VERSION 6

#define ELFMAG0     0x7F
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFCLASS64  2
#define ELFDATA2LSB 1

#define EM_X86_64 62
#define ET_EXEC   2
#define ET_DYN    3

#define PT_LOAD 1
#define PF_X    0x1
#define PF_W    0x2
#define PF_R    0x4

#define AT_NULL   0
#define AT_PHDR   3
#define AT_PHENT  4
#define AT_PHNUM  5
#define AT_PAGESZ 6
#define AT_BASE   7
#define AT_ENTRY  9
#define AT_EXECFN 31

static inline uint64_t
__AlignUp__(uint64_t __Value__, uint64_t __Align__)
{
    return (__Value__ + (__Align__ - 1)) & ~(__Align__ - 1);
}

static int
__ReadExact__(File* __File__, uint64_t __Off__, void* __Buf__, long __Len__)
{
    if (VfsLseek(__File__, (long)__Off__, VSeekSET) < 0)
    {
        PError("ELF: seek failed off=%llu\n", (unsigned long long)__Off__);
        return -1;
    }
    long rd = VfsRead(__File__, __Buf__, __Len__);
    if (rd != __Len__)
    {
        PError("ELF: read failed want=%ld got=%ld\n", __Len__, rd);
        return -1;
    }
    return 0;
}

static int
Elf64Probe(File* __File__)
{
    Elf64_Ehdr Eh = (Elf64_Ehdr){0};

    if (__ReadExact__(__File__, 0, &Eh, (long)sizeof(Eh)) != 0)
    {
        PError("Elf64Probe: header read failed\n");
        return -1;
    }

    if (Eh.e_ident[EI_MAG0] != ELFMAG0 || Eh.e_ident[EI_MAG1] != ELFMAG1 ||
        Eh.e_ident[EI_MAG2] != ELFMAG2 || Eh.e_ident[EI_MAG3] != ELFMAG3)
    {
        PError("Elf64Probe: bad magic\n");
        return -1;
    }
    if (Eh.e_ident[EI_CLASS] != ELFCLASS64 || Eh.e_ident[EI_DATA] != ELFDATA2LSB)
    {
        PError("Elf64Probe: unsupported class/data\n");
        return -1;
    }
    if (Eh.e_machine != EM_X86_64)
    {
        PError("Elf64Probe: unsupported machine\n");
        return -1;
    }

    return 0;
}

static int
Elf64Load(File* __File__, VirtualMemorySpace* __Space__, void* __OutImage__)
{
    if (!__File__ || !__Space__ || !__OutImage__)
    {
        PError("Elf64Load: bad args\n");
        return -1;
    }

    VirtImage* Img = (VirtImage*)__OutImage__;
    Elf64_Ehdr Eh  = (Elf64_Ehdr){0};

    if (__ReadExact__(__File__, 0, &Eh, (long)sizeof(Eh)) != 0)
    {
        PError("Elf64Load: header read failed\n");
        return -1;
    }

    long phnum   = (long)Eh.e_phnum;
    long phsize  = (long)Eh.e_phentsize;
    long tblsize = phnum * phsize;

    if (phnum <= 0 || phsize <= 0 || tblsize <= 0)
    {
        PError("Elf64Load: invalid program header table\n");
        return -1;
    }

    uint8_t* phtbl = (uint8_t*)KMalloc((size_t)tblsize);
    if (!phtbl)
    {
        PError("Elf64Load: phtbl alloc failed\n");
        return -1;
    }
    if (__ReadExact__(__File__, Eh.e_phoff, phtbl, tblsize) != 0)
    {
        KFree(phtbl);
        return -1;
    }

    uint64_t firstBase = 0;

    for (long i = 0; i < phnum; i++)
    {
        Elf64_Phdr* Ph = (Elf64_Phdr*)(phtbl + (i * phsize));

        if (Ph->p_type != PT_LOAD)
        {
            continue;
        }

        uint64_t va      = Ph->p_vaddr;
        uint64_t filesz  = Ph->p_filesz;
        uint64_t memsz   = Ph->p_memsz;
        uint64_t off     = Ph->p_offset;
        uint64_t vaStart = va & ~(PageSize - 1);
        uint64_t vaEnd   = __AlignUp__(va + memsz, PageSize);
        uint64_t mapLen  = vaEnd - vaStart;

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

        if (VirtMapRangeZeroed(__Space__, vaStart, (long)mapLen, flags) != 0)
        {
            PError("Elf64Load: VirtMapRangeZeroed failed va=%llx len=%llu\n",
                   (unsigned long long)vaStart,
                   (unsigned long long)mapLen);
            KFree(phtbl);
            return -1;
        }

        uint8_t* segBuf = NULL;
        if (filesz)
        {
            segBuf = (uint8_t*)KMalloc((size_t)filesz);
            if (!segBuf)
            {
                KFree(phtbl);
                PError("Elf64Load: segBuf alloc failed size=%llu\n", (unsigned long long)filesz);
                return -1;
            }
            if (__ReadExact__(__File__, off, segBuf, (long)filesz) != 0)
            {
                KFree(segBuf);
                KFree(phtbl);
                PError("Elf64Load: segment read failed off=%llx size=%llx\n",
                       (unsigned long long)off,
                       (unsigned long long)filesz);
                return -1;
            }
        }

        uint64_t copied = 0;
        while (copied < memsz)
        {
            uint64_t dstVa = va + copied;
            uint64_t phys  = GetPhysicalAddress(__Space__, dstVa);
            if (phys == 0)
            {
                PError("Elf64Load: no phys for va=%llx\n", (unsigned long long)dstVa);
                if (segBuf)
                {
                    KFree(segBuf);
                }
                KFree(phtbl);
                return -1;
            }

            uint64_t pageOff = dstVa & (PageSize - 1);
            uint64_t chunk   = PageSize - pageOff;
            uint64_t remain  = memsz - copied;
            if (chunk > remain)
            {
                chunk = remain;
            }

            uint8_t* kv = (uint8_t*)PhysToVirt(phys) + pageOff;

            size_t fileChunk = 0;
            if (copied < filesz && segBuf)
            {
                uint64_t fremain = filesz - copied;
                fileChunk        = (size_t)(chunk > fremain ? fremain : chunk);
                memcpy(kv, segBuf + copied, fileChunk);
            }
            if (chunk > fileChunk)
            {
                memset(kv + fileChunk, 0, (size_t)(chunk - fileChunk));
            }

            copied += chunk;
        }

        if (segBuf)
        {
            KFree(segBuf);
        }

        if (firstBase == 0)
        {
            firstBase = vaStart;
        }
    }

    Img->Space    = __Space__;
    Img->Entry    = Eh.e_entry;
    Img->LoadBase = firstBase;
    Img->Flags    = 0;

    KFree(phtbl);

    return 0;
}

static int
Elf64BuildAux(File* __File__, void* __Image__, void* __AuxvBuf__, long __AuxvCap__)
{
    __attribute_unused__ File* F = __File__;

    VirtImage* Img = (VirtImage*)__Image__;
    uint64_t*  Aux = (uint64_t*)__AuxvBuf__;
    long       cap = __AuxvCap__ / (long)sizeof(uint64_t);

    long n = 0;

    if (cap < 2 * 10)
    {
        PError("Elf64BuildAux: auxv too small\n");
        return -1;
    }

    Aux[n++] = AT_PHDR;
    Aux[n++] = 0;
    Aux[n++] = AT_PHENT;
    Aux[n++] = (uint64_t)sizeof(Elf64_Phdr);
    Aux[n++] = AT_PHNUM;
    Aux[n++] = 0;
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
    Img->Auxv.Cap = cap;
    Img->Auxv.Len = n;

    return 0;
}

static DynLoader Elf64Loader = {
    .Caps = {.Name = "elf64", .Priority = 100, /*Upsurdly Large ik*/ .Features = 0},
    .Ops  = {.Probe = Elf64Probe, .Load = Elf64Load, .BuildAux = Elf64BuildAux}};

void
InitElf64Loader(void)
{
    int r = DynLoaderRegister(&Elf64Loader);
    if (r != 0)
    {
        PError("InitElf64Loader: register failed\n");
        return;
    }
}

void
ExitElf64Loader(void)
{
    int r = DynLoaderUnregister("elf64");
    if (r != 0)
    {
        PError("ExitElf64Loader: unregister failed\n");
        return;
    }
}

int
module_init(void)
{
    InitElf64Loader();
    return 0;
}

int
module_exit(void)
{
    ExitElf64Loader();
    return 0;
}