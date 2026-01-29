#pragma once

#include <APICTimer.h>
#include <AllTypes.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <BootConsole.h>
#include <BootImg.h>
#include <DevFS.h>
#include <EarlyBootFB.h>
#include <GDT.h>
#include <IDT.h>
#include <KExports.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <LimineServices.h>
#include <ModELF.h>
#include <ModMemMgr.h>
#include <PMM.h>
#include <POSIXFd.h>
#include <POSIXProc.h>
#include <POSIXProcFS.h>
#include <POSIXSignals.h>
#include <SMP.h>
#include <Serial.h>
#include <String.h>
#include <SymAP.h>
#include <Sync.h>
#include <Syscall.h>
#include <Timer.h>
#include <VFS.h>
#include <VMM.h>

typedef struct ELFAuxv
{
    uint64_t* Buf;
    long      Cap;
    long      Len;
} ELFAuxv;

typedef struct ELFImage
{
    VirtualMemorySpace* Space;
    uint64_t            Entry;
    uint64_t            UserSp;
    uint64_t            LoadBase;
    uint32_t            Flags;
    void*               LoaderPriv;
    ELFAuxv             Auxv;
} ELFImage;

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
} Elf64_EhdrMOD;

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

#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6
#define ELFMAG0     0x7F
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define EM_X86_64   62
#define ET_EXEC     2
#define ET_DYN      3
#define PT_LOAD     1
#define PF_X        0x1
#define PF_W        0x2
#define PF_R        0x4
#define AT_NULL     0
#define AT_PHDR     3
#define AT_PHENT    4
#define AT_PHNUM    5
#define AT_PAGESZ   6
#define AT_BASE     7
#define AT_ENTRY    9
#define AT_EXECFN   31

#define HEX64(x) ((unsigned long long)(x))

int Elf64BuildAux(File* __File__, void* __Img__, void* __AuxB__, long __AuxC__);
int Elf64Load(File* __File__, VirtualMemorySpace* __Space__, void* __Out__);
int Elf64Probe(File* __File__);

/*Completely unrelated*/
uint64_t SetStack(VirtualMemorySpace* __Space__,
                  const char* const*  __Argv__,
                  const char* const*  __Envp__,
                  int                 __Nx__,
                  uint64_t*           __OutRsp__);