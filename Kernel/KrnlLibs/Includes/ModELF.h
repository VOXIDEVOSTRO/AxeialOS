#pragma once

#include <AllTypes.h>
#include <Errnos.h>

/*Section Header*/
typedef struct
{
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;

} Elf64_Shdr;

/*ELF Header*/
typedef struct
{
    unsigned char e_ident[16]; /* ELF identification bytes */
    uint16_t      e_type;      /* Object file type */
    uint16_t      e_machine;   /* Target architecture */
    uint32_t      e_version;   /* ELF version */
    uint64_t      e_entry;     /* Entry point (unused for modules) */
    uint64_t      e_phoff;     /* Program header offset */
    uint64_t      e_shoff;     /* Section header offset */
    uint32_t      e_flags;     /* Processor-specific flags */
    uint16_t      e_ehsize;    /* ELF header size */
    uint16_t      e_phentsize; /* Program header entry size */
    uint16_t      e_phnum;     /* Program header entry count */
    uint16_t      e_shentsize; /* Section header entry size */
    uint16_t      e_shnum;     /* Section header entry count */
    uint16_t      e_shstrndx;  /* Section name string table index */

} Elf64_Ehdr;

/*Section set*/
typedef struct __ElfSectionSet__
{
    long Text;
    long Rodata;
    long Data;
    long Bss;

    long Symtab;
    long Strtab;

    /* Optional */
    long RelaText;
    long RelaData;
    long RelText;
    long RelData;

} __ElfSectionSet__;

/*Symbols*/
typedef struct
{
    uint32_t      st_name; /* Index into .strtab */
    unsigned char st_info; /* Symbol type and binding */
    unsigned char st_other;
    uint16_t      st_shndx; /* Section index */
    uint64_t      st_value; /* Symbol value (offset or absolute) */
    uint64_t      st_size;  /* Size of symbol */

} Elf64_Sym;

/*Rellocate*/
typedef struct __ElfSymbol__
{
    const char*   Name;
    uint64_t      Value;
    uint64_t      ResolvedAddr;
    uint16_t      Shndx;
    unsigned char Info;

} __ElfSymbol__;

/* ELF64 relocation with addend */
typedef struct
{
    uint64_t r_offset; /* Location to apply relocation */
    uint64_t r_info;   /* Symbol index and type */
    int64_t  r_addend; /* Constant addend */

} Elf64_Rela;

/* ELF64 relocation without addend */
typedef struct
{
    uint64_t r_offset; /* Location to apply relocation */
    uint64_t r_info;   /* Symbol index and type */
} Elf64_Rel;

/*Module*/
typedef struct ModImage
{
    uint8_t* Text;
    long     TextSz;

    uint8_t* Rodata;
    long     RodataSz;

    uint8_t* Data;
    long     DataSz;

    uint8_t* Bss;
    long     BssSz;

    __ElfSymbol__* Symbols;
    long           SymCount;

    uint64_t InitAddr;
    uint64_t ExitAddr;

} ModImage;

/* Extract symbol index and type from r_info */
#define ELF64_R_SYM(I)  ((I) >> 32)
#define ELF64_R_TYPE(I) ((uint32_t)(I))

int InstallModule(const char* __Path__);
int UnInstallModule(const char* __Path__);