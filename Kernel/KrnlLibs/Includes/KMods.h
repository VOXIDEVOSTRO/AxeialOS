#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <ModELF.h>

typedef struct ModuleRecord
{
    const char*    Name;
    void**         SectionBases;
    Elf64_Shdr*    ShTbl;
    __ElfSymbol__* Syms;
    Elf64_Sym*     SymBuf;
    char*          StrBuf;
    long           SectionCount;
    uint8_t*       ZeroStub;

    void (*InitFn)(void);
    void (*ExitFn)(void);
    int (*ProbeFn)(void); /*For probe drivers*/

    int                  RefCount;
    struct ModuleRecord* Next;

} ModuleRecord;

extern ModuleRecord* ModuleListHead;

int           ModuleRegistryInit(void);
int           ModuleRegistryAdd(ModuleRecord* __Rec__);
ModuleRecord* ModuleRegistryFind(const char* __Name__);
int           ModuleRegistryRemove(ModuleRecord* __Rec__);

KEXPORT(ModuleRegistryInit);
KEXPORT(ModuleRegistryAdd);
KEXPORT(ModuleRegistryFind);
KEXPORT(ModuleRegistryRemove);