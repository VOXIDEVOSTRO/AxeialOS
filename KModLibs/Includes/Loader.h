#pragma once

#include <EveryType.h>
#include <Memory.h>
#include <Vfs.h>

typedef struct DynLoaderCaps
{
    const char* Name;
    uint32_t    Priority;
    uint32_t    Features;
} DynLoaderCaps;

typedef struct DynLoaderOps
{
    int (*Probe)(File* __File__);
    int (*Load)(File* __File__, VirtualMemorySpace* __Space__, void* __OutImage__);
    int (*BuildAux)(File* __File__, void* __Image__, void* __AuxvBuf__, long __AuxvCap__);
} DynLoaderOps;

typedef struct DynLoader
{
    DynLoaderCaps Caps;
    DynLoaderOps  Ops;
} DynLoader;

int              DynLoaderRegister(const DynLoader* __Loader__);
int              DynLoaderUnregister(const char* __Name__);
const DynLoader* DynLoaderSelect(File* __File__);

typedef struct VirtAuxv
{
    uint64_t* Buf;
    long      Cap;
    long      Len;
} VirtAuxv;

typedef struct VirtImage
{
    VirtualMemorySpace* Space;
    uint64_t            Entry;
    uint64_t            UserSp;
    uint64_t            LoadBase;
    uint32_t            Flags;
    void*               LoaderPriv;
    VirtAuxv            Auxv;
} VirtImage;

typedef struct VirtRequest
{
    const char*        Path;
    File*              File;
    const char* const* Argv;
    const char* const* Envp;
    uint32_t           Hints;
} VirtRequest;

VirtualMemorySpace* VirtCreateSpace(void);
int
VirtMapPage(VirtualMemorySpace* __Space__, uint64_t __Va__, uint64_t __Phys__, uint64_t __Flags__);
int      VirtMapRangeZeroed(VirtualMemorySpace* __Space__,
                            uint64_t            __VaStart__,
                            uint64_t            __Len__,
                            uint64_t            __Flags__);
uint64_t VirtSetupStack(VirtualMemorySpace* __Space__,
                        const char* const*  __Argv__,
                        const char* const*  __Envp__,
                        int                 __Nx__,
                        uint64_t*           __OutRsp__);
int      VirtLoad(const VirtRequest* __Req__, VirtImage* __OutImg__);
int      VirtCommit(VirtImage* __Img__);