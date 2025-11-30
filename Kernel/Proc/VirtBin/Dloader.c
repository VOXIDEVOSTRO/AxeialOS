#include <AllTypes.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <String.h>
#include <VFS.h>
#include <VMM.h>
#include <VirtBin.h>

/* Registry */
#define MaxLoaders 8
static const DynLoader* __Loaders__[MaxLoaders];
static long             __Count__;

int
DynLoaderRegister(const DynLoader* __Loader__)
{
    if (!__Loader__ || __Count__ >= MaxLoaders)
    {
        return -1;
    }
    __Loaders__[__Count__++] = __Loader__;
    return 0;
}

int
DynLoaderUnregister(const char* __Name__)
{
    long I;
    for (I = 0; I < __Count__; I++)
    {
        const DynLoader* L = __Loaders__[I];
        if (L && L->Caps.Name && strcmp(L->Caps.Name, __Name__) == 0)
        {
            long J;
            for (J = I; J + 1 < __Count__; J++)
            {
                __Loaders__[J] = __Loaders__[J + 1];
            }
            __Loaders__[__Count__ - 1] = NULL;
            __Count__--;
            return 0;
        }
    }
    return -1;
}

const DynLoader*
DynLoaderSelect(File* __File__)
{
    long I;
    for (I = 0; I < __Count__; I++)
    {
        const DynLoader* L = __Loaders__[I];
        if (L && L->Ops.Probe && L->Ops.Probe(__File__) == 0)
        {
            return L;
        }
    }
    return NULL;
}