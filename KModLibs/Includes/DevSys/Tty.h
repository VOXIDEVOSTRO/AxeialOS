#pragma once

#ifdef __Kernel__
#    include <AllTypes.h>
#    include <Sync.h>
#else
#    include <EveryType.h>
#    include <SyncSys.h>
#    include <Types/__int__.h> /*Shut up GCC*/
#endif

typedef struct TtyCtx
{
    char     Name[16];
    uint32_t Fg;
    uint32_t Bg;
    SpinLock Lock;
} TtyCtx;

enum TtyCtlCmd
{
    NullTerm,
    NewTtyDevice,
};