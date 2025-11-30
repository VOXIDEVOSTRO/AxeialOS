#pragma once
#include <AllTypes.h>
#include <AxeThreads.h>
#include <Sync.h>

typedef void (*PosixSigHandler)(int);

typedef struct PosixSigAction
{
    PosixSigHandler Handler;
    uint64_t        Mask;
    int             Flags;
} PosixSigAction;

typedef enum PosixSig
{
    SigHup  = 1,
    SigInt  = 2,
    SigQuit = 3,
    SigIll  = 4,
    SigAbrt = 6,
    SigFpe  = 8,
    SigKill = 9,
    SigSegv = 11,
    SigPipe = 13,
    SigAlrm = 14,
    SigTerm = 15,
    SigStop = 19,
    SigTstp = 20,
    SigCont = 18,
    SigChld = 17
} PosixSig;

int PosixKill(long __Pid__, int __Sig__);
int PosixTkill(long __Tid__, int __Sig__);
int PosixSigaction(int __Sig__, const PosixSigAction* __Act__, PosixSigAction* __OldAct__);
int PosixSigprocmask(int __How__, const uint64_t* __Set__, uint64_t* __OldSet__);
int PosixSigpending(uint64_t* __OutMask__);
int PosixSigsuspend(const uint64_t* __Mask__);
int PosixSigqueue(long __Pid__, int __Sig__, int __Value__);
int PosixDeliverSignals(void);

KEXPORT(PosixKill)
KEXPORT(PosixTkill)
KEXPORT(PosixSigaction)
KEXPORT(PosixSigprocmask)
KEXPORT(PosixSigpending)
KEXPORT(PosixSigsuspend)
KEXPORT(PosixSigqueue)
KEXPORT(PosixDeliverSignals)