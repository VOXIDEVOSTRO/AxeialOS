#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <KExports.h>

typedef struct
{
    volatile uint32_t Lock;
    uint32_t          CpuId;
    const char*       Name;
    uint64_t          Flags;

} SpinLock;

void InitializeSpinLock(SpinLock* __Lock__, const char* __Name__, SysErr* __Err__ _unused);
void AcquireSpinLock(SpinLock* __Lock__, SysErr* __Err__ _unused);
void ReleaseSpinLock(SpinLock* __Lock__, SysErr* __Err__ _unused);
bool TryAcquireSpinLock(SpinLock* __Lock__);

typedef struct
{
    volatile uint32_t Lock;
    uint32_t          Owner;
    uint32_t          RecursionCount;
    const char*       Name;
} Mutex;

void InitializeMutex(Mutex* __Mutex__, const char* __Name__, SysErr* __Err__);
void AcquireMutex(Mutex* __Mutex__, SysErr* __Err__);
void ReleaseMutex(Mutex* __Mutex__, SysErr* __Err__);
bool TryAcquireMutex(Mutex* __Mutex__);

typedef struct
{
    volatile int32_t  Count;
    volatile uint32_t WaitQueue;
    SpinLock          QueueLock;
    const char*       Name;
} Semaphore;

void InitializeSemaphore(Semaphore*  __Semaphore__,
                         int32_t     __InitialCount__,
                         const char* __Name__,
                         SysErr*     __Err__);
void AcquireSemaphore(Semaphore* __Semaphore__, SysErr* __Err__ _unused);
void ReleaseSemaphore(Semaphore* __Semaphore__, SysErr* __Err__ _unused);
bool TryAcquireSemaphore(Semaphore* __Semaphore__);

/*BusyWait*/
void __NONBLOCK__BusyWait(uint64_t __Loops__, SysErr* __Err__);
void __BLOCK__BusyWait(uint64_t __Loops__, SysErr* __Err__);

extern SpinLock ConsoleLock;

KEXPORT(InitializeSpinLock);
KEXPORT(AcquireSpinLock);
KEXPORT(ReleaseSpinLock);
KEXPORT(TryAcquireSpinLock);

KEXPORT(InitializeMutex);
KEXPORT(AcquireMutex);
KEXPORT(ReleaseMutex);
KEXPORT(TryAcquireMutex);

KEXPORT(InitializeSemaphore);
KEXPORT(AcquireSemaphore);
KEXPORT(ReleaseSemaphore);
KEXPORT(TryAcquireSemaphore);
