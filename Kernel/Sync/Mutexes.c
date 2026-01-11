#include <Errnos.h>
#include <SMP.h>
#include <Sync.h>

#define KernelValue 0xFFFFFFFF

void
InitializeMutex(Mutex* __Mutex__, const char* __Name__, SysErr* __Err__)
{
    __Mutex__->Lock           = 0;           /* Initially unlocked */
    __Mutex__->Owner          = KernelValue; /* No owner (kernel value) */
    __Mutex__->RecursionCount = 0;           /* No recursive locks */
    __Mutex__->Name           = __Name__;    /* Assign name for debugging */
}

void
AcquireMutex(Mutex* __Mutex__, SysErr* __Err__)
{
    uint32_t CpuId = GetCurrentCpuId();

    if (__Mutex__->Owner == CpuId)
    {
        __Mutex__->RecursionCount++;
        SlotError(__Err__, -Recursion);
        return;
    }

    while (1)
    {
        uint32_t Expected = 0; /* Expect the lock to be free (0) */
        if (__atomic_compare_exchange_n(
                &__Mutex__->Lock, &Expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        {
            /* Successfully acquired the lock */
            __Mutex__->Owner          = CpuId;
            __Mutex__->RecursionCount = 1;
            break;
        }

        /* Lock is held by another CPU, spin with pause for efficiency */
        __asm__ volatile("pause");
    }
}

void
ReleaseMutex(Mutex* __Mutex__, SysErr* __Err__)
{
    uint32_t CpuId = GetCurrentCpuId();

    if (__Mutex__->Owner != CpuId)
    {
        SlotError(__Err__, -BadEntity);
        return;
    }

    __Mutex__->RecursionCount--;

    if (__Mutex__->RecursionCount == 0)
    {
        __Mutex__->Owner = KernelValue;                          /* Reset owner to kernel/none */
        __atomic_store_n(&__Mutex__->Lock, 0, __ATOMIC_RELEASE); /* Unlock atomically */
    }
}

bool
TryAcquireMutex(Mutex* __Mutex__)
{
    uint32_t CpuId = GetCurrentCpuId();

    if (__Mutex__->Owner == CpuId)
    {
        __Mutex__->RecursionCount++;
        return true;
    }

    uint32_t Expected = 0;
    if (__atomic_compare_exchange_n(
            &__Mutex__->Lock, &Expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
        /* Successfully acquired */
        __Mutex__->Owner          = CpuId;
        __Mutex__->RecursionCount = 1;
        return true;
    }

    /* Failed to acquire */
    return false;
}
