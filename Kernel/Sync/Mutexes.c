#include <Errnos.h>
#include <SMP.h>
#include <Sync.h>
#include <__AXEKCONF__.h>

#ifdef LOGMUTEXESC_Debug
#    define LOGMUTEXESC_PDebug(fmt, ...) PDebug("[KERNEL>>Mutexes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMUTEXESC_PDebug(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMUTEXESC_Logs
#    define LOGMUTEXESC_PError(fmt, ...) PError("[KERNEL>>Mutexes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMUTEXESC_PError(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMUTEXESC_Logs
#    define LOGMUTEXESC_PWarn(fmt, ...) PWarn("[KERNEL>>Mutexes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMUTEXESC_PWarn(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMUTEXESC_Logs
#    define LOGMUTEXESC_PInfo(fmt, ...) PInfo("[KERNEL>>Mutexes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMUTEXESC_PInfo(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMUTEXESC_Logs
#    define LOGMUTEXESC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Mutexes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMUTEXESC_PSuccess(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

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
