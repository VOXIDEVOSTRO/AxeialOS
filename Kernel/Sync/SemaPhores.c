#include <Errnos.h>
#include <SMP.h>
#include <Sync.h>
#include <__AXEKCONF__.h>

#ifdef LOGSEMAPHORESC_Debug
#    define LOGSEMAPHORESC_PDebug(fmt, ...) PDebug("[KERNEL>>SemaPhores.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSEMAPHORESC_PDebug(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSEMAPHORESC_Logs
#    define LOGSEMAPHORESC_PError(fmt, ...) PError("[KERNEL>>SemaPhores.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSEMAPHORESC_PError(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSEMAPHORESC_Logs
#    define LOGSEMAPHORESC_PWarn(fmt, ...) PWarn("[KERNEL>>SemaPhores.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSEMAPHORESC_PWarn(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSEMAPHORESC_Logs
#    define LOGSEMAPHORESC_PInfo(fmt, ...) PInfo("[KERNEL>>SemaPhores.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSEMAPHORESC_PInfo(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGSEMAPHORESC_Logs
#    define LOGSEMAPHORESC_PSuccess(fmt, ...) PSuccess("[KERNEL>>SemaPhores.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGSEMAPHORESC_PSuccess(fmt, ...)                                                      \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
InitializeSemaphore(Semaphore*  __Semaphore__,
                    int32_t     __InitialCount__,
                    const char* __Name__,
                    SysErr*     __Err__)
{
    __Semaphore__->Count     = __InitialCount__; /* Set initial count */
    __Semaphore__->WaitQueue = 0;                /* No waiting threads initially */
    InitializeSpinLock(
        &__Semaphore__->QueueLock, "SemaphoreQueue", __Err__); /* Initialize queue lock */
    __Semaphore__->Name = __Name__;                            /* Assign name for debugging */
}

void
AcquireSemaphore(Semaphore* __Semaphore__, SysErr* __Err__ _unused)
{
    while (1)
    {
        int32_t CurrentCount = __atomic_load_n(&__Semaphore__->Count, __ATOMIC_ACQUIRE);

        if (CurrentCount > 0)
        {
            if (__atomic_compare_exchange_n(&__Semaphore__->Count,
                                            &CurrentCount,
                                            CurrentCount - 1,
                                            false,
                                            __ATOMIC_ACQUIRE,
                                            __ATOMIC_RELAXED))
            {
                break; /* Successfully acquired */
            }
            /* Compare-exchange failed, retry */
        }
        /* Spin */
        __asm__ volatile("pause");
    }
}

void
ReleaseSemaphore(Semaphore* __Semaphore__, SysErr* __Err__ _unused)
{
    __atomic_fetch_add(&__Semaphore__->Count, 1, __ATOMIC_RELEASE);
}

bool
TryAcquireSemaphore(Semaphore* __Semaphore__)
{
    int32_t CurrentCount = __atomic_load_n(&__Semaphore__->Count, __ATOMIC_ACQUIRE);

    if (CurrentCount > 0)
    {
        if (__atomic_compare_exchange_n(&__Semaphore__->Count,
                                        &CurrentCount,
                                        CurrentCount - 1,
                                        false,
                                        __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED))
        {
            return true; /* Successfully acquired */
        }
    }

    /* Count is zero or compare-exchange failed */
    return false;
}
