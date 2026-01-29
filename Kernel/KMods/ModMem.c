#include <ModMemMgr.h>
#include <__AXEKCONF__.h>

#ifdef LOGMODMEMC_Debug
#    define LOGMODMEMC_PDebug(fmt, ...) PDebug("[KERNEL>>ModMem.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMEMC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMEMC_Logs
#    define LOGMODMEMC_PError(fmt, ...) PError("[KERNEL>>ModMem.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMEMC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMEMC_Logs
#    define LOGMODMEMC_PWarn(fmt, ...) PWarn("[KERNEL>>ModMem.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMEMC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMEMC_Logs
#    define LOGMODMEMC_PInfo(fmt, ...) PInfo("[KERNEL>>ModMem.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMEMC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMEMC_Logs
#    define LOGMODMEMC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ModMem.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMEMC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

ModuleMemoryManager ModMem = {0, 0, 0};

/*

    'ModMemMgr' has been deprecated (Partially) as a more optimized and faster allocation through
    direct PMM and VMM

*/

void
ModMemInit(SysErr* __Err__)
{
    ModMem.TextCursor  = 0;
    ModMem.DataCursor  = 0;
    ModMem.Initialized = 1;

    LOGMODMEMC_PDebug("[Text=%#llx..%#llx Data=%#llx..%#llx\n",
                      (unsigned long long)ModTextBase,
                      (unsigned long long)(ModTextBase + ModTextSize - 1),
                      (unsigned long long)ModDataBase,
                      (unsigned long long)(ModDataBase + ModDataSize - 1));
}