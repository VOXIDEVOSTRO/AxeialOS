
#include <BlockDev.h>
#include <__AXEKCONF__.h>

#ifdef LOGPARTC_Debug
#    define LOGPARTC_PDebug(fmt, ...) PDebug("[KERNEL>>Part.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARTC_PDebug(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARTC_Logs
#    define LOGPARTC_PError(fmt, ...) PError("[KERNEL>>Part.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARTC_PError(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARTC_Logs
#    define LOGPARTC_PWarn(fmt, ...) PWarn("[KERNEL>>Part.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARTC_PWarn(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARTC_Logs
#    define LOGPARTC_PInfo(fmt, ...) PInfo("[KERNEL>>Part.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARTC_PInfo(fmt, ...)                                                               \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARTC_Logs
#    define LOGPARTC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Part.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARTC_PSuccess(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
BlockRegisterGPTPartitions(BlockDisk*  __Disk__,
                           const void* __GptHeader__,
                           const void* __GptEntries__,
                           long        __EntryCount__)
{

    /*TODO*/

    return SysOkay;
}

int
BlockRegisterMBRPartitions(BlockDisk* __Disk__, const void* __MbrSector__)
{

    /*TODO*/

    return SysOkay;
}