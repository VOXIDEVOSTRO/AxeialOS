#include <BlockDev.h>
#include <Errnos.h>
#include <__AXEKCONF__.h>

#ifdef LOGBLOCKNAMEHELPERSC_Debug
#    define LOGBLOCKNAMEHELPERSC_PDebug(fmt, ...)                                                  \
        PDebug("[KERNEL>>BlockNameHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOCKNAMEHELPERSC_PDebug(fmt, ...)                                                  \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOCKNAMEHELPERSC_Logs
#    define LOGBLOCKNAMEHELPERSC_PError(fmt, ...)                                                  \
        PError("[KERNEL>>BlockNameHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOCKNAMEHELPERSC_PError(fmt, ...)                                                  \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOCKNAMEHELPERSC_Logs
#    define LOGBLOCKNAMEHELPERSC_PWarn(fmt, ...)                                                   \
        PWarn("[KERNEL>>BlockNameHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOCKNAMEHELPERSC_PWarn(fmt, ...)                                                   \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOCKNAMEHELPERSC_Logs
#    define LOGBLOCKNAMEHELPERSC_PInfo(fmt, ...)                                                   \
        PInfo("[KERNEL>>BlockNameHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOCKNAMEHELPERSC_PInfo(fmt, ...)                                                   \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOCKNAMEHELPERSC_Logs
#    define LOGBLOCKNAMEHELPERSC_PSuccess(fmt, ...)                                                \
        PSuccess("[KERNEL>>BlockNameHelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOCKNAMEHELPERSC_PSuccess(fmt, ...)                                                \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
BlockMakeName(char* __Out__, long __Cap__, const char* __Prefix__, long __Index__)
{
    if (Probe_IF_Error(__Out__) || !__Out__ || __Cap__ <= 0 || Probe_IF_Error(__Prefix__) ||
        !__Prefix__)
    {
        PushError("BlockMakeName", LOGBLOCKNAMEHELPERSC_PError, "bad args", -BadArguments);
        return -BadArguments;
    }

    /* sd + 0 -> sda, sd + 1 -> sdb ... */
    char suffix = (char)('a' + (__Index__ % 26));

    long pLen  = (long)StringLength(__Prefix__);
    long total = pLen + 1;
    if (total + 1 > __Cap__)
    {
        PushError(
            "BlockMakeName", LOGBLOCKNAMEHELPERSC_PError, "buffer capacity too small", -Limits);
        return -Limits;
    }

    for (long I = 0; I < pLen; I++)
    {
        __Out__[I] = __Prefix__[I];
    }
    __Out__[pLen]     = suffix;
    __Out__[pLen + 1] = '\0';
    return SysOkay;
}

int
BlockMakePartName(char* __Out__, long __Cap__, const char* __DiskName__, long __PartIndex__)
{
    if (Probe_IF_Error(__Out__) || !__Out__ || __Cap__ <= 0 || Probe_IF_Error(__DiskName__) ||
        !__DiskName__)
    {
        PushError("BlockMakePartName", LOGBLOCKNAMEHELPERSC_PError, "bad args", -BadArguments);
        return -BadArguments;
    }

    /* sda + 1 -> sda1 */
    char num[16] = {0};
    long len     = 0;
    long idx     = __PartIndex__;
    if (idx <= 0)
    {
        idx = 1;
    }

    /* Simple integer to string */
    long t       = idx;
    char tmp[16] = {0};
    long N       = 0;
    while (t > 0)
    {
        tmp[N++] = (char)('0' + (t % 10));
        t /= 10;
    }
    for (long I = 0; I < N; I++)
    {
        num[I] = tmp[N - 1 - I];
    }
    num[N] = '\0';

    long dLen  = (long)StringLength(__DiskName__);
    long nLen  = (long)StringLength(num);
    long total = dLen + nLen;
    if (total + 1 > __Cap__)
    {
        PushError(
            "BlockMakePartName", LOGBLOCKNAMEHELPERSC_PError, "buffer capacity too small", -Limits);
        return -Limits;
    }

    for (long I = 0; I < dLen; I++)
    {
        __Out__[I] = __DiskName__[I];
    }
    for (long I = 0; I < nLen; I++)
    {
        __Out__[dLen + I] = num[I];
    }
    __Out__[total] = '\0';
    return SysOkay;
}