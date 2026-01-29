#include <FirmBlobs.h>
#include <KrnPrintf.h>
#include <__AXEKCONF__.h>

#ifdef LOGBLOBPATHRESC_Debug
#    define LOGBLOBPATHRESC_PDebug(fmt, ...) PDebug("[KERNEL>>BlobPathRes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBPATHRESC_PDebug(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBPATHRESC_Logs
#    define LOGBLOBPATHRESC_PError(fmt, ...) PError("[KERNEL>>BlobPathRes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBPATHRESC_PError(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBPATHRESC_Logs
#    define LOGBLOBPATHRESC_PWarn(fmt, ...) PWarn("[KERNEL>>BlobPathRes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBPATHRESC_PWarn(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBPATHRESC_Logs
#    define LOGBLOBPATHRESC_PInfo(fmt, ...) PInfo("[KERNEL>>BlobPathRes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBPATHRESC_PInfo(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBPATHRESC_Logs
#    define LOGBLOBPATHRESC_PSuccess(fmt, ...)                                                     \
        PSuccess("[KERNEL>>BlobPathRes.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBPATHRESC_PSuccess(fmt, ...)                                                     \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/* Resolve descriptor to absolute path */
int
FirmResolvePath(const FirmwareDesc* __Desc__, char* __OutPath__, long __OutLen__)
{
    if (Probe_IF_Error(__Desc__) || !__Desc__ || Probe_IF_Error(__Desc__->Name) ||
        !__Desc__->Name || Probe_IF_Error(__OutPath__) || !__OutPath__ || __OutLen__ <= 0)
    {
        PushError("FirmResolvePath",
                  LOGBLOBPATHRESC_PError,
                  "bad arguments to FirmResolvePath",
                  -BadArguments);
        return -BadArguments;
    }

    const char* Prefix = 0;
    switch (__Desc__->Origin)
    {
        case FirmOriginBootImg:
            {
                Prefix = FirmInitramfsPrefix;
                break;
            }
        case FirmOriginRootFS:
            {
                Prefix = FirmRootfsPrefix;
                break;
            }
        default:
            {
                PushError("FirmResolvePath",
                          LOGBLOBPATHRESC_PError,
                          "unhandled firmware origin",
                          -NotCanonical);
                return -NotCanonical;
            }
    }

    char TMPBuff[512];
    if (VfsJoinPath(Prefix, __Desc__->Name, TMPBuff, (long)sizeof(TMPBuff)) != SysOkay)
    {
        PushError("FirmResolvePath",
                  LOGBLOBPATHRESC_PError,
                  "cannot join path for firmware blob",
                  -NotCanonical);
        return -NotCanonical;
    }

    if (VfsRealpath(TMPBuff, __OutPath__, __OutLen__) != SysOkay)
    {
        PushError("FirmResolvePath",
                  LOGBLOBPATHRESC_PError,
                  "cannot resolve real path for firmware blob",
                  -NotCanonical);
        return -NotCanonical;
    }

    return SysOkay;
}
