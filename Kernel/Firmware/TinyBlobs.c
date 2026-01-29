#include <FirmBlobs.h>
#include <__AXEKCONF__.h>

#ifdef LOGTINYBLOBSC_Debug
#    define LOGTINYBLOBSC_PDebug(fmt, ...) PDebug("[KERNEL>>TinyBlobs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTINYBLOBSC_PDebug(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTINYBLOBSC_Logs
#    define LOGTINYBLOBSC_PError(fmt, ...) PError("[KERNEL>>TinyBlobs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTINYBLOBSC_PError(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTINYBLOBSC_Logs
#    define LOGTINYBLOBSC_PWarn(fmt, ...) PWarn("[KERNEL>>TinyBlobs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTINYBLOBSC_PWarn(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTINYBLOBSC_Logs
#    define LOGTINYBLOBSC_PInfo(fmt, ...) PInfo("[KERNEL>>TinyBlobs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTINYBLOBSC_PInfo(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGTINYBLOBSC_Logs
#    define LOGTINYBLOBSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>TinyBlobs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGTINYBLOBSC_PSuccess(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

const unsigned char*
FirmData(const FirmwareHandle* __Handle__)
{
    return __Handle__ ? __Handle__->Blob.Data : Nothing;
}

long
FirmSize(const FirmwareHandle* __Handle__)
{
    return __Handle__ ? __Handle__->Blob.Size : Nothing;
}