#include <AllTypes.h>
#include <FirmBlobs.h>
#include <KHeap.h>
#include <String.h>
#include <VFS.h>
#include <__AXEKCONF__.h>

#ifdef LOGBLOBOPSC_Debug
#    define LOGBLOBOPSC_PDebug(fmt, ...) PDebug("[KERNEL>>BlobOps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBOPSC_PDebug(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBOPSC_Logs
#    define LOGBLOBOPSC_PError(fmt, ...) PError("[KERNEL>>BlobOps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBOPSC_PError(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBOPSC_Logs
#    define LOGBLOBOPSC_PWarn(fmt, ...) PWarn("[KERNEL>>BlobOps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBOPSC_PWarn(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBOPSC_Logs
#    define LOGBLOBOPSC_PInfo(fmt, ...) PInfo("[KERNEL>>BlobOps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBOPSC_PInfo(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBLOBOPSC_Logs
#    define LOGBLOBOPSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>BlobOps.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBLOBOPSC_PSuccess(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/* Request firmware blob */
int
FirmRequest(FirmwareHandle**    __OutHandle__,
            const FirmwareDesc* __Desc__,
            const DeviceEntry*  __Dev__)
{
    if (Probe_IF_Error(__OutHandle__) || !__OutHandle__ || Probe_IF_Error(__Desc__) || !__Desc__)
    {
        PushError("FirmRequest", LOGBLOBOPSC_PError, "bad arguments to FirmRequest", -BadArguments);
        return -BadArguments;
    }

    SysErr  err;
    SysErr* Error = &err;

    FirmwareHandle* H = (FirmwareHandle*)KMalloc(sizeof(FirmwareHandle));
    if (Probe_IF_Error(H) || !H)
    {
        PushError("FirmRequest",
                  LOGBLOBOPSC_PError,
                  "can't allocate memory for handle",
                  Pointer_TO_Error(H));
        return -BadAllocation;
    }
    memset(H, 0, sizeof(FirmwareHandle));
    H->Desc        = *__Desc__;
    H->Dev         = __Dev__;
    *__OutHandle__ = H;

    char PathBuf[512];
    if (FirmResolvePath(__Desc__, PathBuf, (long)sizeof(PathBuf)) != SysOkay)
    {
        KFree(H, Error);
        *__OutHandle__ = 0;
        PushError("FirmRequest", LOGBLOBOPSC_PError, "cannot resolve path", -NotCanonical);
        return -NotCanonical;
    }

    File* F = VfsOpen(PathBuf, VFlgRDONLY);
    if (Probe_IF_Error(F) || !F)
    {
        KFree(H, Error);
        *__OutHandle__ = 0;
        PushError("FirmRequest", LOGBLOBOPSC_PError, "cannot open firmware file", -NoSuch);
        return -NoSuch;
    }

    VfsStat St;
    if (VfsFstats(F, &St) != SysOkay || St.Size <= 0)
    {
        VfsClose(F);
        KFree(H, Error);
        *__OutHandle__ = 0;
        PushError("FirmRequest", LOGBLOBOPSC_PError, "file size is bad", -Limits);
        return -Limits;
    }

    unsigned char* Buf = (unsigned char*)KMalloc((size_t)St.Size);
    if (Probe_IF_Error(Buf) || !Buf)
    {
        VfsClose(F);
        KFree(H, Error);
        *__OutHandle__ = 0;
        PushError("FirmRequest",
                  LOGBLOBOPSC_PError,
                  "cannot allocate memory for blob",
                  Pointer_TO_Error(Buf));
        return -BadAllocation;
    }

    long Read   = 0;
    int  RcRead = VfsReadAll(PathBuf, Buf, St.Size, &Read);
    VfsClose(F);

    if (RcRead != 0 || Read != St.Size)
    {
        KFree(Buf, Error);
        KFree(H, Error);
        *__OutHandle__ = 0;
        PushError("FirmRequest", LOGBLOBOPSC_PError, "cannot read firmware file", -BadRead);
        return -BadRead;
    }

    H->Blob.Data = Buf;
    H->Blob.Size = Read;

    LOGBLOBOPSC_PSuccess("Loaded firmware module '%s' size=%ld\n", PathBuf, Read);
    return SysOkay;
}

int
FirmRelease(FirmwareHandle* __Handle__)
{
    SysErr  err;
    SysErr* Error = &err;
    if (Probe_IF_Error(__Handle__) || !__Handle__)
    {
        return SysOkay; /*already released*/
    }
    if (__Handle__->Blob.Data)
    {
        KFree((void*)__Handle__->Blob.Data, Error);
    }
    KFree(__Handle__, Error);
    return SysOkay;
}