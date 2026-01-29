
#include <BootImg.h>
#include <RamFs.h>
#include <String.h>
#include <VFS.h>
#include <__AXEKCONF__.h>

#ifdef LOGPARSEIMAGEC_Debug
#    define LOGPARSEIMAGEC_PDebug(fmt, ...) PDebug("[KERNEL>>ParseImage.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARSEIMAGEC_PDebug(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARSEIMAGEC_Logs
#    define LOGPARSEIMAGEC_PError(fmt, ...) PError("[KERNEL>>ParseImage.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARSEIMAGEC_PError(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARSEIMAGEC_Logs
#    define LOGPARSEIMAGEC_PWarn(fmt, ...) PWarn("[KERNEL>>ParseImage.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARSEIMAGEC_PWarn(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARSEIMAGEC_Logs
#    define LOGPARSEIMAGEC_PInfo(fmt, ...) PInfo("[KERNEL>>ParseImage.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARSEIMAGEC_PInfo(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGPARSEIMAGEC_Logs
#    define LOGPARSEIMAGEC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ParseImage.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGPARSEIMAGEC_PSuccess(fmt, ...)                                                      \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

int
InitializeBootImage(void)
{
    if (!LimineMod.response || LimineMod.response->module_count == 0)
    {
        PushError("InitializeBootImage",
                  LOGPARSEIMAGEC_PError,
                  "failed to request module from limine",
                  -Missing);
        return -Missing;
    }

    for (uint64_t I = 0; I < LimineMod.response->module_count; I++)
    {
        struct limine_file* Mod = LimineMod.response->modules[I];
        if (Probe_IF_Error(Mod) || !Mod || Probe_IF_Error(Mod->path) || !Mod->path)
        {
            continue;
        }

        if (strcmp(Mod->path, "/BootImg.img") == 0)
        {
            LOGPARSEIMAGEC_PDebug(
                "Found BootImg.img at %p, size %llu bytes\n", Mod->address, Mod->size);

            /* Hand off to VFS */
            return BootMountRamFs(Mod->address, Mod->size);
        }
    }

    PushError("InitializeBootImage", LOGPARSEIMAGEC_PError, "failed to find BootImg.img", -NoSuch);
    return -NoSuch;
}
