#include <AllTypes.h>
#include <KHeap.h>
#include <KMods.h>
#include <KrnPrintf.h>
#include <ModMemMgr.h>
#include <String.h>
#include <VFS.h>
#include <__AXEKCONF__.h>

#ifdef LOGMODMGRC_Debug
#    define LOGMODMGRC_PDebug(fmt, ...) PDebug("[KERNEL>>ModMgr.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMGRC_PDebug(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMGRC_Logs
#    define LOGMODMGRC_PError(fmt, ...) PError("[KERNEL>>ModMgr.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMGRC_PError(fmt, ...)                                                            \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMGRC_Logs
#    define LOGMODMGRC_PWarn(fmt, ...) PWarn("[KERNEL>>ModMgr.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMGRC_PWarn(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMGRC_Logs
#    define LOGMODMGRC_PInfo(fmt, ...) PInfo("[KERNEL>>ModMgr.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMGRC_PInfo(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMODMGRC_Logs
#    define LOGMODMGRC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ModMgr.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMODMGRC_PSuccess(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*Globals*/
ModuleRecord* ModuleListHead = 0;

int
ModuleRegistryInit(void)
{
    ModuleListHead = ModuleListHead;
    return SysOkay;
}

int
ModuleRegistryAdd(ModuleRecord* __Rec__)
{
    if (Probe_IF_Error(__Rec__) || !__Rec__)
    {
        PushError("ModuleRegistryAdd",
                  LOGMODMGRC_PError,
                  "bad argument in ModuleRegistryAdd",
                  -BadArguments);
        return -BadArguments;
    }

    __Rec__->Next  = ModuleListHead;
    ModuleListHead = __Rec__;
    return SysOkay;
}

ModuleRecord*
ModuleRegistryFind(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("ModuleRegistryFind",
                  LOGMODMGRC_PError,
                  "bad argument in ModuleRegistryFind",
                  -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    ModuleRecord* It = ModuleListHead;
    while (It)
    {
        if (It->Name && strcmp(It->Name, __Name__) == 0)
        {
            return It;
        }
        It = It->Next;
    }

    PushError(
        "ModuleRegistryFind", LOGMODMGRC_PError, "module not found in ModuleRegistryFind", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

int
ModuleRegistryRemove(ModuleRecord* __Rec__)
{
    if (Probe_IF_Error(__Rec__) || !__Rec__)
    {
        PushError("ModuleRegistryRemove",
                  LOGMODMGRC_PError,
                  "bad argument in ModuleRegistryRemove",
                  -BadArguments);
        return -BadArguments;
    }

    ModuleRecord* Prev = 0;
    ModuleRecord* It   = ModuleListHead;
    while (It)
    {
        if (It == __Rec__)
        {
            if (Prev)
            {
                Prev->Next = It->Next;
            }
            else
            {
                ModuleListHead = It->Next;
            }
            return SysOkay;
        }
        Prev = It;
        It   = It->Next;
    }
    PushError("ModuleRegistryRemove",
              LOGMODMGRC_PError,
              "module not found in ModuleRegistryRemove",
              -NoSuch);
    return -NoSuch;
}
