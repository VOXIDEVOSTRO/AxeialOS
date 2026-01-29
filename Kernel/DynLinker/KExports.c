#include <Errnos.h>
#include <KExports.h>
#include <KrnPrintf.h>
#include <String.h>
#include <__AXEKCONF__.h>

#ifdef LOGKEXPORTSC_Debug
#    define LOGKEXPORTSC_PDebug(fmt, ...) PDebug("[KERNEL>>KExports.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKEXPORTSC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKEXPORTSC_Logs
#    define LOGKEXPORTSC_PError(fmt, ...) PError("[KERNEL>>KExports.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKEXPORTSC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKEXPORTSC_Logs
#    define LOGKEXPORTSC_PWarn(fmt, ...) PWarn("[KERNEL>>KExports.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKEXPORTSC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKEXPORTSC_Logs
#    define LOGKEXPORTSC_PInfo(fmt, ...) PInfo("[KERNEL>>KExports.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKEXPORTSC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKEXPORTSC_Logs
#    define LOGKEXPORTSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>KExports.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKEXPORTSC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void*
KexpLookup(const char* __Name__)
{
    if (Probe_IF_Error(__Name__) || !__Name__)
    {
        PushError("KexpLookup", LOGKEXPORTSC_PError, "bad arguments to KexpLookup", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    /* Iterate */
    const KExport* Cur = __start_kexports;
    const KExport* End = __stop_kexports;

    while (Cur < End)
    {
        if (Cur->Name && strcmp(Cur->Name, __Name__) == 0)
        {
            return Cur->Addr;
        }

        Cur++;
    }

    /* Symbol not found */
    PushError("KexpLookup", LOGKEXPORTSC_PError, "no such export", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}

void
KexpDump(SysErr* __Err__ _unused)
{
    const KExport* Cur = __start_kexports;
    const KExport* End = __stop_kexports;

    LOGKEXPORTSC_PInfo("Listing all kernel exports:\n");

    /* Iterate */
    while (Cur < End)
    {
        KrnPrintf("  %s => %p\n", Cur->Name, Cur->Addr);
        Cur++;
    }
}
