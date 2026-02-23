
#include <Errnos.h>
#include <KrnPrintf.h>

void
PError(const char* __Format__, ...)
{
    if (Probe_IF_Error(__Format__) || !__Format__)
    {
        __Format__ = "(null)";
    }
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    // TODO: Rename the uint's.
    uint32_t MainFG = Console.TXColor;
    uint32_t MainBG = Console.BGColor;

    PutPrint("[");
    SetBGColor(ClrError, ClrInvisible);
    PutPrint("    ERROR    ");
    SetBGColor(ClrNormal, ClrInvisible);
    PutPrint("]: ");

    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    SetBGColor(MainFG, MainBG);
    ReleaseSpinLock(&ConsoleLock, Error);
}

void
PWarn(const char* __Format__, ...)
{
    if (Probe_IF_Error(__Format__) || !__Format__)
    {
        __Format__ = "(null)";
    }
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    uint32_t MainFG = Console.TXColor;
    uint32_t MainBG = Console.BGColor;

    PutPrint("[");
    SetBGColor(ClrWarn, ClrInvisible);
    PutPrint("   WARNING   ");
    SetBGColor(ClrNormal, ClrInvisible);
    PutPrint("]: ");

    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    SetBGColor(MainFG, MainBG);
    ReleaseSpinLock(&ConsoleLock, Error);
}

void
PInfo(const char* __Format__, ...)
{
    if (Probe_IF_Error(__Format__) || !__Format__)
    {
        __Format__ = "(null)";
    }
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    uint32_t MainFG = Console.TXColor;
    uint32_t MainBG = Console.BGColor;

    PutPrint("[");
    SetBGColor(ClrInfo, ClrInvisible);
    PutPrint(" INFORMATION ");
    SetBGColor(ClrNormal, ClrInvisible);
    PutPrint("]: ");

    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    SetBGColor(MainFG, MainBG);
    ReleaseSpinLock(&ConsoleLock, Error);
}

void
_PDebug(const char* __Format__, ...)
{
    if (Probe_IF_Error(__Format__) || !__Format__)
    {
        __Format__ = "(null)";
    }
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    uint32_t MainFG = Console.TXColor;
    uint32_t MainBG = Console.BGColor;

    SetBGColor(ClrDebug, ClrInvisible);
    PutPrint("[    DEBUG    ]: ");

    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    SetBGColor(MainFG, MainBG);
    ReleaseSpinLock(&ConsoleLock, Error);
}

void
PSuccess(const char* __Format__, ...)
{
    if (Probe_IF_Error(__Format__) || !__Format__)
    {
        __Format__ = "(null)";
    }
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    uint32_t MainFG = Console.TXColor;
    uint32_t MainBG = Console.BGColor;

    PutPrint("[");
    SetBGColor(ClrSuccess, ClrInvisible);
    PutPrint("   SUCCESS   ");
    SetBGColor(ClrNormal, ClrInvisible);
    PutPrint("]: ");

    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    SetBGColor(MainFG, MainBG);
    ReleaseSpinLock(&ConsoleLock, Error);
}
