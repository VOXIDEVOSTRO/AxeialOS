#pragma once

#include <AllTypes.h>
#include <BootConsole.h>
#include <KExports.h>
/*For Spinlocks*/
#include <Errnos.h>
#include <Sync.h>
#include <__AXEKCONF__.h>

typedef struct
{
    const char* Format;
    void**      Args;
    int         ArgIndex;

} PrintfState;

typedef struct
{
    int LeftAlign;
    int ShowSign;
    int SpacePrefix;
    int AlternateForm;
    int ZeroPad;
    int Width;
    int Precision;
    int HasPrecision;
    int Length;

} FormatFlags;

#define ClrNormal    0xFFFFFF
#define ClrInvisible 0x000000
#define ClrError     0xFF0000
#define ClrSuccess   0x00FF00
#define ClrBlue      0x0000FF
#define ClrWarn      0xFFFF00
#define ClrInfo      0x00FFFF
#define ClrMagnet    0xFF00FF
#define ClrTang      0xFF8000
#define ClrDebug     0x808080

#ifdef DEBUG
#    define PDebug(fmt, ...) _PDebug(fmt, ##__VA_ARGS__)
#else
#    define PDebug(fmt, ...)                                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifndef AllErrors
/*Independent error reporter with cause and returned or returning error code, very useful*/
#    define PushError(Func, CallLogger, ErrorMsg, RetErrCode)                                      \
        do                                                                                         \
        {                                                                                          \
            CallLogger(                                                                            \
                "[traceback: %s] %s, errno: %s\n", (Func), (ErrorMsg), ErrName(RetErrCode));       \
        } while (0)
#else
/*Independent error reporter with cause and returned or returning error code, very useful*/
#    define PushError(Func, CallLogger, ErrorMsg, RetErrCode)                                      \
        do                                                                                         \
        {                                                                                          \
            PError("[traceback: %s] %s, errno: %s\n", (Func), (ErrorMsg), ErrName(RetErrCode));    \
        } while (0)
#endif

/*Main*/
void KrnPrintf(const char* __Format__, ...);
void KrnPrintfColor(uint32_t __FG__, uint32_t __BG__, const char* __Format__, ...);
void ProcessFormatSpecifier(const char** __Format__, __builtin_va_list* __Args__);

/*Helpers*/
void PrintInteger(int __Value__, int __Base__, int __Uppercase__);
void PrintUnsigned(uint32_t __Value__, int __Base__, int __Uppercase__);
void PrintString(const char* __String__);
void PrintChar(char __Char__);
void PrintPointer(void* __Pointer__);
int  StringLength(const char* __String__);
void ReverseString(char* __String__, int __Length__);
void IntegerToString(int __Value__, char* __Buffer__, int __Base__);
void UnsignedToString(uint32_t __Value__, char* __Buffer__, int __Base__);
void
ProcessInteger(__builtin_va_list* __Args__, FormatFlags* __Flags__, int __Base__, int __Signed__);
void ProcessString(__builtin_va_list* __Args__, FormatFlags* __Flags__);
void ProcessChar(__builtin_va_list* __Args__, FormatFlags* __Flags__);
void ProcessPointer(__builtin_va_list* __Args__, FormatFlags* __Flags__);
void FormatOutput(const char* __Buffer__, FormatFlags* __Flags__, int __IsNegative__, int __Base__);
void UnsignedToStringEx(uint64_t __Value__, char* __Buffer__, int __Base__, int __Uppercase__);

/*Logging*/
void PError(const char* __Format__, ...);
void PWarn(const char* __Format__, ...);
void PInfo(const char* __Format__, ...);
void _PDebug(const char* __Format__, ...);
void PSuccess(const char* __Format__, ...);

/*Exports*/
KEXPORT(KrnPrintf)
KEXPORT(KrnPrintfColor)
KEXPORT(PError)
KEXPORT(PWarn)
KEXPORT(PInfo)
KEXPORT(PSuccess)
KEXPORT(_PDebug)
