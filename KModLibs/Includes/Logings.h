#pragma once

#include <EveryType.h>

#define DEBUG

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

/*Main*/
void KrnPrintf(const char* __Format__, ...);
void KrnPrintfColor(uint32_t __FG__, uint32_t __BG__, const char* __Format__, ...);

/*Logging*/
void PError(const char* __Format__, ...);
void PWarn(const char* __Format__, ...);
void PInfo(const char* __Format__, ...);
void _PDebug(const char* __Format__, ...);
void PSuccess(const char* __Format__, ...);

/*Console*/
void PutChar(char __Char__);