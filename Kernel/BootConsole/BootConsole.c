#include <BootConsole.h>
#include <Serial.h>
#include <__AXEKCONF__.h>

#ifdef LOGBOOTCONSOLEC_Debug
#    define LOGBOOTCONSOLEC_PDebug(fmt, ...) PDebug("[KERNEL>>BootConsole.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBOOTCONSOLEC_PDebug(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBOOTCONSOLEC_Logs
#    define LOGBOOTCONSOLEC_PError(fmt, ...) PError("[KERNEL>>BootConsole.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBOOTCONSOLEC_PError(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBOOTCONSOLEC_Logs
#    define LOGBOOTCONSOLEC_PWarn(fmt, ...) PWarn("[KERNEL>>BootConsole.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBOOTCONSOLEC_PWarn(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBOOTCONSOLEC_Logs
#    define LOGBOOTCONSOLEC_PInfo(fmt, ...) PInfo("[KERNEL>>BootConsole.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBOOTCONSOLEC_PInfo(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGBOOTCONSOLEC_Logs
#    define LOGBOOTCONSOLEC_PSuccess(fmt, ...)                                                     \
        PSuccess("[KERNEL>>BootConsole.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGBOOTCONSOLEC_PSuccess(fmt, ...)                                                     \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

BootConsole Console = {0};

void
KickStartConsole(uint32_t* __FrameBuffer__, uint32_t __CW__, uint32_t __CH__)
{
    Console.FrameBuffer  = __FrameBuffer__;
    Console.FrameBufferW = __CW__;
    Console.FrameBufferH = __CH__;
    Console.ConsoleCol   = __CW__ / FontW;
    Console.ConsoleRow   = __CH__ / FontH;
    Console.CursorX      = 0;
    Console.CursorY      = 0;
    Console.TXColor      = 0xFFFFFF; /* White text */
    Console.BGColor      = 0x000000; /* Black background */
}

void
ClearConsole(void)
{
    for (uint32_t I = 0; I < Console.FrameBufferW * Console.FrameBufferH; I++)
    {
        Console.FrameBuffer[I] = Console.BGColor;
    }

    Console.CursorX = 0;
    Console.CursorY = 0;
}

void
PutChar(char __Char__)
{
    /* Mirror to COM */
    SerialPutChar(__Char__);

    if (__Char__ == '\n')
    {
        Console.CursorX = 0;
        Console.CursorY++;
    }
    else if (__Char__ == '\r')
    {
        Console.CursorX = 0;
    }
    else
    {
        uint32_t PixelX = Console.CursorX * FontW;
        uint32_t PixelY = Console.CursorY * FontH;
#ifndef OnlyUART
        DisplayChar(
            Console.FrameBuffer, Console.FrameBufferW, PixelX, PixelY, __Char__, Console.TXColor);
        Console.CursorX++;
#endif
    }

    /* Wrap horizontally */
    if (Console.CursorX >= Console.ConsoleCol)
    {
        Console.CursorX = 0;
        Console.CursorY++;
    }

    /* This is way faster then the wrap pix-to-pix copy*/
    if (Console.CursorY >= Console.ConsoleRow)
    {
        ClearConsole();
    }
}

void
PutPrint(const char* __String__)
{
    while (*__String__)
    {
        PutChar(*__String__);
        __String__++;
    }
}

void
SetBGColor(uint32_t __FG__, uint32_t __BG__)
{
    Console.TXColor = __FG__;
    Console.BGColor = __BG__;
}

void
SetCursor(uint32_t __CurX__, uint32_t __CurY__)
{
    if (__CurX__ < Console.ConsoleCol)
    {
        Console.CursorX = __CurX__;
    }
    if (__CurY__ < Console.ConsoleRow)
    {
        Console.CursorY = __CurY__;
    }
}