#pragma once

#include <AllTypes.h>
#include <KExports.h>
#include <KrnFont.h>

typedef struct
{
    uint32_t* FrameBuffer;
    uint32_t  FrameBufferW;
    uint32_t  FrameBufferH;
    uint32_t  ConsoleCol;
    uint32_t  ConsoleRow;
    uint32_t  CursorX;
    uint32_t  CursorY;
    uint32_t  TXColor;
    uint32_t  BGColor;

} BootConsole;

extern BootConsole Console;

void KickStartConsole(uint32_t* __FrameBuffer__, uint32_t __CW__, uint32_t __CH__);
void ClearConsole(void);
void PutChar(char __Char__);
void PutPrint(const char* __String__);
void SetBGColor(uint32_t __FG__, uint32_t __BG__);
void SetCursor(uint32_t __CurX__, uint32_t __CurY__);
void ScrollConsole(void);

KEXPORT(PutChar);