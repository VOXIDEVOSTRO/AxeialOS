#include <Dev.h>
#include <Heaps.h>
#include <Logings.h>
#include <StrHelp.h>
#include <SyncSys.h>
#include <Vfs.h>

/*Super Simple TTY Application, Just writes to EarlyBootConsole*/

typedef struct TtyCtx
{
    char     Name[16];
    uint32_t Fg;
    uint32_t Bg;
    SpinLock Lock;
} TtyCtx;

static long
TtyWrite(void* __DevCtx__, const void* __Buf__, long __Len__)
{
    TtyCtx* CCtx = (TtyCtx*)__DevCtx__;
    if (!CCtx || !__Buf__ || __Len__ <= 0)
    {
        return 0;
    }
    const char* Put = (const char*)__Buf__;
    for (long Idx = 0; Idx < __Len__; Idx++)
    {
        PutChar(Put[Idx]);
    }
    return __Len__;
}

static long
TtyRead(void* __DevCtx__, void* __Buf__, long __Len__)
{
    (void)__DevCtx__;
    (void)__Buf__;
    (void)__Len__;
    return 0;
}

static int
TtyOpen(void* __DevCtx__)
{
    (void)__DevCtx__;
    return 0;
}

static int
TtyClose(void* __DevCtx__)
{
    (void)__DevCtx__;
    return 0;
}

static void
TtyMakeName(char* __Out__, long __Cap__, long __Index__)
{
    if (!__Out__ || __Cap__ < 4)
    {
        return;
    }
    __Out__[0] = 't';
    __Out__[1] = 't';
    __Out__[2] = 'y';
    long Pos   = 3;
    char NumBuf[32];
    long I = 0;
    long V = __Index__;
    if (V == 0)
    {
        NumBuf[I++] = '0';
    }
    else
    {
        char Tmp[32];
        long J = 0;
        while (V > 0 && J < 32)
        {
            Tmp[J++] = (char)('0' + (V % 10));
            V /= 10;
        }
        while (J > 0)
        {
            NumBuf[I++] = Tmp[--J];
        }
    }
    NumBuf[I] = '\0';
    long K    = 0;
    while (NumBuf[K] && Pos < __Cap__ - 1)
    {
        __Out__[Pos++] = NumBuf[K++];
    }
    __Out__[Pos] = '\0';
}

static int
TtyExists(const char* __Name__)
{
    if (!__Name__)
    {
        return 0;
    }
    char Path[64];
    Path[0] = '/';
    Path[1] = 'd';
    Path[2] = 'e';
    Path[3] = 'v';
    Path[4] = '/';
    long I  = 0;
    while (__Name__[I] && (5 + I) < (long)sizeof(Path) - 1)
    {
        Path[5 + I] = __Name__[I];
        I++;
    }
    Path[5 + I] = '\0';

    File* F = VfsOpen(Path, VFlgRDONLY);
    if (F)
    {
        VfsClose(F);
        return 1;
    }
    return 0;
}

/*Foward*/
static int TtyIoctl(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__);

static int
TtyRegister(long __Index__)
{
    TtyCtx* Ctx = KMalloc(sizeof(TtyCtx));
    if (!Ctx)
    {
        return -1;
    }
    memset(Ctx, 0, sizeof(TtyCtx));
    TtyMakeName(Ctx->Name, sizeof(Ctx->Name), __Index__);

    CharDevOps Ops = {
        .Open  = TtyOpen,
        .Close = TtyClose,
        .Read  = TtyRead,
        .Write = TtyWrite,
        .Ioctl = TtyIoctl,
    };

    if (TtyExists(Ctx->Name))
    {
        KFree(Ctx);
        return -1;
    }

    int Ret = DevFsRegisterCharDevice(Ctx->Name, 11, __Index__, Ops, Ctx);
    if (Ret == 0)
    {
        PSuccess("[INFO]: tty registered at %s\n", Ctx->Name);
    }
    else
    {
        PError("[ERROR]: tty registration failed (Ret=%d)\n", Ret);
        KFree(Ctx);
    }
    return Ret;
}

static int
TtyIoctl(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__)
{
    (void)__DevCtx__;
    switch (__Cmd__)
    {
        case 1:
            return TtyRegister((long)(uintptr_t)__Arg__);
        default:
            return -1;
    }
}

void
InitTty(void)
{
    TtyRegister(0);
}

int
module_init(void)
{
    InitTty();
    return 0;
}

int
module_exit(void)
{
    /*Nothing to clean up*/
    return 0;
}