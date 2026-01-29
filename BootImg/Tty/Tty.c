#include <APICTimer.h>
#include <AllTypes.h>
#include <AxeSchd.h>
#include <AxeThreads.h>
#include <BootConsole.h>
#include <BootImg.h>
#include <DevFS.h>
#include <EarlyBootFB.h>
#include <GDT.h>
#include <IDT.h>
#include <KExports.h>
#include <KHeap.h>
#include <KrnPrintf.h>
#include <LimineServices.h>
#include <ModELF.h>
#include <ModMemMgr.h>
#include <PMM.h>
#include <POSIXFd.h>
#include <POSIXProc.h>
#include <POSIXProcFS.h>
#include <POSIXSignals.h>
#include <SMP.h>
#include <Serial.h>
#include <String.h>
#include <SymAP.h>
#include <Sync.h>
#include <Syscall.h>
#include <Timer.h>
#include <VFS.h>
#include <VMM.h>

/* Global errno */
SysErr  err;
SysErr* Error = &err;

typedef struct TtyCtx
{
    char     Name[16];
    uint32_t Fg;
    uint32_t Bg;
    SpinLock Lock;
    SpinLock WriteLock;
} TtyCtx;

static long
TtyWrite(void* __DevCtx__, const void* __Buf__, long __Len__)
{
    TtyCtx* CCtx = (TtyCtx*)__DevCtx__;
    if (!CCtx || !__Buf__ || __Len__ <= 0)
    {
        return -BadArguments;
    }

    const char* Put = (const char*)__Buf__;

    AcquireSpinLock(&CCtx->WriteLock, Error);
    for (long I = 0; I < __Len__; I++)
    {
        char Char = Put[I];
        if (Char == '\n')
        {
            PutChar('\r');
            PutChar('\n');
        }
        else
        {
            PutChar(Char);
        }
    }

    ReleaseSpinLock(&CCtx->WriteLock, Error);

    return __Len__;
}

static long
TtyRead(void* __DevCtx__ _unused, void* __Buf__ _unused, long __Len__ _unused)
{
    return SysOkay;
}

static int
TtyOpen(void* __DevCtx__ _unused)
{
    TtyCtx* CCtx = (TtyCtx*)__DevCtx__;
    if (CCtx)
    {
        atomic_flag_clear_explicit(&CCtx->WriteLock, memory_order_release);
    }
    return SysOkay;
}

static int
TtyClose(void* __DevCtx__ _unused)
{
    return SysOkay;
}

/* Name builder: "tty" + index */
static void
TtyMakeName(char* __Out__, long __Cap__, long __Index__, SysErr* __Err__)
{
    if (!__Out__ || __Cap__ < 4)
    {
        SlotError(__Err__, -BadArguments);
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

    long K = 0;
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
        return -BadArguments;
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
        return SysOkay; /* exists */
    }
    return -NoSuch; /* does not exist */
}

/* Forward */
static int TtyIoctl(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__);

static int
TtyRegister(long __Index__)
{
    TtyCtx* Ctx = KMalloc(sizeof(TtyCtx));
    if (!Ctx)
    {
        return -BadAllocation;
    }
    memset(Ctx, 0, sizeof(TtyCtx));
    TtyMakeName(Ctx->Name, sizeof(Ctx->Name), __Index__, Error);

    atomic_flag_clear_explicit(&Ctx->WriteLock, memory_order_release);

    CharDevOps Ops = (CharDevOps){
        .Open  = TtyOpen,
        .Close = TtyClose,
        .Read  = TtyRead,
        .Write = TtyWrite,
        .Ioctl = TtyIoctl,
    };

    /* Register only if it does NOT exist */
    if (TtyExists(Ctx->Name) == SysOkay)
    {
        int Ret = DevFsRegisterCharDevice(Ctx->Name, 11, __Index__, Ops, Ctx);
        if (Ret != SysOkay)
        {
            KFree(Ctx, Error);
        }

        return SysOkay;
    }
    return -NotRecorded;
}

static int
TtyIoctl(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__)
{
    switch (__Cmd__)
    {
        case 1:
            return TtyRegister((long)(uintptr_t)__Arg__);
        default:
            return -NoSuch;
    }
}

void
InitTty(void)
{
    /* First TTY instance */
    (void)TtyRegister(0);
}

void
module_init(void)
{
    InitTty();
}

int
module_probe(void)
{
    return (TtyExists("tty0") == SysOkay) ? SysOkay : -NoSuch;
}

void
module_exit(void)
{
    /* TODO: optional unregister */
}