#include "KrnCommon.h"
#include <Errnos.h>
#include <__AXEKCONF__.h>

/*bloated?*/

#ifdef LOGENTRYC_Debug
#    define LOGENTRYC_PDebug(fmt, ...) PDebug("[KERNEL>>Entry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGENTRYC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGENTRYC_Logs
#    define LOGENTRYC_PError(fmt, ...) PError("[KERNEL>>Entry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGENTRYC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGENTRYC_Logs
#    define LOGENTRYC_PWarn(fmt, ...) PWarn("[KERNEL>>Entry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGENTRYC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGENTRYC_Logs
#    define LOGENTRYC_PInfo(fmt, ...) PInfo("[KERNEL>>Entry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGENTRYC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGENTRYC_Logs
#    define LOGENTRYC_PSuccess(fmt, ...) PSuccess("[KERNEL>>Entry.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGENTRYC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

SpinLock TestLock;
bool     InitComplete = false;

void
Idler(void* __Argument__)
{
    SysErr  err;
    SysErr* Error = &err;

    for (;;)
    {
        ThreadYield(Error);
    }
}

/*Worker*/
void
KernelWorkerThread(void* __Argument__)
{
    SysErr  err;
    SysErr* Error = &err;

    LOGENTRYC_PInfo(
        "Kernel Worker started on CPU %u\n",
        GetCurrentCpuId()); /*Will start on BSP anyway, it's the only kernel worker on CPU 0*/

    /*Idler*/
    LOGENTRYC_PInfo("KickStarting Idler...\n");
    Thread* T = CreateThread(ThreadTypeKernel, Idler, NULL, ThreadPriorityIdle);
    ThreadExecute(T, Error); /*For balancing*/
    LOGENTRYC_PSuccess("Idler OK.\n");

    /*Modules*/
    LOGENTRYC_PInfo("KickStarting ModMem Mgr...\n");
    ModMemInit(Error);
    LOGENTRYC_PSuccess("ModMem Mgr OK.\n");

    LOGENTRYC_PInfo("KickStarting RamDisk...\n");
    InitializeBootImage();
    LOGENTRYC_PSuccess("RamDisk OK.\n");

    /*Udev/Devfs*/
    LOGENTRYC_PInfo("KickStarting Udev/Devfs...\n");
    DevFsInit();
    Superblock* SuperBlk = DevFsMountImpl(Nothing, Nothing);

    if (Probe_IF_Error(SuperBlk))
    {
        InitComplete = false;
        LOGENTRYC_PError("Udev/Devfs NOT OK.\n");
    }
    else
    {
        InitComplete = true;
    }
    if (VfsRegisterPseudoFs("/dev", SuperBlk) != SysOkay)
    {
        InitComplete = false;
        LOGENTRYC_PError("Cannot mount Udev/Devfs, NOT OK\n");
    }
    else
    {
        DevFsRegisterSeedDevices();
        InitComplete = true;
        LOGENTRYC_PSuccess("Udev/Devfs OK.\n");
    }

    /*Procfs*/
    LOGENTRYC_PInfo("KickStarting Procfs...\n");
    if (ProcFsInit() != SysOkay)
    {
        InitComplete = false;
        LOGENTRYC_PError("Procs NOT OK.\n");
    }
    else
    {
        InitComplete = true;
        LOGENTRYC_PSuccess("Procfs OK.\n");
    }

    /*Buses*/

    /*PCI*/
    LOGENTRYC_PInfo("KickStarting [BUS] PCI/PCIe...\n");
    if (InitializePciBus() != SysOkay)
    {
        InitComplete = false;
        LOGENTRYC_PError("[BUS] PCI/PCIe NOT OK.\n");
    }
    else
    {
        InitComplete = true;
        LOGENTRYC_PSuccess("[BUS] PCI/PCIe OK.\n");
    }

    /*Hardware*/
    LOGENTRYC_PInfo("KickStarting Driver Mgr...\n");
    InitializeDriverManager();
    LOGENTRYC_PSuccess("Driver Mgr OK.\n");

    LOGENTRYC_PInfo("KickStarting Device Mgr...\n");
    InitDeviceManager(Error);
    LOGENTRYC_PSuccess("Device Mgr OK.\n");

    LOGENTRYC_PInfo("KickStarting Probe Mgr...\n");
    InitProbeManager(Error);
    LOGENTRYC_PSuccess("Probe Mgr OK.\n");

    /*Load driver at current state*/
    CheckForHardware(Error);

#ifdef KernelTesting

    /*Testing*/
    LOGENTRYC_PInfo("KickStarting Tests...\n");
    __TEST__Thrd();
    __TEST__Proc();
    LOGENTRYC_PSuccess("Tests OK.\n");

#endif

    if (InitComplete == true)
    {
        LOGENTRYC_PInfo("KickStarting InitProc...\n");

        LOGENTRYC_PSuccess("[Post kernel init complete]\n");
        PosixProc* InitProc = PosixProcCreate();
        if (Probe_IF_Error(InitProc) || !InitProc)
        {
            LOGENTRYC_PError("failed to create initproc, errno: %d\n", Pointer_TO_Error(InitProc));
        }

        LOGENTRYC_PSuccess("created initproc pid=%ld ppid=%ld\n", InitProc->Pid, InitProc->Ppid);
        const char* InitProc_argv[] = {"AxeInitProc", "System", NULL};
        const char* InitProc_envp[] = {"PATH=/", "BootImg", "AxeInit.elf", NULL};
        int InitProc_Ret = PosixProcExecve(InitProc, "/AxeInit.elf", InitProc_argv, InitProc_envp);
        if (InitProc_Ret != SysOkay)
        {
            LOGENTRYC_PError(
                "failed to kickstart initproc pid=%ld, Errno: %d\n", InitProc->Pid, InitProc_Ret);
        }
        else
        {
            LOGENTRYC_PSuccess("executed initproc\n");
        }

        LOGENTRYC_PSuccess("InitProc OK.\n");
    }
    else
    {
        LOGENTRYC_PError("[Post kernel init failed]\n");
    }

#ifndef LoopHlt
    ThreadExit(SysOkay, Error);
#else
    for (;;)
    {
        /*As of idle thread*/
        __asm__("hlt");
    }
#endif
}

void
_start(void)
{
    SysErr  err;
    SysErr* Error = &err;

    if (EarlyLimineFrambuffer.response && EarlyLimineFrambuffer.response->framebuffer_count > 0)
    {
        struct limine_framebuffer* FrameBuffer = EarlyLimineFrambuffer.response->framebuffers[0];

        /*Locks*/
        InitializeSpinLock(&TestLock, "TestLock", Error);
        InitializeSpinLock(&SMPLock, "SMP", Error);
        InitializeSpinLock(&ConsoleLock, "Console", Error);

        /*UART*/
        InitializeSerial();

        /*Console*/
        if (FrameBuffer->address)
        {
            KickStartConsole(
                (uint32_t*)FrameBuffer->address, FrameBuffer->width, FrameBuffer->height);
            ClearConsole();

            LOGENTRYC_PInfo("AxeKrnl Kernel Booting...\n");
        }
        else
        {
            InitComplete = false;
            SerialPutString("No frambuffer provided, no console");
        }

        LOGENTRYC_PInfo("[Starting early kernel init]\n");

        /*CPU/IDT/GDT/ISR/IRQ/TSS*/
        LOGENTRYC_PInfo("KickStarting GDT...\n");
        InitializeGdt(Error);
        LOGENTRYC_PSuccess("GDT OK.\n");

        LOGENTRYC_PInfo("KickStarting IDT...\n");
        InitializeIdt(Error);
        LOGENTRYC_PSuccess("IDT OK.\n");

        /*FPU,SSE,Floats*/
        LOGENTRYC_PInfo("KickStarting Floats/SSE/FPU...\n");
        unsigned long Cr0, Cr4;
        __asm__ volatile("mov %%cr0, %0" : "=r"(Cr0));
        __asm__ volatile("mov %%cr4, %0" : "=r"(Cr4));
        Cr0 &= ~(1UL << 2); /* EM = 0 */
        Cr0 |= (1UL << 1);  /* MP = 1 */
        Cr0 &= ~(1UL << 3); /* TS = 0 */
        __asm__ volatile("mov %0, %%cr0" ::"r"(Cr0) : "memory");
        Cr4 |= (1UL << 9) | (1UL << 10);
        __asm__ volatile("mov %0, %%cr4" ::"r"(Cr4) : "memory");
        __asm__ volatile("fninit");
        LOGENTRYC_PSuccess("Floats/SSE/FPU OK.\n");

        /*Memory managers*/
        LOGENTRYC_PInfo("KickStarting PMM Mgr...\n");
        InitializePmm(Error);
        LOGENTRYC_PSuccess("PMM Mgr OK.\n");

        LOGENTRYC_PInfo("KickStarting VMM Mgr...\n");
        InitializeVmm(Error);
        LOGENTRYC_PSuccess("VMM Mgr OK.\n");

        LOGENTRYC_PInfo("KickStarting KHeap Mgr...\n");
        InitializeKHeap(Error);
        LOGENTRYC_PSuccess("KHeap Mgr OK.\n");

        /*Timer*/
        LOGENTRYC_PInfo("KickStarting Timer Mgr...\n");
        InitializeTimer(true, Error);
        LOGENTRYC_PSuccess("Timer Mgr OK.\n");

        /*Syscall*/
        LOGENTRYC_PInfo("KickStarting Syscalls...\n");
        InitSyscall();

        /*Legacy*/
        SetIdtEntry(SyscallIntNo,
                    (uint64_t)SysEntASM /*Int 0x80*/,
                    KernelCodeSelector,
                    SysInterruptGate,
                    Error);

        /*Modern*/
        uint64_t Efer = ReadMsr(0xC0000080); // EFER MSR
        Efer |= (1 << 0);                    // Set SCE (System Call Enable)
        WriteMsr(0xC0000080, Efer);
        uint64_t Star = ((uint64_t)0x13 << 48) | ((uint64_t)0x08 << 32);
        WriteMsr(0xC0000081, Star);                               // STAR MSR
        WriteMsr(0xC0000082, (uint64_t)SysEntASMSys /*Syscall*/); // LSTAR MSR
        WriteMsr(0xC0000084, (1ULL << 9));                        // SFMASK MSR
        LOGENTRYC_PSuccess("Syscalls OK.\n");

        /*Threading and SMP*/
        LOGENTRYC_PInfo("KickStarting Thread Mgr...\n");
        InitializeThreadManager(Error);
        LOGENTRYC_PSuccess("Thread Mgr OK.\n");

        LOGENTRYC_PInfo("KickStarting MLFQ Scheduler PerCPU...\n");
        InitializeScheduler(Error);
        LOGENTRYC_PSuccess("MLFQ Scheduler OK.\n");

        LOGENTRYC_PInfo("KickStarting SMP Mgr...\n");
        InitializeSmp(Error);
        LOGENTRYC_PSuccess("SMP Mgr OK.\n");

        LOGENTRYC_PSuccess("[Early kernel init complete]\n");

        LOGENTRYC_PInfo("KickStarting Post Kernel Init...\n");

        /*Kernel worker [Post Kernel Init]*/
        Thread* KernelWorker =
            CreateThread(ThreadTypeKernel, KernelWorkerThread, NULL, ThreadPrioritykernel);
        if (KernelWorker)
        {
            ThreadExecute(KernelWorker, Error);
            LOGENTRYC_PSuccess("Ctl Transfer to Worker\n");
            InitComplete = true;
        }
        else
        {
            LOGENTRYC_PError("[Cannot start the post kernel init]\n");
            InitComplete = false;
        }
    }

    for (;;)
    {
        __asm__("hlt");
    }
}
