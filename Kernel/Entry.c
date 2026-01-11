#include "KrnCommon.h"
#include <Errnos.h>

// #define EarlySplash

/** Devs */
#define __Kernel__

SpinLock TestLock;
bool     InitComplete = false;

/*Worker*/
void
KernelWorkerThread(void* __Argument__)
{
    SysErr  err;
    SysErr* Error = &err;

    PInfo("[Starting post kernel init]\n");

    PInfo("Kernel Worker started on CPU %u\n", GetCurrentCpuId());

    /*Modules*/
    ModMemInit(Error);
    InitializeBootImage();

    /*Udev/Devfs*/
    DevFsInit();
    Superblock* SuperBlk = DevFsMountImpl(0, 0);
    if (Probe_IF_Error(SuperBlk))
    {
        InitComplete = false;
        PError("devfs failed\n");
    }
    else
    {
        InitComplete = true;
    }

    if (VfsRegisterPseudoFs("/dev", SuperBlk) != SysOkay)
    {
        InitComplete = false;
        PError("mount udev/devfs failed\n");
    }
    else
    {
        InitComplete = true;
    }
    DevFsRegisterSeedDevices();

    /*Procfs*/
    if (ProcFsInit() != SysOkay)
    {
        InitComplete = false;
        PError("procfs init failed\n");
    }
    else
    {
        InitComplete = true;
    }

    if (InitComplete == true)
    {
        PSuccess("[Early kernel init complete]\n");
    }
    else
    {
        PError("[Early kernel init failed]\n");
    }

    /*Buses*/

    /*PCI*/
    if (InitializePciBus() != SysOkay)
    {
        InitComplete = false;
        PError("pcibus init failed\n");
    }
    else
    {
        InitComplete = true;
    }

    /*Hardware*/
    InitializeDriverManager();
    InitDeviceManager(Error);
    InitProbeManager(Error);

    /*Load driver at current state*/
    CheckForHardware(Error);

    /*Testing*/
    __TEST__Thrd();
    __TEST__Proc();

    if (InitComplete == true)
    {
        PSuccess("[Post kernel init complete]\n");

#ifdef EarlySplash

        ClearConsole();

        PSuccess("[Splash]\n");

        KrnPrintf("        @         B H           M&@     @@@@@@@@@@    @@@@         @          "
                  "@@@@      \n");
        KrnPrintf("       9@        @r i              G    @@@@@@@@@@    @@@@         9@         "
                  "@@@@      \n");
        KrnPrintf("       @@@     2    @@r       h@    ;   @@@S          @@@@        @@@@        "
                  "@@@@      \n");
        KrnPrintf("      @@@@@   i ; ;@h&;#     @B@@@    : @@@S          @@@@        @@@@        "
                  "@@@@      \n");
        KrnPrintf("     S@@@@@    &sA@   @@&s 3B@A   @  @  @@@S          @@@@       @@@@@@       "
                  "@@@@      \n");
        KrnPrintf("     @@@ @@@     X     B@@h@@9          @@@@@@@@@     @@@@      @@@@@@@@      "
                  "@@@@      \n");
        KrnPrintf("    @@@@ @@@@           @@i&@           @@@@@@@@@     @@@@      @@@  @@@      "
                  "@@@@      \n");
        KrnPrintf("   ;@@@   @@@          @#@ @&h          @@@S          @@@@     @@@@  @@@@     "
                  "@@@@      \n");
        KrnPrintf("   @@@2   @@@@       @r@B   B@sr        @@@S          @@@@    9@@@    @@@S    "
                  "@@@@      \n");
        KrnPrintf("  @@@@@@@@@@@@@     @S@i    rr@#@       @@@S          @@@@    @@@@@@@@@@@@    "
                  "@@@@      \n");
        KrnPrintf("  @@@@@@@@@@@@@   @@Gh         H5@S     @@@S          @@@@   @@@@@@@@@@@@@@   "
                  "@@@@      \n");
        KrnPrintf(" @@@@       @@@@s;@29          i@2@9    @@@@@@@@@@@   @@@@  h@@@        @@@i  "
                  "@@@@@@@@@@\n");
        KrnPrintf("@@@@         @@@@ @               A     @@@@@@@@@@@   @@@@  @@@@        @@@@  "
                  "@@@@@@@@@@\n");
#endif
    }
    else
    {
        PError("[Post kernel init failed]\n");
    }

    ThreadExit(0, Error);
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

            PInfo("AxeKrnl Kernel Booting...\n");
        }
        else
        {
            InitComplete = false;
            SerialPutString("No frambuffer provided, no console");
        }

        PInfo("[Starting early kernel init]\n");

        /*CPU/IDT/GDT/ISR/IRQ/TSS*/
        InitializeGdt(Error);
        InitializeIdt(Error);

        /*FPU,SSE,Floats*/
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

        /*Memory managers*/
        InitializePmm(Error);
        InitializeVmm(Error);
        InitializeKHeap(Error);

        /*Timer*/
        InitializeTimer(Error);

        /*Syscall*/
        InitSyscall();
        SetIdtEntry(SyscallIntNo, (uint64_t)SysEntASM, KernelCodeSelector, SysInterruptGate, Error);

        /*Threading and SMP*/
        InitializeSmp(Error);
        InitializeThreadManager(Error);
        InitializeScheduler(Error);

        /*Kernel worker [Post Kernel Init]*/
        Thread* KernelWorker =
            CreateThread(ThreadTypeKernel, KernelWorkerThread, NULL, ThreadPrioritykernel);
        if (KernelWorker)
        {
            ThreadExecute(KernelWorker, Error);
            PSuccess("Ctl Transfer to Worker\n");
            InitComplete = true;
        }
        else
        {
            PError("[Cannot start the post kernel init]\n");
            InitComplete = false;
        }
    }

    for (;;)
    {
        __asm__("hlt");
    }
}
