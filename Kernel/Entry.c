#include "KrnCommon.h"

/** Devs */
#define __Kernel__

SpinLock TestLock;

void
KernelWorkerThread(void* __Argument__)
{
    PInfo("Kernel Worker: Started on CPU %u\n", GetCurrentCpuId());

    ModMemInit();
    InitializeBootImage();

    DevFsInit();
    Superblock* SuperBlk = DevFsMountImpl(0, 0);
    if (!SuperBlk)
    {
        PError("Boot: DevFsMountImpl failed\n");
    }

    if (VfsRegisterPseudoFs("/dev", SuperBlk) != 0)
    {
        PError("Boot: mount devfs failed\n");
    }
    DevFsRegisterSeedDevices();

    if (ProcFsInit() != 0)
    {
        PError("procfs init failed\n");
        return;
    }

    InitRamDiskDevDrvs();

    __TEST__Proc();

    /*done*/
    ThreadExit(0);
}

void
_start(void)
{
    if (EarlyLimineFrambuffer.response && EarlyLimineFrambuffer.response->framebuffer_count > 0)
    {
        struct limine_framebuffer* FrameBuffer = EarlyLimineFrambuffer.response->framebuffers[0];

        InitializeSpinLock(&TestLock, "TestLock");

        InitializeSerial();

        if (FrameBuffer->address)
        {
            KickStartConsole(
                (uint32_t*)FrameBuffer->address, FrameBuffer->width, FrameBuffer->height);
            InitializeSpinLock(&ConsoleLock, "Console");
            ClearConsole();

            PInfo("AxeialOS Kernel Booting...\n");
        }

        InitializeGdt();
        InitializeIdt();

        unsigned long Cr0, Cr4;

        /* Read CR0 and CR4 */
        __asm__ volatile("mov %%cr0, %0" : "=r"(Cr0));
        __asm__ volatile("mov %%cr4, %0" : "=r"(Cr4));

        /* CR0: clear EM (bit 2), set MP (bit 1), clear TS (bit 3) */
        Cr0 &= ~(1UL << 2); /* EM = 0 */
        Cr0 |= (1UL << 1);  /* MP = 1 */
        Cr0 &= ~(1UL << 3); /* TS = 0 */
        __asm__ volatile("mov %0, %%cr0" ::"r"(Cr0) : "memory");

        /* CR4: set OSFXSR (bit 9) and OSXMMEXCPT (bit 10) for SSE */
        Cr4 |= (1UL << 9) | (1UL << 10);
        __asm__ volatile("mov %0, %%cr4" ::"r"(Cr4) : "memory");

        /* Initialize x87/SSE state */
        __asm__ volatile("fninit");

        InitializePmm();
        InitializeVmm();
        InitializeKHeap();

        InitializeTimer();
        InitSyscall();
        SetIdtEntry(0x80, (uint64_t)SysEntASM, KernelCodeSelector, 0xEE);
        InitializeThreadManager();
        InitializeSpinLock(&SMPLock, "SMP");
        InitializeSmp();
        InitializeScheduler();

        Thread* KernelWorker =
            CreateThread(ThreadTypeKernel, KernelWorkerThread, NULL, ThreadPrioritykernel);
        if (KernelWorker)
        {
            ThreadExecute(KernelWorker);
            PSuccess("Ctl Transfer to Worker\n");
        }
    }

    for (;;)
    {
        __asm__("hlt");
    }
}
