#include <Errnos.h>
#include <GDT.h>
#include <IDT.h>
#include <POSIXProc.h>
#include <POSIXSignals.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <SymAP.h>
#include <__AXEKCONF__.h>

#ifdef LOGISRHANDLERC_Debug
#    define LOGISRHANDLERC_PDebug(fmt, ...) PDebug("[KERNEL>>ISRhandler.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGISRHANDLERC_PDebug(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGISRHANDLERC_Logs
#    define LOGISRHANDLERC_PError(fmt, ...) PError("[KERNEL>>ISRhandler.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGISRHANDLERC_PError(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGISRHANDLERC_Logs
#    define LOGISRHANDLERC_PWarn(fmt, ...) PWarn("[KERNEL>>ISRhandler.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGISRHANDLERC_PWarn(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGISRHANDLERC_Logs
#    define LOGISRHANDLERC_PInfo(fmt, ...) PInfo("[KERNEL>>ISRhandler.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGISRHANDLERC_PInfo(fmt, ...)                                                         \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGISRHANDLERC_Logs
#    define LOGISRHANDLERC_PSuccess(fmt, ...) PSuccess("[KERNEL>>ISRhandler.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGISRHANDLERC_PSuccess(fmt, ...)                                                      \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

/*Atomic monsters*/
#define ATOMIC_LOAD(ptr)           atomic_load(&(ptr))
#define ATOMIC_STORE(ptr, val)     atomic_store(&(ptr), (val))
#define ATOMIC_FETCH_ADD(ptr, val) atomic_fetch_add(&(ptr), (val))
#define ATOMIC_FETCH_SUB(ptr, val) atomic_fetch_sub(&(ptr), (val))
#define ATOMIC_FETCH_OR(ptr, val)  atomic_fetch_or(&(ptr), (val))
#define ATOMIC_FETCH_AND(ptr, val) atomic_fetch_and(&(ptr), (val))
#define ATOMIC_EXCHANGE(ptr, val)  atomic_exchange(&(ptr), (val))

void
IsrHandler(InterruptFrame* __Frame__)
{
    /*TODO: Send IPI of panic to all the APs*/

    __asm__ volatile("cli");

    SysErr   err;
    SysErr*  Error      = &err;
    uint32_t CurrentCpu = GetCurrentCpuId();

    if (__Frame__->IntNo == 14 && (__Frame__->ErrCode & 1) && (__Frame__->ErrCode & 2) &&
        (__Frame__->ErrCode & 4))
    {
        uint64_t Cr2;
        __asm__ volatile("movq %%cr2, %0" : "=r"(Cr2)); /* CR2 contains faulting address */
        HandleCOW(Cr2, __Frame__->ErrCode, Error);
        if (Error->ErrCode == SysOkay)
        {
            return;
        }
    }

    bool FromUser = ((__Frame__->Cs & 3) == 3);
    if (FromUser)
    {
        PosixProc* Proc = PosixFind(GetCurrentThread(CurrentCpu)->ProcessId);
        if (Proc)
        {
            LOGISRHANDLERC_PWarn("User exception %s (Vector: %lu) in PID=%ld on CPUID:%lu\n",
                                 ExceptionNames[__Frame__->IntNo],
                                 __Frame__->IntNo,
                                 Proc->Pid,
                                 CurrentCpu);

            switch (__Frame__->IntNo)
            {
                case 14: /* Page Fault */
                    PosixKill(Proc->Pid, SigSegv);
                    PosixExit(Proc, SysErro);
                    LOGISRHANDLERC_PInfo("Killed PID=%ld for memory violation.\n", Proc->Pid);
                    break;
                case 13: /* General Protection */
                    PosixKill(Proc->Pid, SigSegv);
                    PosixExit(Proc, SysErro);
                    LOGISRHANDLERC_PInfo("Killed PID=%ld for violation.\n", Proc->Pid);
                    break;
                case 0: /* Divide Error */
                    PosixKill(Proc->Pid, SigFpe);
                    PosixExit(Proc, SysErro);
                    LOGISRHANDLERC_PInfo("Killed PID=%ld for dividing by zero.\n", Proc->Pid);
                    break;
                case 6: /* Invalid Opcode */
                    PosixKill(Proc->Pid, SigIll);
                    PosixExit(Proc, SysErro);
                    LOGISRHANDLERC_PInfo("Killed PID=%ld for using bad instruction.\n", Proc->Pid);
                    break;
                default:
                    PosixKill(Proc->Pid, SigKill);
                    PosixExit(Proc, SysErro);
                    LOGISRHANDLERC_PInfo("Killed PID=%ld for something else.\n", Proc->Pid);
                    break;
            }
#ifndef USERDETAILS
            /*Re-Schedule*/
            Schedule(CurrentCpu, __Frame__, Error);
            __asm__ volatile("sti");
            return;
#endif
        }
    }
#ifndef USERDETAILS
    KrnPrintf("\n");
#endif
#ifdef USERDETAILS
    if (FromUser)
    {
#endif
#ifndef USERDETAILS
        LOGISRHANDLERC_PError("EXCEPTION: %s (Vector: %lu) on CPU %u\n",
                              ExceptionNames[__Frame__->IntNo],
                              __Frame__->IntNo,
                              CurrentCpu);
#endif

        KrnPrintf("Error Code: 0x%016lx\n", __Frame__->ErrCode);

        KrnPrintf("\n");

        KrnPrintf("\nCPU STATE:\n");
        KrnPrintf("  RIP: 0x%016lx  RSP: 0x%016lx\n", __Frame__->Rip, __Frame__->Rsp);
        KrnPrintf("  RAX: 0x%016lx  RBX: 0x%016lx\n", __Frame__->Rax, __Frame__->Rbx);
        KrnPrintf("  RCX: 0x%016lx  RDX: 0x%016lx\n", __Frame__->Rcx, __Frame__->Rdx);
        KrnPrintf("  RSI: 0x%016lx  RDI: 0x%016lx\n", __Frame__->Rsi, __Frame__->Rdi);
        KrnPrintf("  RBP: 0x%016lx  R8:  0x%016lx\n", __Frame__->Rbp, __Frame__->R8);
        KrnPrintf("  R9:  0x%016lx  R10: 0x%016lx\n", __Frame__->R9, __Frame__->R10);
        KrnPrintf("  R11: 0x%016lx  R12: 0x%016lx\n", __Frame__->R11, __Frame__->R12);
        KrnPrintf("  R13: 0x%016lx  R14: 0x%016lx\n", __Frame__->R13, __Frame__->R14);
        KrnPrintf("  R15: 0x%016lx\n", __Frame__->R15);

        KrnPrintf("\nSEGMENT REGISTERS:\n");
        KrnPrintf("  CS: 0x%04lx  SS: 0x%04lx\n", __Frame__->Cs, __Frame__->Ss);
        KrnPrintf("  RFLAGS: 0x%016lx\n", __Frame__->Rflags);

        /*Break down RFLAGS*/
        KrnPrintf("  RFLAGS: ");
        if (__Frame__->Rflags & (1 << 0))
        {
            KrnPrintf("CF "); /* Carry Flag */
        }
        if (__Frame__->Rflags & (1 << 2))
        {
            KrnPrintf("PF "); /* Parity Flag */
        }
        if (__Frame__->Rflags & (1 << 4))
        {
            KrnPrintf("AF "); /* Auxiliary Carry Flag */
        }
        if (__Frame__->Rflags & (1 << 6))
        {
            KrnPrintf("ZF "); /* Zero Flag */
        }
        if (__Frame__->Rflags & (1 << 7))
        {
            KrnPrintf("SF "); /* Sign Flag */
        }
        if (__Frame__->Rflags & (1 << 8))
        {
            KrnPrintf("TF "); /* Trap Flag */
        }
        if (__Frame__->Rflags & (1 << 9))
        {
            KrnPrintf("IF "); /* Interrupt Flag */
        }
        if (__Frame__->Rflags & (1 << 10))
        {
            KrnPrintf("DF "); /* Direction Flag */
        }
        if (__Frame__->Rflags & (1 << 11))
        {
            KrnPrintf("OF "); /* Overflow Flag */
        }
        KrnPrintf("\n");

        DumpControlRegisters(Error);
        if (!__Frame__->Rip)
        {
            KrnPrintf("NULL Rip!\n");
        }
        else
        {
            DumpInstruction(__Frame__->Rip, Error);
        }
        KrnPrintf("\nSTACK DUMP (64 bytes from RSP):\n");
        DumpMemory(__Frame__->Rsp, 64, Error);

        KrnPrintf("\nSTACK TRACE:\n");
        uint64_t* Rbp = (uint64_t*)__Frame__->Rbp;
        for (int Iteration = 0; Iteration < 8 && Rbp != 0; Iteration++)
        {
            if ((uint64_t)Rbp < 0x1000 || (uint64_t)Rbp > 0x7FFFFFFFFFFF)
            {
                break;
            }

            uint64_t RetAddr = *(Rbp + 1); /* Return address is at RBP+8 */
            KrnPrintf("  Frame %d: RBP=0x%016lx RET=0x%016lx\n", Iteration, (uint64_t)Rbp, RetAddr);
            Rbp = (uint64_t*)*Rbp; /* Next frame's RBP is at current RBP */
        }

        switch (__Frame__->IntNo)
        {
            case 13: /*General Protection Fault*/
                KrnPrintf("\nGENERAL PROTECTION FAULT DETAILS:\n");
                if (__Frame__->ErrCode & 1)
                {
                    KrnPrintf("  External event caused the exception\n");
                }
                else
                {
                    KrnPrintf("  Internal event caused the exception\n");
                }

                if (__Frame__->ErrCode & 2)
                {
                    KrnPrintf("  Exception occurred in IDT\n");
                }
                else if (__Frame__->ErrCode & 4)
                {
                    KrnPrintf("  Exception occurred in LDT\n");
                }
                else
                {
                    KrnPrintf("  Exception occurred in GDT\n");
                }

                KrnPrintf("  Selector Index: %lu\n", (__Frame__->ErrCode >> 3) & 0x1FFF);
                break;

            case 14: /*Page Fault*/
                {
                    uint64_t Cr2;
                    __asm__ volatile("movq %%cr2, %0"
                                     : "=r"(Cr2)); /* CR2 contains faulting address */

                    KrnPrintf("\nPAGE FAULT DETAILS:\n");
                    KrnPrintf("  Faulting Address: 0x%016lx\n", Cr2);
                    KrnPrintf("  Caused by: ");

                    if (__Frame__->ErrCode & 1)
                    {
                        KrnPrintf("Protection violation ");
                    }
                    else
                    {
                        KrnPrintf("Page not present ");
                    }

                    if (__Frame__->ErrCode & 2)
                    {
                        KrnPrintf("Write ");
                    }
                    else
                    {
                        KrnPrintf("Read ");
                    }

                    if (__Frame__->ErrCode & 4)
                    {
                        KrnPrintf("User mode ");
                    }
                    else
                    {
                        KrnPrintf("Kernel mode ");
                    }

                    if (__Frame__->ErrCode & 8)
                    {
                        KrnPrintf("Reserved bit violation ");
                    }

                    if (__Frame__->ErrCode & 16)
                    {
                        KrnPrintf("Instruction fetch ");
                    }

                    KrnPrintf("\n");
                }
                break;
        }

        KrnPrintf("\nMEMORY AROUND RIP:\n");
        if (!__Frame__->Rip)
        {
            KrnPrintf("NULL Rip!\n");
        }
        else
        {
            DumpMemory(__Frame__->Rip - 32, 64, Error);
        }

        PerCpuData* CpuData = GetPerCpuData(CurrentCpu);
        if (CurrentCpu != 0)
        {
            KrnPrintf("\nDESCRIPTOR TABLES (CPU %u):\n", CurrentCpu);
            KrnPrintf(
                "  GDT Base: 0x%016lx  Limit: %u\n", CpuData->GdtPtr.Base, CpuData->GdtPtr.Limit);
            KrnPrintf(
                "  IDT Base: 0x%016lx  Limit: %u\n", CpuData->IdtPtr.Base, CpuData->IdtPtr.Limit);
        }
        else
        {
            KrnPrintf("\nDESCRIPTOR TABLES (CPU %u):\n", CurrentCpu);
            KrnPrintf("  GDT Base: 0x%016lx  Limit: %u\n", GdtPtr.Base, GdtPtr.Limit);
            KrnPrintf("  IDT Base: 0x%016lx  Limit: %u\n", IdtPtr.Base, IdtPtr.Limit);
        }

        KrnPrintf("\n");
        KrnPrintf("Fix your shitty code idiot.\n");

#ifdef USERDETAILS
        if (FromUser)
        {
            /*Re-Schedule*/
            Schedule(CurrentCpu, __Frame__, Error);
            __asm__ volatile("sti");
            return;
        }
        else
        {
#endif
            for (;;)
            {
                __asm__ volatile("hlt");
            }
#ifdef USERDETAILS
        }
#endif
#ifdef USERDETAILS
    }
#endif
}