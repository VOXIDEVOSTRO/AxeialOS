#include <GDT.h>
#include <IDT.h>
#include <PerCPUData.h>
#include <SMP.h>
#include <SymAP.h>

void
IsrHandler(InterruptFrame* __Frame__)
{
    /*Disable interrupts to prevent re-entrant exceptions during diagnostics*/
    __asm__ volatile("cli");

    /*Get current CPU ID for SMP-aware debugging*/
    uint32_t CurrentCpu = GetCurrentCpuId();

    KrnPrintf("\n");

    /*Display exception header with name, vector, and CPU information*/
    PError("EXCEPTION: %s (Vector: %lu) on CPU %u\n",
           ExceptionNames[__Frame__->IntNo],
           __Frame__->IntNo,
           CurrentCpu);
    KrnPrintf("Error Code: 0x%016lx\n", __Frame__->ErrCode);

    KrnPrintf("\n");

    /*Dump complete CPU register state at time of exception*/
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

    /*Display segment registers and flags*/
    KrnPrintf("\nSEGMENT REGISTERS:\n");
    KrnPrintf("  CS: 0x%04lx  SS: 0x%04lx\n", __Frame__->Cs, __Frame__->Ss);
    KrnPrintf("  RFLAGS: 0x%016lx\n", __Frame__->Rflags);

    /*Break down RFLAGS into individual flag components for easier analysis*/
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

    /*Dump CPU control registers (CR0, CR2, CR3, CR4)*/
    DumpControlRegisters();

    /*Display instruction bytes at the faulting RIP*/
    DumpInstruction(__Frame__->Rip);

    /*Dump stack contents around the stack pointer*/
    KrnPrintf("\nSTACK DUMP (64 bytes from RSP):\n");
    DumpMemory(__Frame__->Rsp, 64);

    /*Generate stack trace by walking the RBP chain*/
    KrnPrintf("\nSTACK TRACE:\n");
    uint64_t* rbp = (uint64_t*)__Frame__->Rbp;
    for (int Iteration = 0; Iteration < 8 && rbp != 0; Iteration++)
    {
        /*Validate RBP pointer to prevent crashes during stack trace*/
        if ((uint64_t)rbp < 0x1000 || (uint64_t)rbp > 0x7FFFFFFFFFFF)
        {
            break;
        }

        uint64_t ret_addr = *(rbp + 1); /* Return address is at RBP+8 */
        KrnPrintf("  Frame %d: RBP=0x%016lx RET=0x%016lx\n", Iteration, (uint64_t)rbp, ret_addr);
        rbp = (uint64_t*)*rbp; /* Next frame's RBP is at current RBP */
    }

    /*Provide detailed analysis for specific exception types*/
    switch (__Frame__->IntNo)
    {
        case 13: /*General Protection Fault - Most common protection violation*/
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

        case 14: /*Page Fault - Memory access violation*/
            {
                uint64_t cr2;
                __asm__ volatile("movq %%cr2, %0" : "=r"(cr2)); /* CR2 contains faulting address */
                KrnPrintf("\nPAGE FAULT DETAILS:\n");
                KrnPrintf("  Faulting Address: 0x%016lx\n", cr2);
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

    /*Dump memory around the instruction pointer for context*/
    KrnPrintf("\nMEMORY AROUND RIP:\n");
    DumpMemory(__Frame__->Rip - 32, 64);

    /*Display per-CPU descriptor table information for SMP debugging*/
    PerCpuData* CpuData = GetPerCpuData(CurrentCpu);
    if (CurrentCpu != 0)
    {
        KrnPrintf("\nDESCRIPTOR TABLES (CPU %u):\n", CurrentCpu);
        KrnPrintf("  GDT Base: 0x%016lx  Limit: %u\n", CpuData->GdtPtr.Base, CpuData->GdtPtr.Limit);
        KrnPrintf("  IDT Base: 0x%016lx  Limit: %u\n", CpuData->IdtPtr.Base, CpuData->IdtPtr.Limit);
    }
    else
    {
        KrnPrintf("\nDESCRIPTOR TABLES (CPU %u):\n", CurrentCpu);
        KrnPrintf("  GDT Base: 0x%016lx  Limit: %u\n", GdtPtr.Base, GdtPtr.Limit);
        KrnPrintf("  IDT Base: 0x%016lx  Limit: %u\n", IdtPtr.Base, IdtPtr.Limit);
    }

    KrnPrintf("\n");
    KrnPrintf("Fix your shitty code idiot.\n");

    /*Halt the system indefinitely - appropriate for development/debugging*/
    while (1)
    {
        __asm__ volatile("hlt");
    }
}
