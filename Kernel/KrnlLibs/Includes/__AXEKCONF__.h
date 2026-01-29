#pragma once

/*kconf for the axekrnl*/

/*TODO: maybe add a guide and some documentation about this and how to use*/

/*
    Misc
*/

/*Debug*/
/*|->*/ #define DEBUG

/*Errors*/
/*|->*/ // #define AllErrors

/*Fonts*/
/*|->*/ #define __F16

/*Syscalls*/
/*|->*/ // #define LegacySyscalls

/*
    ./Kernel/
*/

/*Entry.c*/
/*|->*/ #define LOGENTRYC_Debug
/*|->*/ #define LOGENTRYC_Logs
/*|->*/ // #define KernelTesting
/*|->*/ // #define LoopHlt

/*Test.c*/
/*|->*/ #define LOGTESTC_Debug
/*|->*/ #define LOGTESTC_Logs
/*|->*/ // #define __SUBTEST__ThrdTest
/*|->*/ #define __SUBTEST__ItLoops 10000
/*|->*/ #define __SUBTEST__Thrd    1

/*
    ./Kernel/VMM/
*/

/*VMMDebug.c*/
/*|->*/ // #define LOGVMMDEBUGC_Debug
/*|->*/ // #define LOGVMMDEBUGC_Logs

/*VMM.c*/
/*|->*/ // #define LOGVMMC_Debug
/*|->*/ // #define LOGVMMC_Logs

/*Pages.c*/
/*|->*/ // #define LOGPAGESC_Debug
/*|->*/ // #define LOGPAGESC_Logs

/*
    ./Kernel/VFS/
*/

/*VfsRamFs.c*/
/*|->*/ // #define LOGVFSRAMFSC_Debug
/*|->*/ // #define LOGVFSRAMFSC_Logs

/*VFS.c*/
/*|->*/ // #define LOGVFSC_Debug
/*|->*/ // #define LOGVFSC_Logs

/*
    ./Kernel/Timer/
*/

/*TimerCtl.c*/
/*|->*/ // #define LOGTIMERCTLC_Debug
/*|->*/ // #define LOGTIMERCTLC_Logs
/*|->*/ // #define InEveryInt 100
/*|->*/ // #define TimerIntTrace

/*PIT.c*/
/*|->*/ // #define LOGPITC_Debug
/*|->*/ // #define LOGPITC_Logs

/*MSRhelpers.c*/
/*|->*/ // #define LOGMSRHELPERSC_Debug
/*|->*/ // #define LOGMSRHELPERSC_Logs

/*HPET.c*/
/*|->*/ // #define LOGHPETC_Debug
/*|->*/ // #define LOGHPETC_Logs

/*APIC.c*/
/*|->*/ // #define LOGAPICC_Debug
/*|->*/ // #define LOGAPICC_Logs

/*
    ./Kernel/Syscalls/
*/

/*SysTbl.c*/
/*|->*/ // #define LOGSYSTBLC_Debug
/*|->*/ // #define LOGSYSTBLC_Logs

/*Syscall.c*/
/*|->*/ // #define LOGSYSCALLC_Debug
/*|->*/ // #define LOGSYSCALLC_Logs

/*
    ./Kernel/Sync/
*/

/*Spinlocks.c*/
/*|->*/ // #define LOGSPINLOCKSC_Debug
/*|->*/ // #define LOGSPINLOCKSC_Logs

/*SemaPhores.c*/
/*|->*/ // #define LOGSEMAPHORESC_Debug
/*|->*/ // #define LOGSEMAPHORESC_Logs

/*Mutexes.c*/
/*|->*/ // #define LOGMUTEXESC_Debug
/*|->*/ // #define LOGMUTEXESC_Logs

/*
    ./Kernel/SymMultiProc/
*/

/*LimineSMP.c*/
/*|->*/ // #define LOGLIMINESMPC_Debug
/*|->*/ // #define LOGLIMINESMPC_Logs

/*ApEntry.c*/
/*|->*/ // #define LOGAPENTRYC_Debug
/*|->*/ // #define LOGAPENTRYC_Logs

/*
    ./Kernel/SymMultiProc/PerCpuRoutines/
*/

/*StackAndCPU.c*/
/*|->*/ // #define LOGStackAndCPUC_Debug
/*|->*/ // #define LOGStackAndCPUC_Logs

/*BSPPages.c*/
/*|->*/ // #define LOGBSPPagesC_Debug
/*|->*/ // #define LOGBSPPagesC_Logs

/*
    ./Kernel/Serial/
*/

/*SerialPuts.c*/
/*|->*/ // #define LOGSERIALPUTSC_Debug
/*|->*/ // #define LOGSERIALPUTSC_Logs

/*Serial.c*/
/*|->*/ // #define LOGSERIALC_Debug
/*|->*/ // #define LOGSERIALC_Logs

/*
    ./Kernel/RamFS/
*/

/*RamFS.c*/
/*|->*/ // #define LOGRAMFSC_Debug
/*|->*/ // #define LOGRAMFSC_Logs

/*Nodehelpers.c*/
/*|->*/ // #define LOGNODEHELPERSC_Debug
/*|->*/ // #define LOGNODEHELPERSC_Logs

/*FSOperations.c*/
/*|->*/ // #define LOGFSOPERATIONSC_Debug
/*|->*/ // #define LOGFSOPERATIONSC_Logs

/*CpioHelpers*/
/*|->*/ // #define LOGCPIOHELPERSC_Debug
/*|->*/ // #define LOGCPIOHELPERSC_Logs

/*
    ./Kernel/Proc/
*/

/*Stack.c*/
/*|->*/ // #define LOGSTACKC_Debug
/*|->*/ // #define LOGSTACKC_Logs

/*ProcHelp.c*/
/*|->*/ // #define LOGPROCHELPC_Debug
/*|->*/ // #define LOGPROCHELPC_Logs

/*ProcFS.c*/
/*|->*/ // #define LOGPROCFSC_Debug
/*|->*/ // #define LOGPROCFSC_Logs

/*ProcFD.c*/
/*|->*/ // #define LOGPROCFDC_Debug
/*|->*/ // #define LOGPROCFDC_Logs

/*Proc.c*/
/*|->*/ // #define LOGPROCC_Debug
/*|->*/ // #define LOGPROCC_Logs

/*ELFL.c*/
/*|->*/ // #define LOGELFLC_Debug
/*|->*/ // #define LOGELFLC_Logs

/*
    ./Kernel/PMM/
*/

/*PMMDebug.c*/
/*|->*/ // #define LOGPMMDEBUGC_Debug
/*|->*/ // #define LOGPMMDEBUGC_Logs

/*PMM.c*/
/*|->*/ // #define LOGPMMC_Debug
/*|->*/ // #define LOGPMMC_Logs

/*MemMap.c*/
/*|->*/ // #define LOGMEMMAPC_Debug
/*|->*/ // #define LOGMEMMAPC_Logs

/*Bitmap.c*/
/*|->*/ // #define LOGBITMAPC_Debug
/*|->*/ // #define LOGBITMAPC_Logs

/*
    ./Kernel/KMods/
*/

/*ModMgr.c*/
/*|->*/ // #define LOGMODMGRC_Debug
/*|->*/ // #define LOGMODMGRC_Logs

/*ModMem.c*/
/*|->*/ // #define LOGMODMEMC_Debug
/*|->*/ // #define LOGMODMEMC_Logs

/*
    ./Kernel/KHeap/
*/

/*Slab.c*/
/*|->*/ // #define LOGSLABC_Debug
/*|->*/ // #define LOGSLABC_Logs

/*KHeap.c*/
/*|->*/ // #define LOGKHEAPC_Debug
/*|->*/ // #define LOGKHEAPC_Logs

/*
    ./Kernel/Interrupts/
*/

/*TSS.c*/
/*|->*/ // #define LOGTSSC_Debug
/*|->*/ // #define LOGTSSC_Logs

/*ISRHandler.c*/
/*|->*/ #define LOGISRHANDLERC_Debug
/*|->*/ #define LOGISRHANDLERC_Logs
/*|->*/ // #define USERDETAILS

/*IRQHandler.c*/
/*|->*/ // #define LOGIRQHANDLERC_Debug
/*|->*/ // #define LOGIRQHANDLERC_Logs

/*IDT.c*/
/*|->*/ // #define LOGIDTC_Debug
/*|->*/ // #define LOGIDTC_Logs

/*GDT.c*/
/*|->*/ // #define LOGGDTC_Debug
/*|->*/ // #define LOGGDTC_Logs

/*
    ./Kernel/Hardware/ProbeMgr/
*/

/*ProbeCore.c*/
/*|->*/ // #define LOGPROBECOREC_Debug
/*|->*/ // #define LOGPROBECOREC_Logs

/*
    ./Kernel/Hardware/DriverMgr/
*/

/*DrvReg.c*/
/*|->*/ // #define LOGDRVREGC_Debug
/*|->*/ // #define LOGDRVREGC_Logs

/*DrvLoader.c*/
/*|->*/ // #define LOGDRVLOADERC_Debug
/*|->*/ // #define LOGDRVLOADERC_Logs

/*DrvCore.c*/
/*|->*/ // #define LOGDRVCOREC_Debug
/*|->*/ // #define LOGDRVCOREC_Logs

/*
    ./Kernel/Hardware/DeviceMgr/
*/

/*DevCore.c*/
/*|->*/ // #define LOGDEVCOREC_Debug
/*|->*/ // #define LOGDEVCOREC_Logs

/*
    ./Kernel/Fonts/
*/

/*KrnFonts.c*/
/*|->*/ // #define LOGKRNFONTSC_Debug
/*|->*/ // #define LOGKRNFONTSC_Logs

/*KrnFontMap.c*/
/*|->*/ // #define LOGKRNFONTMAPC_Debug
/*|->*/ // #define LOGKRNFONTMAPC_Logs

/*
    ./Kernel/Firmware/
*/

/*TinyBlobs.c*/
/*|->*/ // #define LOGTINYBLOBSC_Debug
/*|->*/ // #define LOGTINYBLOBSC_Logs

/*BlobPathRes.c*/
/*|->*/ // #define LOGBLOBPATHRESC_Debug
/*|->*/ // #define LOGBLOBPATHRESC_Logs

/*BlobOps.c*/
/*|->*/ // #define LOGBLOBOPSC_Debug
/*|->*/ // #define LOGBLOBOPSC_Logs

/*
    ./Kernel/DynLinker/
*/

/*Linker.c*/
/*|->*/ // #define LOGLINKERC_Debug
/*|->*/ // #define LOGLINKERC_Logs

/*KExports.c*/
/*|->*/ // #define LOGKEXPORTSC_Debug
/*|->*/ // #define LOGKEXPORTSC_Logs

/*
    ./Kernel/DevFS/
*/

/*DevFS.c*/
/*|->*/ // #define LOGDEVFSC_Debug
/*|->*/ // #define LOGDEVFSC_Logs

/*
    ./Kernel/CharsDevs
*/

/*CharNameHelpers.c*/
/*|->*/ // #define LOGCHARNAMEHELPERSC_Debug
/*|->*/ // #define LOGCHARNAMEHELPERSC_Logs

/*
    ./Kernel/Buses/PCI/
*/

/*PCIDumps.c*/
/*|->*/ // #define LOGPCIDUMPSC_Debug
/*|->*/ // #define LOGPCIDUMPSC_Logs

/*PCIBus.c*/
/*|->*/ // #define LOGPCIBUSC_Debug
/*|->*/ // #define LOGPCIBUSC_Logs

/*MSI.c*/
/*|->*/ // #define LOGMSIC_Debug
/*|->*/ // #define LOGMSIC_Logs

/*
    ./Kernel/BootImg/
*/

/*ParseImage.c*/
/*|->*/ // #define LOGPARSEIMAGEC_Debug
/*|->*/ // #define LOGPARSEIMAGEC_Logs

/*
    ./Kernel/BootConsole/
*/

/*BootConsole.c*/
/*|->*/ // #define LOGBOOTCONSOLEC_Debug
/*|->*/ // #define LOGBOOTCONSOLEC_Logs
/*|->*/ // #define OnlyUART

/*
    ./Kernel/BlocksDevs/
*/

/*Part.c*/
/*|->*/ // #define LOGPARTC_Debug
/*|->*/ // #define LOGPARTC_Logs

/*BlockNameHelpers.c*/
/*|->*/ // #define LOGBLOCKNAMEHELPERSC_Debug
/*|->*/ // #define LOGBLOCKNAMEHELPERSC_Logs

/*BlockDev.c*/
/*|->*/ // #define LOGBLOCKDEVC_Debug
/*|->*/ // #define LOGBLOCKDEVC_Logs

/*
    ./Kernel/AxeThreads/
*/

/*ThreadMGR.c*/
/*|->*/ // #define LOGTHREADMGRC_Debug
/*|->*/ // #define LOGTHREADMGRC_Logs

/*Scheduler.c*/
/*|->*/ // #define LOGSCHEDULERC_Debug
/*|->*/ // #define LOGSCHEDULERC_Logs