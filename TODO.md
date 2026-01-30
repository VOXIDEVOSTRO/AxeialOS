# Things my lazy bum should(MUST!) do

- Add fricking double buffering to super slow early boot console [X]. (completed because i simplified the EarlyBootConsole, for more info read the code of it)
- Add support to syscall instruction [X]. (completed, the kernel also supports legacy Int 0x80)
- Fix a problem where CPU 0 (BSP) doesn't schedule threads [X]. (nevermind was just a logic error)
- Add some better documentation like for AXEKCONF [].
- Standardize the K-API(Kernel API from drivers/kernel modules) [].
- Probably add proper shutdown and restart stuff for like fatal panics (kernel panic) and for other stuff as in main routine [].
- Impliment HPET timer [].
- Fix the countless problems in the POSIXProc and especially fork and execve faults [].