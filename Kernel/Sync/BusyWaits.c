#include <AxeThreads.h>
#include <Sync.h>
#include <__AXEKCONF__.h>

void
__BLOCK__BusyWait(uint64_t __Loops__, SysErr* __Err__)
{
    while (--__Loops__)
    {
        __asm__("pause");
    }
}

void
__NONBLOCK__BusyWait(uint64_t __Loops__, SysErr* __Err__)
{
    while (--__Loops__)
    {
        ThreadYield(__Err__);
    }
}