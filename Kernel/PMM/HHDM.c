#include <PMM.h>
#include <__AXEKCONF__.h>

void*
PhysToVirt(uint64_t __PhysAddr__)
{
    return (void*)(__PhysAddr__ + Pmm.HhdmOffset);
}

uint64_t
VirtToPhys(void* __VirtAddr__)
{
    return (uint64_t)__VirtAddr__ - Pmm.HhdmOffset;
}
