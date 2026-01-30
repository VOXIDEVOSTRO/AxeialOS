#include <KHeap.h>
#include <KrnPrintf.h>
#include <PCIBus.h>
#include <String.h>
#include <__AXEKCONF__.h>

/*reads*/
uint32_t
PciConfigRead32(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__)
{
    uint32_t Address = PciMakeAddress(__Bus__, __Device__, __Function__, __Offset__);

    __asm__ volatile("outl %0, %1" ::"a"(Address), "Nd"(PciConfigAddress));

    uint32_t Result;
    __asm__ volatile("inl %1, %0" : "=a"(Result) : "Nd"(PciConfigData));

    return Result;
}

uint16_t
PciConfigRead16(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__)
{
    uint32_t Data = PciConfigRead32(__Bus__, __Device__, __Function__, __Offset__ & 0xFC);
    return (uint16_t)(Data >> ((__Offset__ & 2) * 8));
}

uint8_t
PciConfigRead8(uint8_t __Bus__, uint8_t __Device__, uint8_t __Function__, uint8_t __Offset__)
{
    uint32_t Data = PciConfigRead32(__Bus__, __Device__, __Function__, __Offset__ & 0xFC);
    return (uint8_t)(Data >> ((__Offset__ & 3) * 8));
}

/*writes*/
void
PciConfigWrite32(uint8_t  __Bus__,
                 uint8_t  __Device__,
                 uint8_t  __Function__,
                 uint8_t  __Offset__,
                 uint32_t __Value__)
{
    uint32_t Address = PciMakeAddress(__Bus__, __Device__, __Function__, __Offset__);

    __asm__ volatile("outl %0, %1" ::"a"(Address), "Nd"(PciConfigAddress));
    __asm__ volatile("outl %0, %1" ::"a"(__Value__), "Nd"(PciConfigData));
}

void
PciConfigWrite16(uint8_t  __Bus__,
                 uint8_t  __Device__,
                 uint8_t  __Function__,
                 uint8_t  __Offset__,
                 uint16_t __Value__)
{
    uint32_t Data  = PciConfigRead32(__Bus__, __Device__, __Function__, __Offset__ & 0xFC);
    uint32_t Shift = (__Offset__ & 2) * 8;
    uint32_t Mask  = 0xFFFF << Shift;

    Data = (Data & ~Mask) | (((uint32_t)__Value__) << Shift);
    PciConfigWrite32(__Bus__, __Device__, __Function__, __Offset__ & 0xFC, Data);
}

void
PciConfigWrite8(uint8_t __Bus__,
                uint8_t __Device__,
                uint8_t __Function__,
                uint8_t __Offset__,
                uint8_t __Value__)
{
    uint32_t Data  = PciConfigRead32(__Bus__, __Device__, __Function__, __Offset__ & 0xFC);
    uint32_t Shift = (__Offset__ & 3) * 8;
    uint32_t Mask  = 0xFF << Shift;

    Data = (Data & ~Mask) | (((uint32_t)__Value__) << Shift);
    PciConfigWrite32(__Bus__, __Device__, __Function__, __Offset__ & 0xFC, Data);
}