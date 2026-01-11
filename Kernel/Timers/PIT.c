#include <Timer.h>

#define BaseFreqTimer 1193182

int
InitializePitTimer(void)
{
    uint16_t Divisor = BaseFreqTimer /* PIT base frequency */ / TimerTargetFrequency;

    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)0x36), "Nd"((uint16_t)0x43));
    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)(Divisor & 0xFF)), "Nd"((uint16_t)0x40));
    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)(Divisor >> 8)), "Nd"((uint16_t)0x40));

    Timer.TimerFrequency = TimerTargetFrequency;
    PSuccess("PIT Timer initialized at %u Hz\n", Timer.TimerFrequency);

    return SysOkay;
}
