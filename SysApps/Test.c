#include <stdio.h>

int
main(void)
{
    printf("Hello World\n");
    for (;;)
    {
        __asm__("nop");
    }
}