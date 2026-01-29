#include <DevMgr.h>
#include <Errnos.h>

/*load 'Tty' device, blindly*/

int
module_probe(void)
{
    int Return = LoadDriver("Tty");
    if (Return != SysOkay)
    {
        return -BadReturn;
    }
    return SysOkay;
}

void
module_exit(void)
{
    module_probe();
}

void
module_init(void)
{
    module_probe();
}
