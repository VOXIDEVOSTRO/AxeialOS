#include <AllTypes.h>
#include <KrnPrintf.h>

/*Deprecated?*/

int
module_probe(void)
{
    PSuccess("Probe successful\n");
    return SysOkay;
}

void
module_init(void)
{
    PSuccess("Init complete\n");
}

void
module_exit(void)
{
    PSuccess("Exit complete\n");
}
