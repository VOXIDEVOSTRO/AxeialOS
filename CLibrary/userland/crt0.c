#include <reent.h>
extern void __libc_init_array(void);
extern int  main(void);

void
_init(void)
{ /*Shut up GCC*/
}
void
_fini(void)
{ /*Shut up GCC*/
}

void
_start(void)
{
    _REENT_INIT_PTR(_impure_ptr);
    __sinit(_impure_ptr);
    __libc_init_array();
    int ret = main();
    _exit(ret); /*Returned*/
}