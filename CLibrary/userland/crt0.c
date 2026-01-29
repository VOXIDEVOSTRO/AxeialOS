#include <reent.h>
#include <stdint.h>
#include <string.h>
#include <sys/reent.h>

extern void __libc_init_array(void);
extern int  main(int, char**, char**);
void        _exit(int __status__);
void        __sinit(struct _reent* r);

void
_init(void)
{ /* Shut up GCC */
}
void
_fini(void)
{ /* Shut up GCC */
}

void __attribute__((naked))
_start(void)
{
    volatile uintptr_t* sp;
    __asm__ volatile("mov %%rsp, %0\n" : "=r"(sp));
    int    argc = (int)sp[0];
    char** argv = (char**)(sp + 1);
    char** envp = argv + argc + 1;
    _REENT_INIT_PTR(_impure_ptr);
    __sinit(_impure_ptr);
    __libc_init_array();
    int ret = main(argc, argv, envp);
    _exit(ret);
}