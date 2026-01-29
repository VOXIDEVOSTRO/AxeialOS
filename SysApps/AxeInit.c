#include <stdio.h>

int
main(int argc, char* argv[], char* envp[])
{
    printf("argc = %d\n", argc);

    for (int i = 0; i < argc; i++)
    {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    for (char** env = envp; *env != NULL; env++)
    {
        printf("envp: %s\n", *env);
    }

    return 0; /*SysOkay?*/
}