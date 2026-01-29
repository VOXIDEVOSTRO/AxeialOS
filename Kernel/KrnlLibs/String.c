#include <AllTypes.h>
#include <__AXEKCONF__.h>

/*Strcpy*/
void
strcpy(char* __Dest__, const char* __Src__, uint32_t __MaxLen__)
{
    uint32_t Index = 0;
    while (__Src__[Index] && Index < (__MaxLen__ - 1))
    {
        __Dest__[Index] = __Src__[Index];
        Index++;
    }
    __Dest__[Index] = '\0';
}

/*memcpy*/
void*
memcpy(void* __Dest__, const void* __Src__, size_t __Size__)
{
    char*       Dest = __Dest__;
    const char* Src  = __Src__;

    while (__Size__--)
    {
        *Dest++ = *Src++;
    }

    return __Dest__;
}

/*Memset*/
void*
memset(void* __Dest__, int __Value__, size_t __Index__)
{
    unsigned char* ptr = (unsigned char*)__Dest__;

    while (__Index__--)
    {
        *ptr++ = (unsigned char)__Value__;
    }

    return __Dest__;
}

/*Strcmp*/
int
strcmp(const char* __Str1__, const char* __Str2__)
{
    while (*__Str1__ && (*__Str1__ == *__Str2__))
    {
        __Str1__++;
        __Str2__++;
    }

    return (unsigned char)(*__Str1__) - (unsigned char)(*__Str2__);
}

/*Strlen*/
size_t
strlen(const char* __Str__)
{
    size_t __Size__ = 0;
    while (__Str__[__Size__] != '\0')
    {
        __Size__++;
    }
    return __Size__;
}

/*Strncmp*/
int
strncmp(const char* __S1__, const char* __S2__, size_t __Size__)
{
    for (size_t __i = 0; __i < __Size__; __i++)
    {
        unsigned char c1 = (unsigned char)__S1__[__i];
        unsigned char c2 = (unsigned char)__S2__[__i];

        if (c1 != c2)
        {
            return (c1 < c2) ? -1 : 1;
        }

        if (c1 == '\0')
        {
            return 0;
        }
    }
    return 0;
}

/*Strchr*/
char*
strrchr(const char* __Str__, int __Idx__)
{
    const char* LastChar = 0;
    char        Char     = (char)__Idx__;

    if (!__Str__)
    {
        return 0;
    }

    while (*__Str__)
    {
        if (*__Str__ == Char)
        {
            LastChar = __Str__;
        }
        __Str__++;
    }

    /* Also check terminating null if __Idx__ == '\0' */
    if (Char == '\0')
    {
        return (char*)__Str__;
    }

    return (char*)LastChar;
}

/*Strchr*/
char*
strchr(const char* __Str__, int __Idx__)
{
    if (!__Str__)
    {
        return 0;
    }

    while (*__Str__)
    {
        if (*__Str__ == (char)__Idx__)
        {
            return (char*)__Str__;
        }
        __Str__++;
    }

    /* Check terminating NUL if __Idx__ == '\0' */
    if (__Idx__ == 0)
    {
        return (char*)__Str__;
    }

    return 0;
}

/*atol*/
long
atol(const char* __Str__)
{
    if (!__Str__)
    {
        return 0;
    }
    long Result = 0;
    int  Sign   = 1;

    /* skip whitespace */
    while (*__Str__ == ' ' || *__Str__ == '\t' || *__Str__ == '\n')
    {
        __Str__++;
    }

    /* handle Sign */
    if (*__Str__ == '-')
    {
        Sign = -1;
        __Str__++;
    }
    else if (*__Str__ == '+')
    {
        __Str__++;
    }

    while (*__Str__ >= '0' && *__Str__ <= '9')
    {
        Result = Result * 10 + (*__Str__ - '0');
        __Str__++;
    }
    return Sign * Result;
}

/* strncpy */
char*
strncpy(char* __Dst__, const char* __Src__, long __Idx__)
{
    if (!__Dst__ || !__Src__ || __Idx__ <= 0)
    {
        return __Dst__;
    }
    long I = 0;
    for (; I < __Idx__ - 1 && __Src__[I]; I++)
    {
        __Dst__[I] = __Src__[I];
    }
    __Dst__[I] = '\0';
    return __Dst__;
}