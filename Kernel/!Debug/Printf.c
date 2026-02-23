
#include <Errnos.h>
#include <KrnPrintf.h>
#include <Serial.h>

void
KrnPrintf(const char* __Format__, ...)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    ReleaseSpinLock(&ConsoleLock, Error);
}

void
KrnPrintfColor(uint32_t __FG__, uint32_t __BG__, const char* __Format__, ...)
{
    SysErr  err;
    SysErr* Error = &err;
    AcquireSpinLock(&ConsoleLock, Error);
    uint32_t MainFG = Console.TXColor;
    uint32_t MainBG = Console.BGColor;

    SetBGColor(__FG__, __BG__);

    __builtin_va_list args;
    __builtin_va_start(args, __Format__);

    while (*__Format__)
    {
        if (*__Format__ == '%')
        {
            __Format__++;
            ProcessFormatSpecifier(&__Format__, &args);
        }
        else
        {
            PutChar(*__Format__);
            __Format__++;
        }
    }

    __builtin_va_end(args);
    SetBGColor(MainFG, MainBG);
    ReleaseSpinLock(&ConsoleLock, Error);
}

void
ProcessFormatSpecifier(const char** __Format__, __builtin_va_list* __Args__)
{
    FormatFlags Flags = {0};

    /* Parse flags: -, +, space, #, 0 */
    while (1)
    {
        switch (**__Format__)
        {
            case '-':
                Flags.LeftAlign = 1;
                (*__Format__)++;
                continue;
            case '+':
                Flags.ShowSign = 1;
                (*__Format__)++;
                continue;
            case ' ':
                Flags.SpacePrefix = 1;
                (*__Format__)++;
                continue;
            case '#':
                Flags.AlternateForm = 1;
                (*__Format__)++;
                continue;
            case '0':
                Flags.ZeroPad = 1;
                (*__Format__)++;
                continue;
            default:
                break;
        }
        break;
    }

    /* Parse width: either number or * for argument */
    if (**__Format__ == '*')
    {
        Flags.Width = __builtin_va_arg(*__Args__, int);
        (*__Format__)++;
    }
    else
    {
        while (**__Format__ >= '0' && **__Format__ <= '9')
        {
            Flags.Width = Flags.Width * 10 + (**__Format__ - '0');
            (*__Format__)++;
        }
    }

    /* Parse precision: . followed by number or * */
    if (**__Format__ == '.')
    {
        Flags.HasPrecision = 1;
        (*__Format__)++;
        if (**__Format__ == '*')
        {
            Flags.Precision = __builtin_va_arg(*__Args__, int);
            (*__Format__)++;
        }
        else
        {
            while (**__Format__ >= '0' && **__Format__ <= '9')
            {
                Flags.Precision = Flags.Precision * 10 + (**__Format__ - '0');
                (*__Format__)++;
            }
        }
    }

    /* Parse length modifiers: hh, h, l, ll, z, t, J */
    switch (**__Format__)
    {
        case 'l':
            (*__Format__)++;
            if (**__Format__ == 'l')
            {
                Flags.Length = 2; /* ll */
                (*__Format__)++;
            }
            else
            {
                Flags.Length = 1; /* l */
            }
            break;
        case 'h':
            (*__Format__)++;
            if (**__Format__ == 'h')
            {
                Flags.Length = -2; /* hh */
                (*__Format__)++;
            }
            else
            {
                Flags.Length = -1; /* h */
            }
            break;
        case 'z':
            Flags.Length = 3;
            (*__Format__)++;
            break;
        case 't':
            Flags.Length = 4;
            (*__Format__)++;
            break;
        case 'J':
            Flags.Length = 5;
            (*__Format__)++;
            break;
    }

    /* Process the conversion specifier */
    switch (**__Format__)
    {
        case 'd':
        case 'I':
            ProcessInteger(__Args__, &Flags, 10, 1);
            break;
        case 'u':
            ProcessInteger(__Args__, &Flags, 10, 0);
            break;
        case 'x':
            ProcessInteger(__Args__, &Flags, 16, 0);
            break;
        case 'X':
            Flags.Length |= 0x80; /* Uppercase flag */
            ProcessInteger(__Args__, &Flags, 16, 0);
            break;
        case 'o':
            ProcessInteger(__Args__, &Flags, 8, 0);
            break;
        case 'b':
            ProcessInteger(__Args__, &Flags, 2, 0);
            break;
        case 's':
            ProcessString(__Args__, &Flags);
            break;
        case 'c':
            ProcessChar(__Args__, &Flags);
            break;
        case 'p':
            ProcessPointer(__Args__, &Flags);
            break;
        case 'N':
            /* Not implemented for security reasons */
            break;
        case 'f':
        case 'F':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
            /* Floating point not implemented in kernel */
            PutPrint("(float)");
            break;
        case '%':
            PutChar('%');
            break;
        default:
            /* Unknown specifier - print as-is */
            PutChar('%');
            PutChar(**__Format__);
            break;
    }
    (*__Format__)++;
}

void
ProcessInteger(__builtin_va_list* __Args__, FormatFlags* __Flags__, int __Base__, int __Signed__)
{
    char     Buffer[64];
    int64_t  Value      = 0;
    uint64_t UValue     = 0;
    int      IsNegative = 0;

    /* Extract value based on length modifier and signedness */
    if (__Signed__)
    {
        switch (__Flags__->Length)
        {
            case -2:
                Value = (signed char)__builtin_va_arg(*__Args__, int);
                break;
            case -1:
                Value = (short)__builtin_va_arg(*__Args__, int);
                break;
            case 0:
                Value = __builtin_va_arg(*__Args__, int);
                break;
            case 1:
                Value = __builtin_va_arg(*__Args__, long);
                break;
            case 2:
                Value = __builtin_va_arg(*__Args__, long long);
                break;
            default:
                Value = __builtin_va_arg(*__Args__, int);
                break;
        }
        if (Value < 0)
        {
            IsNegative = 1;
            UValue     = -Value;
        }
        else
        {
            UValue = Value;
        }
    }
    else
    {
        switch (__Flags__->Length)
        {
            case -2:
                UValue = (unsigned char)__builtin_va_arg(*__Args__, unsigned int);
                break;
            case -1:
                UValue = (unsigned short)__builtin_va_arg(*__Args__, unsigned int);
                break;
            case 0:
                UValue = __builtin_va_arg(*__Args__, unsigned int);
                break;
            case 1:
                UValue = __builtin_va_arg(*__Args__, unsigned long);
                break;
            case 2:
                UValue = __builtin_va_arg(*__Args__, unsigned long long);
                break;
            default:
                UValue = __builtin_va_arg(*__Args__, unsigned int);
                break;
        }
    }

    /* Convert unsigned value to string in specified base */
    UnsignedToStringEx(UValue, Buffer, __Base__, (__Flags__->Length & 0x80) ? 1 : 0);

    /* Apply formatting (padding, prefixes, alignment) */
    FormatOutput(Buffer, __Flags__, IsNegative, __Base__);
}

void
ProcessString(__builtin_va_list* __Args__, FormatFlags* __Flags__)
{
    const char* Str = __builtin_va_arg(*__Args__, const char*);
    if (!Str)
    {
        Str = "(null)";
    }

    int Len = StringLength(Str);
    if (__Flags__->HasPrecision && __Flags__->Precision < Len)
    {
        Len = __Flags__->Precision;
    }

    /* Right-align padding */
    if (!__Flags__->LeftAlign && __Flags__->Width > Len)
    {
        for (int I = 0; I < __Flags__->Width - Len; I++)
        {
            PutChar(' ');
        }
    }

    /* Output string characters */
    for (int I = 0; I < Len; I++)
    {
        PutChar(Str[I]);
    }

    /* Left-align padding */
    if (__Flags__->LeftAlign && __Flags__->Width > Len)
    {
        for (int I = 0; I < __Flags__->Width - Len; I++)
        {
            PutChar(' ');
        }
    }
}

void
ProcessChar(__builtin_va_list* __Args__, FormatFlags* __Flags__)
{
    char Ch = (char)__builtin_va_arg(*__Args__, int);

    /* Right-align padding */
    if (!__Flags__->LeftAlign && __Flags__->Width > 1)
    {
        for (int I = 0; I < __Flags__->Width - 1; I++)
        {
            PutChar(' ');
        }
    }

    PutChar(Ch);

    /* Left-align padding */
    if (__Flags__->LeftAlign && __Flags__->Width > 1)
    {
        for (int I = 0; I < __Flags__->Width - 1; I++)
        {
            PutChar(' ');
        }
    }
}

void
ProcessPointer(__builtin_va_list* __Args__, FormatFlags* __Flags__)
{
    void* Ptr = __builtin_va_arg(*__Args__, void*);
    char  Buffer[32];

    PutPrint("0x");
    UnsignedToStringEx((uintptr_t)Ptr, Buffer, 16, 0);
    PutPrint(Buffer);
}

void
FormatOutput(const char* __Buffer__, FormatFlags* __Flags__, int __IsNegative__, int __Base__)
{
    int  Len       = StringLength(__Buffer__);
    int  PrefixLen = 0;
    char Prefix[4] = {0};

    /* Build sign/space prefix */
    if (__IsNegative__)
    {
        Prefix[PrefixLen++] = '-';
    }
    else if (__Flags__->ShowSign)
    {
        Prefix[PrefixLen++] = '+';
    }
    else if (__Flags__->SpacePrefix)
    {
        Prefix[PrefixLen++] = ' ';
    }

    /* Build alternate form prefix */
    if (__Flags__->AlternateForm)
    {
        if (__Base__ == 16)
        {
            Prefix[PrefixLen++] = '0';
            Prefix[PrefixLen++] = 'x';
        }
        else if (__Base__ == 8 && __Buffer__[0] != '0')
        {
            Prefix[PrefixLen++] = '0';
        }
    }

    int TotalLen = Len + PrefixLen;
    int PadLen   = (__Flags__->Width > TotalLen) ? __Flags__->Width - TotalLen : 0;

    /* Left padding (spaces) */
    if (!__Flags__->LeftAlign && !__Flags__->ZeroPad)
    {
        for (int I = 0; I < PadLen; I++)
        {
            PutChar(' ');
        }
    }

    /* Output prefix */
    for (int I = 0; I < PrefixLen; I++)
    {
        PutChar(Prefix[I]);
    }

    /* Zero padding */
    if (!__Flags__->LeftAlign && __Flags__->ZeroPad)
    {
        for (int I = 0; I < PadLen; I++)
        {
            PutChar('0');
        }
    }

    /* Output the number */
    PutPrint(__Buffer__);

    /* Right padding (spaces) */
    if (__Flags__->LeftAlign)
    {
        for (int I = 0; I < PadLen; I++)
        {
            PutChar(' ');
        }
    }
}

void
UnsignedToStringEx(uint64_t __Value__, char* __Buffer__, int __Base__, int __Uppercase__)
{
    int Iteration = 0;

    if (__Value__ == 0)
    {
        __Buffer__[Iteration++] = '0';
        __Buffer__[Iteration]   = '\0';
        return;
    }

    while (__Value__ != 0)
    {
        int Remainder = __Value__ % __Base__;
        if (Remainder > 9)
        {
            __Buffer__[Iteration++] = (Remainder - 10) + (__Uppercase__ ? 'A' : 'a');
        }
        else
        {
            __Buffer__[Iteration++] = Remainder + '0';
        }
        __Value__ = __Value__ / __Base__;
    }

    __Buffer__[Iteration] = '\0';
    ReverseString(__Buffer__, Iteration);
}

void
PrintInteger(int __Value__, int __Base__, int __Uppercase__)
{
    char Buffer[32];
    IntegerToString(__Value__, Buffer, __Base__);

    if (__Uppercase__)
    {
        for (int Iteration = 0; Buffer[Iteration]; Iteration++)
        {
            if (Buffer[Iteration] >= 'a' && Buffer[Iteration] <= 'f')
            {
                Buffer[Iteration] = Buffer[Iteration] - 'a' + 'A';
            }
        }
    }

    PrintString(Buffer);
}

void
PrintUnsigned(uint32_t __Value__, int __Base__, int __Uppercase__)
{
    char Buffer[32];
    UnsignedToString(__Value__, Buffer, __Base__);

    if (__Uppercase__)
    {
        for (int Iteration = 0; Buffer[Iteration]; Iteration++)
        {
            if (Buffer[Iteration] >= 'a' && Buffer[Iteration] <= 'f')
            {
                Buffer[Iteration] = Buffer[Iteration] - 'a' + 'A';
            }
        }
    }

    PrintString(Buffer);
}

void
PrintString(const char* __String__)
{
    if (__String__ == 0)
    {
        PutPrint("(null)");
        return;
    }
    PutPrint(__String__);
}

void
PrintChar(char __Char__)
{
    PutChar(__Char__);
}

void
PrintPointer(void* __Pointer__)
{
    PutPrint("0x");
    PrintUnsigned((uint32_t)(uintptr_t)__Pointer__, 16, 0);
}

int
StringLength(const char* __String__)
{
    int Length = 0;
    while (__String__[Length])
    {
        Length++;
    }
    return Length;
}

void
ReverseString(char* __String__, int __Length__)
{
    int Start = 0;
    int End   = __Length__ - 1;

    while (Start < End)
    {
        char Temp         = __String__[Start];
        __String__[Start] = __String__[End];
        __String__[End]   = Temp;
        Start++;
        End--;
    }
}

void
IntegerToString(int __Value__, char* __Buffer__, int __Base__)
{
    int Iteration  = 0;
    int IsNegative = 0;

    if (__Value__ == 0)
    {
        __Buffer__[Iteration++] = '0';
        __Buffer__[Iteration]   = '\0';
        return;
    }

    if (__Value__ < 0 && __Base__ == 10)
    {
        IsNegative = 1;
        __Value__  = -__Value__;
    }

    while (__Value__ != 0)
    {
        int Remainder           = __Value__ % __Base__;
        __Buffer__[Iteration++] = (Remainder > 9) ? (Remainder - 10) + 'a' : Remainder + '0';
        __Value__               = __Value__ / __Base__;
    }

    if (IsNegative)
    {
        __Buffer__[Iteration++] = '-';
    }

    __Buffer__[Iteration] = '\0';
    ReverseString(__Buffer__, Iteration);
}

void
UnsignedToString(uint32_t __Value__, char* __Buffer__, int __Base__)
{
    int Iteration = 0;

    if (__Value__ == 0)
    {
        __Buffer__[Iteration++] = '0';
        __Buffer__[Iteration]   = '\0';
        return;
    }

    while (__Value__ != 0)
    {
        int Remainder           = __Value__ % __Base__;
        __Buffer__[Iteration++] = (Remainder > 9) ? (Remainder - 10) + 'a' : Remainder + '0';
        __Value__               = __Value__ / __Base__;
    }

    __Buffer__[Iteration] = '\0';
    ReverseString(__Buffer__, Iteration);
}
