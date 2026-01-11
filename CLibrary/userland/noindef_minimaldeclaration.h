#pragma once

#include "../install/x86_64-elf/include/errno.h"
#include "../install/x86_64-elf/include/stdint.h"
#include "../install/x86_64-elf/include/stdlib.h"
#include "../install/x86_64-elf/include/sys/resource.h"
#include "../install/x86_64-elf/include/sys/select.h"
#include "../install/x86_64-elf/include/sys/stat.h"
#include "../install/x86_64-elf/include/sys/time.h"
#include "../install/x86_64-elf/include/sys/times.h"
#include "../install/x86_64-elf/include/sys/types.h"

/*sys/uio.h*/
struct iovec
{
    void*  iov_base; /* Starting address */
    size_t iov_len;  /* Number of bytes to transfer */
};

/*sys/utsname.h*/
struct utsname
{
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

/*AxeKrnl Kernel Libraries*/

/*Errnos.h*/
enum ErrCodes
{
    Nothing,

    /*All Codes*/
    NotCanonical,  /*not a valid range, address or value*/
    Limits,        /*not in a certain set limit*/
    Impilict,      /*not supported, no implimneted or stubbed function*/
    BadArgs,       /*non valid argument passed on to the function*/
    TooBig,        /*to big to fit*/
    TooSmall,      /*to small to latch*/
    TooMany,       /*too many or full*/
    TooLess,       /*not valid in maximum range*/
    NoWrite,       /*bad write or no operation for write*/
    NoRead,        /*bad read or no operation for read*/
    NoSuch,        /*not found or not a valid type*/
    Missing,       /*missing a certain thing*/
    Overflow,      /*overflowing*/
    NotInit,       /*not initilized systems*/
    BadAlloc,      /*cannot be allocated*/
    Dangling,      /*not a valid conversion or impilict value*/
    NotRecorded,   /*cannot be measured*/
    NotRooted,     /*cannot resolve*/
    BadEntry,      /*a entry thats not valid*/
    NoOperations,  /*no operation, cannot be performed*/
    CannotLookup,  /*cannot be found or looked up*/
    Redefined,     /*was redefined somewhere*/
    BadEntity,     /*not a valid entity in entry*/
    ErrReturn,     /*something returned error*/
    Depleted,      /*out of something*/
    BadSystemcall, /*cannot system call*/
    Recursion,     /*measured recursion*/
    Busy,          /*busy things*/

};
