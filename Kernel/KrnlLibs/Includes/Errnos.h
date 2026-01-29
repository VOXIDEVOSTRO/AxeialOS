#pragma once

#include <AllTypes.h>

#define SysOkay 0
#define SysErro -1

typedef struct
{
    int ErrCode;
} SysErr;

/*for voids*/
#define SlotError(__PtrError__, __CodeEnum__)                                                      \
    do                                                                                             \
    {                                                                                              \
        if ((__PtrError__) != NULL)                                                                \
        {                                                                                          \
            (__PtrError__)->ErrCode = (__CodeEnum__);                                              \
        }                                                                                          \
    } while (0)

/*For bools or binary returns, syserro and sysokay work too*/

enum ErrCodes
{
    Nothing,

    /*All Codes*/
    NotCanonical,  /*not a valid range, address or value*/
    Limits,        /*not in a certain set limit*/
    Impilict,      /*not supported, not implimented or stubbed function*/
    BadArguments,  /*non-valid argument passed on to the function*/
    TooBig,        /*to big to fit*/
    TooSmall,      /*to small to latch*/
    TooMany,       /*too many or full*/
    TooLess,       /*not valid in maximum range*/
    BadWrite,      /*bad write or no operation for write*/
    BadRead,       /*bad read or no operation for read*/
    NoSuch,        /*not found or not a valid type*/
    Missing,       /*missing a certain thing*/
    Overflow,      /*overflowing*/
    NotInitilized, /*not initilized systems*/
    BadAllocation, /*cannot be allocated*/
    Dangling,      /*not a valid conversion or impilict value*/
    NotRecorded,   /*cannot be measured*/
    NotRooted,     /*could not be resolved from base*/
    BadEntry,      /*a entry thats not valid*/
    NoOperations,  /*no operation, cannot be performed*/
    CannotLookup,  /*could not be found or looked up*/
    Redefined,     /*was redefined somewhere else*/
    BadEntity,     /*not a valid entity in entry*/
    BadReturn,     /*something returned error*/
    Depleted,      /*out of something*/
    BadSystemcall, /*cannot system call*/
    Recursion,     /*measured recursion*/
    Busy,          /*busy things*/
    ErrMAX         /*total errors*/

};

#define Error_TO_Pointer(__Code__) ((void*)(intptr_t)(__Code__))
#define Pointer_TO_Error(__Ptr__)  ((int)(intptr_t)(__Ptr__))
#define Probe_IF_Error(__Ptr__)    ((intptr_t)(__Ptr__) < 0 && (intptr_t)(__Ptr__) >= -ErrMAX)

static const char* ErrStrings[ErrMAX] = {
    "Nothing/NULL/0", "NotCanonical",  "Limits",      "Impilict",  "BadArguments",
    "TooBig",         "TooSmall",      "TooMany",     "TooLess",   "BadWrite",
    "BadRead",        "NoSuch",        "Missing",     "Overflow",  "NotInitilized",
    "BadAllocation",  "Dangling",      "NotRecorded", "NotRooted", "BadEntry",
    "NoOperations",   "CannotLookup",  "Redefined",   "BadEntity", "BadReturn",
    "Depleted",       "BadSystemcall", "Recursion",   "Busy"};

/*useful*/
#define _unused __attribute((unused))

static inline const char*
ErrName(int __EnumIdx__ /*Always negative*/)
{
    if (__EnumIdx__ < 0)
    {
        __EnumIdx__ = -__EnumIdx__;
    }
    if (__EnumIdx__ >= ErrMAX)
    {
        return "BadError";
    }
    return ErrStrings[__EnumIdx__];
}
