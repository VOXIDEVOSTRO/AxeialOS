#pragma once

#include <EveryType.h>

typedef enum DevType
{
    DevChar,
    DevBlock

} DevType;

typedef struct CharDevOps
{
    int (*Open)(void* __DevCtx__);
    int (*Close)(void* __DevCtx__);
    long (*Read)(void* __DevCtx__, void* __Buf__, long __Len__);
    long (*Write)(void* __DevCtx__, const void* __Buf__, long __Len__);
    int (*Ioctl)(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__);

} CharDevOps;

typedef struct BlockDevOps
{
    int (*Open)(void* __DevCtx__);
    int (*Close)(void* __DevCtx__);
    long (*ReadBlocks)(void* __DevCtx__, uint64_t __Lba__, void* __Buf__, long __Count__);
    long (*WriteBlocks)(void* __DevCtx__, uint64_t __Lba__, const void* __Buf__, long __Count__);
    int (*Ioctl)(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__);
    long BlockSize; /* bytes per block, e.g., 512 or 4096 */

} BlockDevOps;

typedef struct DeviceEntry
{
    const char* Name;    /* "null", "zero", "tty0", "sda" */
    DevType     Type;    /* DevChar / DevBlock */
    uint32_t    Major;   /* optional major classification */
    uint32_t    Minor;   /* optional minor instance */
    void*       Context; /* driver-private/specific context */
    union
    {
        CharDevOps  C;
        BlockDevOps B;

    } Ops;

} DeviceEntry;

typedef struct DevFsFileCtx
{
    const DeviceEntry* Dev;    /* bound device entry */
    uint64_t           Lba;    /* for block devices: current block cursor */
    long               Offset; /* byte offset within current block for raw streaming */

} DevFsFileCtx;

int DevFsRegisterCharDevice(const char* __Name__,
                            uint32_t    __Major__,
                            uint32_t    __Minor__,
                            CharDevOps  __Ops__,
                            void*       __Context__);
int DevFsRegisterBlockDevice(const char* __Name__,
                             uint32_t    __Major__,
                             uint32_t    __Minor__,
                             BlockDevOps __Ops__,
                             void*       __Context__);
int DevFsUnregisterDevice(const char* __Name__);
int DevFsRegisterSeedDevices(void);
