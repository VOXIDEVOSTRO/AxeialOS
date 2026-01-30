#pragma once

#include <AllTypes.h>
#include <Errnos.h>
#include <KExports.h>
#include <VFS.h>

/* Device types */
typedef enum DevType
{
    DevChar,
    DevBlock

} DevType;

/* Char ops */
typedef struct CharDevOps
{
    int (*Open)(void* __DevCtx__);
    int (*Close)(void* __DevCtx__);
    long (*Read)(void* __DevCtx__, void* __Buf__, long __Len__);
    long (*Write)(void* __DevCtx__, const void* __Buf__, long __Len__);
    int (*Ioctl)(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__);

} CharDevOps;

/* Block ops */
typedef struct BlockDevOps
{
    int (*Open)(void* __DevCtx__);
    int (*Close)(void* __DevCtx__);
    long (*ReadBlocks)(void* __DevCtx__, uint64_t __Lba__, void* __Buf__, long __Count__);
    long (*WriteBlocks)(void* __DevCtx__, uint64_t __Lba__, const void* __Buf__, long __Count__);
    int (*Ioctl)(void* __DevCtx__, unsigned long __Cmd__, void* __Arg__);
    long BlockSize; /* bytes per block */

} BlockDevOps;

/* Device entry (immutable after publish) */
typedef struct DeviceEntry
{
    const char* Name; /* owned string */
    DevType     Type;
    uint32_t    Major;
    uint32_t    Minor;
    void*       Context;
    union
    {
        CharDevOps  C;
        BlockDevOps B;

    } Ops;

} DeviceEntry;

/* File private context */
typedef struct DevFsFileCtx
{
    const DeviceEntry*   Dev;
    atomic_uint_fast64_t Lba;    /* block cursor */
    atomic_long          Offset; /* byte offset within block or stream */

} DevFsFileCtx;

/* Public API */
int         DevFsInit(void);
int         DevFsRegister(void);
Superblock* DevFsMountImpl(const char* __Dev__, const char* __Opts__);

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

/* Optional helpers */
int CharMakeName(char* __Out__, long __Cap__, const char* __Prefix__, long __Index__);
int CharMakeSubName(char* __Out__, long __Cap__, const char* __Base__, long __SubIndex__);

KEXPORT(DevFsRegisterCharDevice);
KEXPORT(DevFsRegisterBlockDevice);
KEXPORT(DevFsUnregisterDevice);
KEXPORT(DevFsRegisterSeedDevices);