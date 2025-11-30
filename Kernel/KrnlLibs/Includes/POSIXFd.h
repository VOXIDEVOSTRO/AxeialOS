#pragma once
#include <AllTypes.h>
#include <DevFS.h>
#include <Sync.h>
#include <VFS.h>

typedef struct PosixFd
{
    long  Fd;
    long  Flags;
    void* Obj;
    long  Refcnt;
    int   IsFile;
    int   IsChar;
    int   IsBlock;
} PosixFd;

typedef struct PosixFdTable
{
    PosixFd* Entries;
    long     Count;
    long     Cap;
    long     StdinFd;
    long     StdoutFd;
    long     StderrFd;
    SpinLock Lock;
} PosixFdTable;

typedef struct Iovec
{
    void*  IovBase;
    size_t IovLen;
} Iovec;

int  PosixFdInit(PosixFdTable* __Tab__, long __Cap__);
int  PosixOpen(PosixFdTable* __Tab__, const char* __Path__, long __Flags__, long __Mode__);
int  PosixClose(PosixFdTable* __Tab__, int __Fd__);
long PosixRead(PosixFdTable* __Tab__, int __Fd__, void* __Buf__, long __Len__);
long PosixWrite(PosixFdTable* __Tab__, int __Fd__, const void* __Buf__, long __Len__);
long PosixLseek(PosixFdTable* __Tab__, int __Fd__, long __Off__, int __Wh__);
int  PosixDup(PosixFdTable* __Tab__, int __Fd__);
int  PosixDup2(PosixFdTable* __Tab__, int __OldFd__, int __NewFd__);
int  PosixPipe(PosixFdTable* __Tab__, int __Pipefd__[2]);
int  PosixFcntl(PosixFdTable* __Tab__, int __Fd__, int __Cmd__, long __Arg__);
int  PosixIoctl(PosixFdTable* __Tab__, int __Fd__, unsigned long __Cmd__, void* __Arg__);
int  PosixAccess(PosixFdTable* __Tab__, const char* __Path__, long __Mode__);
int  PosixStatPath(const char* __Path__, VfsStat* __Out__);
int  PosixFstat(PosixFdTable* __Tab__, int __Fd__, VfsStat* __Out__);
int  PosixMkdir(const char* __Path__, long __Mode__);
int  PosixRmdir(const char* __Path__);
int  PosixUnlink(const char* __Path__);
int  PosixRename(const char* __Old__, const char* __New__);
/*Helpers*/
int __FindFreeFd__(PosixFdTable* __Tab__, int __Start__);

KEXPORT(PosixFdInit)
KEXPORT(PosixOpen)
KEXPORT(PosixClose)
KEXPORT(PosixRead)
KEXPORT(PosixWrite)
KEXPORT(PosixLseek)
KEXPORT(PosixDup)
KEXPORT(PosixDup2)
KEXPORT(PosixPipe)
KEXPORT(PosixFcntl)
KEXPORT(PosixIoctl)
KEXPORT(PosixAccess)
KEXPORT(PosixStatPath)
KEXPORT(PosixFstat)
KEXPORT(PosixMkdir)
KEXPORT(PosixRmdir)
KEXPORT(PosixUnlink)
KEXPORT(PosixRename)