#pragma once

#include <AllTypes.h>
#include <Errnos.h>

void   strcpy(char* __Dest__, const char* __Src__, uint32_t __MaxLen__); /*strcpy*/
void*  memcpy(void* __Dest__, const void* __Src__, size_t __Size__);     /*memcpy*/
void*  memset(void* __Dest__, int __Value__, size_t __Index__);          /*memset*/
int    strcmp(const char* __Str1__, const char* __Str2__);               /*strcmp*/
int    strncmp(const char* __S1__, const char* __S2__, size_t __Size__); /*strncmp*/
size_t strlen(const char* __Str__);                                      /*strlen*/
char*  strrchr(const char* s, int c);                                    /*strrchr*/
char*  strchr(const char* __Str__, int __Idx__);                         /*strchr*/
long   atol(const char* __Str__);                                        /*atol*/
char*  strncpy(char* __Dst__, const char* __Src__, long __Idx__);        /*strncpy*/