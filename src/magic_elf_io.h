/*

magic_elf - The ELF file format analyzer.

Copyright 2009-2017 - Michael Kohn (mike@mikekohn.net)
http://www.mikekohn.net/

This program falls under the BSD license. 

*/

#ifndef MAGIC_ELF_IO_H
#define MAGIC_ELF_IO_H

#include <stdint.h>

#include "magic_elf.h"

/* One little, two little, three little endians */

#define ELF_ULONG uint64_t

#define GET_BIG_ENDIAN16(a,b) (a[b]<<8)|(a[b+1]);
#define GET_BIG_ENDIAN32(a,b) (a[b]<<24)|(a[b+1]<<16)|(a[b+2]<<8)|(a[b+3]);
#define GET_BIG_ENDIAN64(a,b) ((ELF_ULONG)a[b]<<56)| \
                              ((ELF_ULONG)a[b+1]<<48)| \
                              ((ELF_ULONG)a[b+2]<<40)| \
                              ((ELF_ULONG)a[b+3]<<32)| \
                              ((ELF_ULONG)a[b+4]<<24)| \
                              ((ELF_ULONG)a[b+5]<<16)| \
                              ((ELF_ULONG)a[b+6]<<8)| \
                              ((ELF_ULONG)a[b+7])
#define GET_LITTLE_ENDIAN16(a,b) (a[b+1]<<8)|(a[b]);
#define GET_LITTLE_ENDIAN32(a,b) (a[b+3]<<24)|(a[b+2]<<16)|(a[b+1]<<8)|(a[b]);
#define GET_LITTLE_ENDIAN64(a,b) ((ELF_ULONG)a[b+7]<<56)| \
                                 ((ELF_ULONG)a[b+6]<<48)| \
                                 ((ELF_ULONG)a[b+5]<<40)| \
                                 ((ELF_ULONG)a[b+4]<<32)| \
                                 ((ELF_ULONG)a[b+3]<<24)| \
                                 ((ELF_ULONG)a[b+2]<<16)| \
                                 ((ELF_ULONG)a[b+1]<<8)| \
                                 ((ELF_ULONG)a[b]);

uint16_t get_int16_be(elf_info_t *elf_info, long offset);
uint32_t get_int32_be(elf_info_t *elf_info, long offset);
uint64_t get_int64_be(elf_info_t *elf_info, long offset);
uint16_t get_int16_le(elf_info_t *elf_info, long offset);
uint32_t get_int32_le(elf_info_t *elf_info, long offset);
uint64_t get_int64_le(elf_info_t *elf_info, long offset);
uint16_t read_int16_be(elf_info_t *elf_info);
uint32_t read_int32_be(elf_info_t *elf_info);
uint64_t read_int64_be(elf_info_t *elf_info);
uint16_t read_int16_le(elf_info_t *elf_info);
uint32_t read_int32_le(elf_info_t *elf_info);
uint64_t read_int64_le(elf_info_t *elf_info);
uint8_t read_int8(elf_info_t *elf_info);

#endif


