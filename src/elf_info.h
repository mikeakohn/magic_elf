/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license. 

*/

#ifndef MAGIC_ELF_ELF_INFO_H
#define MAGIC_ELF_ELF_INFO_H

#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#endif

// Here's a crock of SHT.
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_INIT_ARRAY 14
#define SHT_FINI_ARRAY 15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP 17
#define SHT_SYMTAB_SHNDX 18
#define SHT_LOOS 0x60000000
#define SHT_HIOS 0x6fffffff
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff

struct _core_search
{
  int pid;
  long file_offset;
};

typedef struct
{
#ifdef _WIN32
  HANDLE fd;
  HANDLE mem;
  HANDLE mem_handle;
#else
  int fd;
#endif
  uint8_t *buffer;
  int bitwidth;
  long buffer_len;
  struct _core_search core_search;
  uint64_t file_ptr;
  uint16_t (*get_half)(void *elf_info, long offset);
  uint32_t (*get_word)(void *elf_info, long offset);
  unsigned long (*get_addr)(void *elf_info, long offset);
  unsigned long (*get_offset)(void *elf_info, long offset);
  unsigned long (*get_xword)(void *elf_info, long offset);
  uint16_t (*read_half)(void *elf_info);
  uint32_t (*read_word)(void *elf_info);
  unsigned long (*read_addr)(void *elf_info);
  unsigned long (*read_offset)(void *elf_info);
  unsigned long (*read_xword)(void *elf_info);
  uint8_t (*read_int8)(void *elf_info);
  uint16_t (*read_int16)(void *elf_info);
  uint32_t (*read_int32)(void *elf_info);
  uint64_t (*read_int64)(void *elf_info);

  uint16_t e_machine;

  unsigned long e_entry;
  unsigned long e_phoff;
  unsigned long e_shoff;
  unsigned int e_phentsize;
  unsigned int e_phnum;
  unsigned int e_shentsize;
  unsigned int e_shnum;

  unsigned long str_tbl_offset;
  unsigned long sym_tbl_offset;
  unsigned long sym_tbl_len;
  unsigned long str_sym_tbl_offset;
} elf_info_t;

elf_info_t *open_elf(const char *filename);
elf_info_t *open_elf_from_mem(void *mem_ptr);
void close_elf(elf_info_t **elf_info);

#endif

