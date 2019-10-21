/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "elf_info.h"
#include "file_io.h"
#include "set_functions.h"

int set_functions(elf_info_t *elf_info)
{
  // int shdr_offset;
  int e_shstrndx;
  long len;

  if (elf_info->buffer[0] != 0x7f ||
      elf_info->buffer[1] != 'E' ||
      elf_info->buffer[2] != 'L' ||
      elf_info->buffer[3] != 'F')
  {
    return -1;
  }

  if (elf_info->buffer[5] == 1)
  {
    // Little endian.
    elf_info->get_half = (void *)get_int16_le;
    elf_info->get_word = (void *)get_int32_le;
    elf_info->read_half = (void *)read_int16_le;
    elf_info->read_word = (void *)read_int32_le;
    elf_info->read_int16 = (void *)read_int16_le;
    elf_info->read_int32 = (void *)read_int32_le;
    elf_info->read_int64 = (void *)read_int64_le;

    if (elf_info->bitwidth == 32)
    {
      elf_info->read_addr = (void *)read_int32_le;
      elf_info->get_addr = (void *)get_int32_le;
    }
      else
    if (elf_info->bitwidth == 64)
    {
      elf_info->read_addr = (void *)read_int64_le;
      elf_info->get_addr = (void *)get_int64_le;
    }
      else
    {
      return -3;
    }
  }
    else
  if (elf_info->buffer[5] == 2)
  {
    // Big endian
    elf_info->get_half = (void *)get_int16_be;
    elf_info->get_word = (void *)get_int32_be;
    elf_info->read_half = (void *)read_int16_be;
    elf_info->read_word = (void *)read_int32_be;
    elf_info->read_int16 = (void *)read_int16_be;
    elf_info->read_int32 = (void *)read_int32_be;
    elf_info->read_int64 = (void *)read_int64_be;

    if (elf_info->bitwidth == 32)
    {
      elf_info->read_addr = (void *)read_int32_be;
      elf_info->get_addr = (void *)get_int32_be;
    }
      else
    if (elf_info->bitwidth == 64)
    {
      elf_info->read_addr = (void *)read_int64_be;
      elf_info->get_addr = (void *)get_int64_be;
    }
      else
    {
      return -3;
    }
  }
    else
  {
    return -2;
  }

  elf_info->read_offset = elf_info->read_addr;
  elf_info->get_offset = elf_info->get_addr;
  elf_info->read_xword = elf_info->read_addr;
  elf_info->get_xword = elf_info->get_addr;
  elf_info->read_int8 = (void *)read_int8;

  if (elf_info->bitwidth == 32)
  {
    elf_info->e_entry = elf_info->get_addr(elf_info, 8 + 16);
    elf_info->e_phoff = elf_info->get_offset(elf_info, 12 + 16);
    elf_info->e_shoff = elf_info->get_offset(elf_info, 16 + 16);
    elf_info->e_phentsize = elf_info->get_half(elf_info, 26 + 16);
    elf_info->e_phnum = elf_info->get_half(elf_info, 28 + 16);
    elf_info->e_shentsize = elf_info->get_half(elf_info, 30 + 16);
    elf_info->e_shnum = elf_info->get_half(elf_info, 32 + 16);
    e_shstrndx = elf_info->get_half(elf_info, 34 + 16);
    elf_info->str_tbl_offset =
      elf_info->get_offset(elf_info, elf_info->e_shoff + (e_shstrndx * elf_info->e_shentsize) + 16);
  }
    else
  {
    elf_info->e_entry = elf_info->get_addr(elf_info, 8 + 16);
    elf_info->e_phoff = elf_info->get_offset(elf_info, 16 + 16);
    elf_info->e_shoff = elf_info->get_offset(elf_info, 24 + 16);
    elf_info->e_phentsize = elf_info->get_half(elf_info, 38 + 16);
    elf_info->e_phnum = elf_info->get_half(elf_info, 40 + 16);
    elf_info->e_shentsize = elf_info->get_half(elf_info, 42 + 16);
    elf_info->e_shnum = elf_info->get_half(elf_info, 44 + 16);
    e_shstrndx = elf_info->get_half(elf_info, 46 + 16);
    elf_info->str_tbl_offset =
      elf_info->get_offset(elf_info, elf_info->e_shoff + (e_shstrndx * elf_info->e_shentsize) + 24);
  }

  elf_info->str_sym_tbl_offset = find_section_offset(elf_info, SHT_STRTAB, ".strtab", NULL);
  elf_info->sym_tbl_offset = find_section_offset(elf_info, SHT_SYMTAB, NULL, &len);
  elf_info->sym_tbl_len = len;

#if 0
printf("%lx %lx\n", elf_info->sym_tbl_offset, elf_info->str_sym_tbl_offset);
printf("%ld\n\n", elf_info->str_sym_tbl_len);
printf("%lx\n", elf_info->e_entry);
printf("%lx\n", elf_info->e_phoff);
printf("%lx\n", elf_info->e_shoff);
printf("pensize %d\n", elf_info->e_phentsize);
printf("%d\n", elf_info->e_phnum);
printf("sendsize %d\n", elf_info->e_shentsize);
printf("%d\n", elf_info->e_shnum);
printf("%d\n", e_shstrndx);
printf("strings: %lx\n", elf_info->str_tbl_offset);
printf("symbols: %lx\n", elf_info->sym_tbl_offset);
#endif

  return 0;
}

