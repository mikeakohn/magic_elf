/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2022 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license. 

*/

#ifndef MAGIC_ELF_H
#define MAGIC_ELF_H

#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "elf_info.h"

long address_to_offset(elf_info_t *elf_info, long address);
void *find_symbol_address(elf_info_t *elf_info, const char *symbol_name);
long find_symbol_offset(elf_info_t *elf_info, const char *symbol_name);
unsigned long find_section_offset(elf_info_t *elf_info, int section, const char *sec_name, long *len);

#endif

