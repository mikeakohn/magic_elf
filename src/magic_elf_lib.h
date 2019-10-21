/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_MAGIC_ELF_LIB_H
#define MAGIC_ELF_MAGIC_ELF_LIB_H

#include "elf_info.h"

void *find_symbol_address(elf_info_t *elf_info, const char *symbol_name);
long address_to_offset(elf_info_t *elf_info, long address);
long find_symbol_offset(elf_info_t *elf_info, const char *symbol_name);
//const char *get_elf_string(elf_info_t *elf_info, int index)

#endif

