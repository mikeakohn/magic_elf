/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_SYMBOL_H
#define MAGIC_ELF_SYMBOL_H

#include <stdint.h>

struct Symbol
{
  Symbol()
  {
  }

  ~Symbol()
  {
  }

  const char *get_symbol_binding();
  const char *get_symbol_type();

  uint32_t st_name;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};

#endif

