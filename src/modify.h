/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2022 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license. 

*/

#ifndef MAGIC_ELF_MODIFY_H
#define MAGIC_ELF_MODIFY_H

#include <stdint.h>

#include "magic_elf.h"

int modify_function(
  const char *filename,
  const char *function_name,
  long file_offset,
  uint64_t ret_value,
  int bits);

int modify_core(
  const char *filename,
  const char *reg,
  long file_offset,
  uint64_t value,
  int bits);

#endif

