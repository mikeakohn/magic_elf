/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_MODIFY_H
#define MAGIC_ELF_MODIFY_H

#include <stdint.h>

class Modify
{
public:
  static int modify_function(
    const char *filename,
    const char *function_name,
    uint64_t ret_value);

  static int set_core_register_value(
    const char *filename,
    const char *reg,
    uint64_t value,
    uint32_t pid);

private:
  Modify();
  ~Modify();
};

#endif

