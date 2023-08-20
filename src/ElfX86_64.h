/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_ELF_X86_64_H
#define MAGIC_ELF_ELF_X86_64_H

#include <stdint.h>

#include "Elf64.h"

class ElfX86_64 : public Elf64
{
public:
  ElfX86_64();
  virtual ~ElfX86_64();

  virtual void print_registers();

  virtual int get_register_index(const char *name, uint64_t &offset);
};

#endif

