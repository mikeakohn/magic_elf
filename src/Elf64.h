/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_ELF64_H
#define MAGIC_ELF_ELF64_H

#include <stdint.h>

#include "Elf.h"

class Elf64 : public Elf
{
public:
  Elf64();
  virtual ~Elf64();

  virtual void compute_string_table_offset();

  virtual int read_program(Program &program);
  virtual int read_section(Section &section);
  virtual int read_symbol(Symbol &symbol);

  virtual void print_program(Program &program);
  virtual void print_core_mapped_files(int desccz);

  virtual void print_section_relocation(
    int sh_offset,
    int sh_size,
    int symtab_offset,
    int strtab_offset);

#if 0
  virtual void print_section_symbol_table(
    int offset,
    int sh_size,
    int sh_entsize,
    int strtab_offset);
#endif

  uint64_t read_xword()           { return read_int64(); }
  uint64_t get_xword(long offset) { return read_int64(offset); }

  virtual uint64_t get_addr(long offset)   { return read_int64(offset); }
  virtual uint64_t get_offset(long offset) { return read_int64(offset); }

  virtual uint64_t read_reg(uint64_t offset) { return read_int64(offset); }
  virtual void write_reg(uint64_t offset, uint64_t value);

protected:
  virtual uint64_t read_addr()   { return read_int64(); }
  virtual uint64_t read_offset() { return read_int64(); }

};

#endif

