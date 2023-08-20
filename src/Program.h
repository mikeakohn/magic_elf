/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_PROGRAM_H
#define MAGIC_ELF_PROGRAM_H

#include <stdint.h>

struct Program
{
  Program()
  {
  }

  ~Program()
  {
  }

  const char *get_header_type();
  const char *get_flags_type();

  bool is_maskos()   { return (p_flags & 0xff0000) == 0xff0000; }
  bool is_maskproc() { return (p_flags & 0xff000000) == 0xff000000; }

  static const char *get_note_type(int type);

  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

#endif

