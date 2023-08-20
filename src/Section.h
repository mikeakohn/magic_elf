/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_SECTION_H
#define MAGIC_ELF_SECTION_H

#include <stdint.h>
#include <string>

struct Section
{
  Section()
  {
  }

  ~Section()
  {
  }

  const char *get_section_type();
  std::string get_flags_type();

  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
};

#endif

