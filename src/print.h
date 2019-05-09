/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license. 

*/

#ifndef MAGIC_ELF_PRINT_H
#define MAGIC_ELF_PRINT_H

void print_elf_header(elf_info_t *elf_info);
void print_elf_program_headers(elf_info_t *elf_info);
void print_elf_section_headers(elf_info_t *elf_info);

#endif

