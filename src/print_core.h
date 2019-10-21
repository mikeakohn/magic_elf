/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license. 

*/

#ifndef MAGIC_ELF_PRINT_CORE_H
#define MAGIC_ELF_PRINT_CORE_H

void print_core_siginfo(elf_info_t *elf_info);
void print_core_regs(elf_info_t *elf_info);
void print_core_prstatus(elf_info_t *elf_info);
void print_core_prpsinfo(elf_info_t *elf_info);
void print_core_mapped_files(elf_info_t *elf_info, int len);

#endif

