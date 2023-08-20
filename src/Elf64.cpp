/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "Elf64.h"

Elf64::Elf64()
{
  bitwidth = 64;
}

Elf64::~Elf64()
{
}

void Elf64::compute_string_table_offset()
{
  string_table_offset =
    get_offset(header.e_shoff + (header.e_shstrndx * header.e_shentsize) + 24);
}

int Elf64::read_program(Program &program)
{
  program.p_type   = read_word();
  program.p_flags  = read_word();
  program.p_offset = read_offset();
  program.p_vaddr  = read_addr();
  program.p_paddr  = read_addr();
  program.p_filesz = read_xword();
  program.p_memsz  = read_xword();
  program.p_align  = read_xword();

  return 0;
}

int Elf64::read_section(Section &section)
{
  section.sh_name      = read_word();
  section.sh_type      = read_word();
  section.sh_flags     = read_xword();
  section.sh_addr      = read_addr();
  section.sh_offset    = read_offset();
  section.sh_size      = read_xword();
  section.sh_link      = read_word();
  section.sh_info      = read_word();
  section.sh_addralign = read_xword();
  section.sh_entsize   = read_xword();

  return 0;
}

int Elf64::read_symbol(Symbol &symbol)
{
  symbol.st_name  = read_word();
  symbol.st_info  = read_int8();
  symbol.st_other = read_int8();
  symbol.st_shndx = read_half();
  symbol.st_value = read_addr();
  symbol.st_size  = read_xword();

  return 0;
}

void Elf64::print_program(Program &program)
{
  printf("  p_type: %d (%s)\n", program.p_type, program.get_header_type());
  printf(" p_flags: %d %s%s%s\n", program.p_flags, program.get_flags_type(),
    program.is_maskos()   ? " MASKOS"   : "",
    program.is_maskproc() ? " MASKPROC" : "");
  printf("p_offset: 0x%" PRIx64 "\n", program.p_offset);
  printf(" p_vaddr: 0x%" PRIx64 "\n", program.p_vaddr);
  printf(" p_paddr: 0x%" PRIx64 "\n", program.p_paddr);
  printf("p_filesz: 0x%" PRIx64 "\n", program.p_filesz);
  printf(" p_memsz: 0x%" PRIx64 "\n", program.p_memsz);
  printf(" p_align: 0x%" PRIx64 "\n\n", program.p_align);
}

void Elf64::print_core_mapped_files(int desccz)
{
  push_ptr();

  char *filename = (char *)buffer + file_ptr;
  long count = read_offset();
  int n;

  printf("            count: %ld\n", count);
  printf("        page size: %ld\n", read_offset());

  printf("            Page Offset      Start            End\n");
  filename += 8 * 2 + (count * 8 *3);

  for (n = 0; n < count; n++)
  {
     uint64_t start = read_int64();
     uint64_t end = read_int64();
     uint64_t page_offset = read_int64();
     printf("            %016" PRIx64 " %016" PRIx64" %016" PRIx64 "\n", page_offset, start, end);
     printf("            %s\n\n", filename);
     filename += strlen(filename) + 1;
  }

  pop_ptr();
}

void Elf64::print_section_relocation(
  int sh_offset,
  int sh_size,
  int symtab_offset,
  int strtab_offset)
{
  int n = 0;

  printf("%12s %12s type\n", "Offset", "Sym");

  while (n < sh_size)
  {
    uint64_t offset = get_addr(sh_offset + n);
    uint64_t info = get_word(sh_offset + n + 8);
    uint64_t sym = info >> 8;
    int type = info & 0xff;

    printf("0x%08" PRIx64 " 0x%08" PRIx64 " %d\n", offset, sym, type);

    n = n + 16;
  }

  printf("\n\n");
}

void Elf64::write_reg(uint64_t offset, uint64_t value)
{
  if (is_little_endian)
  {
    buffer[offset + 0] = value & 0xff;
    buffer[offset + 1] = (value >> 8) & 0xff;
    buffer[offset + 2] = (value >> 16) & 0xff;
    buffer[offset + 3] = (value >> 24) & 0xff;
    buffer[offset + 4] = (value >> 32) & 0xff;
    buffer[offset + 5] = (value >> 40) & 0xff;
    buffer[offset + 6] = (value >> 48) & 0xff;
    buffer[offset + 7] = (value >> 56) & 0xff;
  }
    else
  {
    buffer[offset + 0] = (value >> 56) & 0xff;
    buffer[offset + 1] = (value >> 48) & 0xff;
    buffer[offset + 2] = (value >> 40) & 0xff;
    buffer[offset + 3] = (value >> 32) & 0xff;
    buffer[offset + 4] = (value >> 24) & 0xff;
    buffer[offset + 5] = (value >> 16) & 0xff;
    buffer[offset + 6] = (value >> 8) & 0xff;
    buffer[offset + 7] = value & 0xff;
  }
}

