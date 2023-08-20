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

#include "Elf32.h"

Elf32::Elf32()
{
  bitwidth = 32;
}

Elf32::~Elf32()
{
}

void Elf32::compute_string_table_offset()
{
  string_table_offset =
    get_offset(header.e_shoff + (header.e_shstrndx * header.e_shentsize) + 16);
}

int Elf32::read_program(Program &program)
{
  program.p_type   = read_word();
  program.p_offset = read_offset();
  program.p_vaddr  = read_addr();
  program.p_paddr  = read_addr();
  program.p_filesz = read_word();
  program.p_memsz  = read_word();
  program.p_flags  = read_word();
  program.p_align  = read_word();

  return 0;
}

int Elf32::read_section(Section &section)
{
  section.sh_name      = read_word();
  section.sh_type      = read_word();
  section.sh_flags     = read_word();
  section.sh_addr      = read_addr();
  section.sh_offset    = read_offset();
  section.sh_size      = read_word();
  section.sh_link      = read_word();
  section.sh_info      = read_word();
  section.sh_addralign = read_word();
  section.sh_entsize   = read_word();

  return 0;
}

int Elf32::read_symbol(Symbol &symbol)
{
  symbol.st_name  = read_word();
  symbol.st_value = read_addr();
  symbol.st_size  = read_word();
  symbol.st_info  = read_int8();
  symbol.st_other = read_int8();
  symbol.st_shndx = read_half();

  return 0;
}

void Elf32::print_program(Program &program)
{
  printf("  p_type: %d (%s)\n", program.p_type, program.get_header_type());
  printf("p_offset: 0x%lx\n", program.p_offset);
  printf(" p_vaddr: 0x%lx\n", program.p_vaddr);
  printf(" p_paddr: 0x%lx\n", program.p_paddr);
  printf("p_filesz: %" PRId64 "\n", program.p_filesz);
  printf(" p_memsz: %" PRId64 "\n", program.p_memsz);
  printf(" p_flags: %d %s%s%s\n", program.p_flags, program.get_flags_type(),
    program.is_maskos()   ? " MASKOS"   : "",
    program.is_maskproc() ? " MASKPROC" : "");
  printf(" p_align: %" PRId64 "\n\n", program.p_align);
}

void Elf32::print_core_mapped_files(int desccz)
{
  push_ptr();

  const char *filename = (char *)buffer + file_ptr;
  long count = read_offset();
  int n;

  printf("            count: %ld\n", count);
  printf("        page size: %ld\n", read_offset());

  printf("            Page Offset   Start    End\n");
  filename += 4 * 2 + (count * 4 * 3);

  for (n = 0; n < count; n++)
  {
     uint32_t page_offset = read_int32();
     uint32_t start = read_int32();
     uint32_t end = read_int32();
     printf("            %08x %08x %08x\n", start, end, page_offset);
     printf("            %s\n\n", filename);
     filename += strlen(filename) + 1;
  }

  pop_ptr();
}

void Elf32::print_section_relocation(
  int sh_offset,
  int sh_size,
  int symtab_offset,
  int strtab_offset)
{
  const char *relocation_types[] =
  {
    "NONE",
    "386_32",
    "PC32",
    "GOT32",
    "PLT32",
    "COPY",
    "GLOB_DAT",
    "JMP_SLOT",
    "RELATIVE",
    "GOTOFF",
    "GOTPC",
  };

  int n = 0;

  printf("Offset     Type     Symbol\n");

  while (n < sh_size)
  {
    uint32_t offset = get_addr(sh_offset + n);
    uint32_t info = get_word(sh_offset + n + 4);
    int sym = info >> 8;
    int type = info & 0xff;

    printf("0x%08x ", offset);

    if (type > 10)
    {
      printf("%d ", type);
    }
      else
    {
      printf("%-8s ", relocation_types[type]);
    }

    int symbol = get_word(symtab_offset + (sym * 16));
    const char *name = get_string(symbol);

    printf("[%d] %s\n", sym, name);

    n = n + 8;
  }

  printf("\n\n");
}

#if 0
void Elf32::print_section_symbol_table(
  int offset,
  int sh_size,
  int sh_entsize,
  int strtab_offset)
{
  char *strtab = (char *)buffer + strtab_offset;

  for (int n = 0; n < sh_size; n = n + sh_entsize)
  {
    int info = *(buffer + offset + n + 12);
    int bind = info >> 4;
    int type = info & 0xf;

    char bind_string[32];

    switch (bind)
    {
      case 0:  strcpy(bind_string, "LOCAL");  break;
      case 1:  strcpy(bind_string, "GLOBAL"); break;
      case 2:  strcpy(bind_string, "WEAK");   break;
      case 13: strcpy(bind_string, "LOPROC"); break;
      case 15: strcpy(bind_string, "HIPROC"); break;
      default:
        snprintf(bind_string, sizeof(bind_string), "0x%2x", bind);
        break;
    }

    char type_string[32];

    switch (type)
    {
      case 0:  strcpy(type_string, "NOTYPE");  break;
      case 1:  strcpy(type_string, "OBJECT");  break;
      case 2:  strcpy(type_string, "FUNC");    break;
      case 3:  strcpy(type_string, "SECTION"); break;
      case 4:  strcpy(type_string, "FILE");    break;
      case 13: strcpy(type_string, "LOPROC");  break;
      case 15: strcpy(type_string, "HIPROC");  break;
      default:
        snprintf(type_string, sizeof(type_string), "0x%2x", type);
        break;
    }

    strtab_offset = get_word(offset + n);

    printf("   %-30s [%d] 0x%" PRIx64 " %d %s %s %d %d\n",
      strtab + strtab_offset,
      strtab_offset,
      get_addr(offset + n + 4),
      get_word(offset + n + 8),
      bind_string,
      type_string,
      *(buffer + offset + n + 13),
      get_half(offset + n + 14)
    );
  }

  printf("\n\n");
}
#endif

void Elf32::write_reg(uint64_t offset, uint64_t value)
{
  if (is_little_endian)
  {
    buffer[offset + 0] = value & 0xff;
    buffer[offset + 1] = (value >> 8) & 0xff;
    buffer[offset + 2] = (value >> 16) & 0xff;
    buffer[offset + 3] = (value >> 24) & 0xff;
  } 
    else
  { 
    buffer[offset + 0] = (value >> 24) & 0xff;
    buffer[offset + 1] = (value >> 16) & 0xff;
    buffer[offset + 2] = (value >> 8) & 0xff;
    buffer[offset + 3] = value & 0xff;
  }
}

