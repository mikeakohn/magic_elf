/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "file_io.h"
#include "magic_elf.h"
#include "print_core.h"
#include "print_section_headers.h"

static void print_elf_comment(unsigned char *comment, int sh_size)
{
  int n;

  for (n = 0; n < sh_size; n++)
  {
    if (comment[n] >= 32 && comment[n] < 127)
    {
      printf("%c", comment[n]);
    }
      else
    {
      printf("[%02x]", comment[n]);
    }
  }

  printf("\n\n");
}

static void print_elf_symtab_32(
  elf_info_t *elf_info,
  int offset,
  int sh_size,
  int sh_entsize,
  int strtab_offset)
{
  int n;
  char *strtab = (char *)elf_info->buffer + strtab_offset;

  for (n = 0; n < sh_size; n = n + sh_entsize)
  {
    int info = *(elf_info->buffer + offset + n + 12);
    int bind = info >> 4;
    int type = info & 0xf;

    char bind_string[32];

    switch(bind)
    {
      case 0: strcpy(bind_string, "LOCAL"); break;
      case 1: strcpy(bind_string, "GLOBAL"); break;
      case 2: strcpy(bind_string, "WEAK"); break;
      case 13: strcpy(bind_string, "LOPROC"); break;
      case 15: strcpy(bind_string, "HIPROC"); break;
      default: sprintf(bind_string, "0x%2x", bind); break;
    }

    char type_string[32];

    switch(type)
    {
      case 0: strcpy(type_string, "NOTYPE"); break;
      case 1: strcpy(type_string, "OBJECT"); break;
      case 2: strcpy(type_string, "FUNC"); break;
      case 3: strcpy(type_string, "SECTION"); break;
      case 4: strcpy(type_string, "FILE"); break;
      case 13: strcpy(type_string, "LOPROC"); break;
      case 15: strcpy(type_string, "HIPROC"); break;
      default: sprintf(type_string, "0x%2x", type); break;
    }

    strtab_offset = elf_info->get_word(elf_info, offset+n);

    printf("   %-30s [%d] 0x%lx %d %s %s %d %d\n",
      strtab + strtab_offset,
      strtab_offset,
      elf_info->get_addr(elf_info, offset + n + 4),
      elf_info->get_word(elf_info, offset + n + 8),
      bind_string,
      type_string,
      *(elf_info->buffer + offset + n + 13),
      elf_info->get_half(elf_info, offset + n + 14)
    );
  }

  printf("\n\n");
}

static void print_elf_symtab_64(
  elf_info_t *elf_info,
  int offset,
  int sh_size,
  int sh_entsize,
  int strtab_offset)
{
  int n;
  char *strtab = (char *)elf_info->buffer + strtab_offset;
  for (n = 0; n < sh_size; n = n + sh_entsize)
  {
    strtab_offset = elf_info->get_word(elf_info, offset+n);
    printf("%-30s [%d] 0x%lx %ld %d %d %d\n",
      strtab + strtab_offset,
      strtab_offset,
      elf_info->get_addr(elf_info, offset + n + 8),
      elf_info->get_xword(elf_info, offset + n + 16),
      *(elf_info->buffer+offset + n + 4),
      *(elf_info->buffer+offset + n + 5),
      elf_info->get_half(elf_info, offset + n + 6)
    );
  }
  printf("\n\n");
}

static void print_elf_string_table(uint8_t *table, int sh_size)
{
  int index = 0;
  int len = 0;
  int n;

  for (n = 0; n < sh_size; n++)
  {
    if (len == 0) { printf("\n   [%d] %d: ", n, index++); }

    if (table[n] >= 32 && table[n] < 127)
    {
      printf("%c", table[n]);
    }
      else
    {
      if (table[n] == 0) { len = 0; continue; }
      printf("[%02x]", table[n]);
    }

    len++;
  }

  printf("\n\n");
}

static void print_elf_relocation32(
  elf_info_t *elf_info,
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

  while(n < sh_size)
  {
    uint32_t offset = elf_info->get_addr(elf_info, sh_offset + n);
    uint32_t info = elf_info->get_word(elf_info, sh_offset + n + 4);
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

    int symbol = elf_info->get_word(elf_info, symtab_offset + (sym * 16));
    uint8_t *name = elf_info->buffer + strtab_offset + symbol;

    printf("[%d] %s\n", sym, name);

    n = n + 8;
  }

  printf("\n\n");
}

static void print_elf_relocation64(
  elf_info_t *elf_info,
  int sh_offset,
  int sh_size)
{
  int n = 0;

  printf("%12s %12s type\n", "Offset", "Sym");

  while(n < sh_size)
  {
    uint64_t offset = elf_info->get_addr(elf_info, sh_offset + n);
    uint64_t info = elf_info->get_word(elf_info, sh_offset + n + 8);
    uint64_t sym = info >> 8;
    int type = info & 0xff;

    printf("0x%08" PRIx64 " 0x%08" PRIx64 " %d\n", offset, sym, type);

    n = n + 16;
  }

  printf("\n\n");
}

#if 0
static void print_elf_dynamic(elf_info_t *elf_info, int offset, int size)
{
char *dynamic_tag[] = {
  "DT_NULL",
  "DT_NEEDED",
  "DT_PLTRELSZ",
  "DT_PLGOT",
  "DT_HASH",
  "DT_STRTAB",
  "DT_SYMTAB",
  "DT_REALA",
  "DT_REALASZ",
  "DT_REALAENT",
  "DT_STRSZ",
  "DT_SYMENT",
  "DT_INIT",
  "DT_FINI",
  "DT_SONAME",
  "DT_RPATH",
  "DT_SYMBOLIC"
};
unsigned int d_tag;
unsigned int d_un;
int n;

  for (n=0; n<size; n=n+8)
  {
    d_tag=elf_info->get_word(elf_info, offset+n);
    d_un=elf_info->get_word(elf_info, offset+n+4);

    printf("0x%08x ", d_un);

    if (d_tag>16) { printf("??? (%d)\n", d_tag); }
    else { printf("%s\n", dynamic_tag[d_tag]); }
  }
}
#endif

static void print_elf_arm_attrs(unsigned char *attrs, int sh_size)
{
  int n;
  char text[17];
  int ptr;

  ptr = 0;

  for (n = 0; n < sh_size; n++)
  {
    if ((n % 16) == 0)
    {
      if (ptr != 0) { text[ptr] = 0; printf("  %s", text); ptr = 0; }
      printf("\n");
    }
    printf(" %02x", attrs[n]);
    if (attrs[n] >= 48 && attrs[n] < 120) { text[ptr++] = attrs[n]; }
    else { text[ptr++] = '.'; }
  }

  text[ptr] = 0;
  printf("  %s\n\n", text);
  //int pos = 6 + strlen((char *)attrs + 5);

  printf("   Version: %c\n", attrs[0]);
  printf("      Size: %d\n", attrs[1] | (attrs[2] << 8) | (attrs[3] << 16) | (attrs[4] << 24));
  printf("VendorName: %s\n", attrs+5);
  printf("\n");
}

void print_elf_section_headers(elf_info_t *elf_info)
{
  int count;
  int t;
  long i;
  long marker;
  //uint32_t rel_text_offset;
  //uint32_t symtable_offset;

  elf_info->file_ptr = elf_info->e_shoff;

  printf("Elf Section Headers (count=%d)\n\n", elf_info->e_shnum);

  for (count = 0; count<elf_info->e_shnum; count++)
  {
    marker = elf_info->file_ptr+elf_info->e_shentsize;

    printf("Section Header %d (offset=0x%04" PRIx64 ")\n", count, elf_info->file_ptr);
    printf("---------------------------------------------\n");

    t = elf_info->read_word(elf_info);
    printf("     sh_name: %d", t);
    char *section_name = NULL;
    if (t != 0)
    {
      section_name = (char *)(elf_info->buffer + elf_info->str_tbl_offset + t);
      printf(" (%s)\n", section_name);
    }
      else
    { printf("\n"); }

    int sh_type = elf_info->read_word(elf_info);
    printf("     sh_type: %d ", sh_type);

    switch(sh_type)
    {
      case 0: { printf("(SHT_NULL)\n"); break; }
      case 1: { printf("(SHT_PROGBITS)\n"); break; }
      case 2: { printf("(SHT_SYMTAB)\n"); break; }
      case 3: { printf("(SHT_STRTAB)\n"); break; }
      case 4: { printf("(SHT_RELA)\n"); break; }
      case 5: { printf("(SHT_HASH)\n"); break; }
      case 6: { printf("(SHT_DYNAMIC)\n"); break; }
      case 7: { printf("(SHT_NOTE)\n"); break; }
      case 8: { printf("(SHT_NOBITS)\n"); break; }
      case 9: { printf("(SHT_REL)\n"); break; }
      case 10: { printf("(SHT_SHLIB)\n"); break; }
      case 11: { printf("(SHT_DYNSYM)\n"); break; }
      case 14: { printf("(SHT_INIT_ARRAY)\n"); break; }
      case 15: { printf("(SHT_FINI_ARRAY)\n"); break; }
      case 16: { printf("(SHT_PREINIT_ARRAY)\n"); break; }
      case 17: { printf("(SHT_GROUP)\n"); break; }
      case 18: { printf("(SHT_SYMTAB_SHNDX)\n"); break; }
      case 0x60000000: { printf("(SHT_LOOS)\n"); break; }
      case 0x6fffffff: { printf("(SHT_HIOS)\n"); break; }
      case 0x70000000: { printf("(SHT_LOPROC)\n"); break; }
      case 0x7fffffff: { printf("(SHT_HIPROC)\n"); break; }
      case 0x80000000: { printf("(SHT_LOUSER)\n"); break; }
      case 0xffffffff: { printf("(SHT_HIUSER)\n"); break; }
      default: printf("(Unknown)\n");
    }

    i = elf_info->read_xword(elf_info);
    printf("    sh_flags: 0x%lx (", i);

    if ((i & 0x1) != 0) { printf("SHF_WRITE "); }
    if ((i & 0x2) != 0) { printf("SHF_ALLOC "); }
    if ((i & 0x4) != 0) { printf("SHF_EXECINSTR "); }
    if ((i & 0x10) != 0) { printf("SHF_MERGE "); }
    if ((i & 0x20) != 0) { printf("SHF_STRINGS "); }
    if ((i & 0x40) != 0) { printf("SHF_INFO_LINK "); }
    if ((i & 0x80) != 0) { printf("SHF_LINK_ORDER "); }
    if ((i & 0x100) != 0) { printf("SHF_OS_NONCONFORMING "); }
    if ((i & 0x200) != 0) { printf("SHF_GROUP "); }
    if ((i & 0x400) != 0) { printf("SHF_TLS "); }
    if ((i & 0xff00000) != 0) { printf("SHF_MASKOS "); }
    if ((i & 0xf0000000) != 0) { printf("SHF_MASKPROC "); }
    printf(")\n");

    printf("     sh_addr: 0x%lx\n", elf_info->read_addr(elf_info));
    long sh_offset = elf_info->read_offset(elf_info);
    long sh_size = elf_info->read_xword(elf_info);
    printf("   sh_offset: 0x%lx\n", sh_offset);
    printf("     sh_size: %ld\n", sh_size);
    printf("     sh_link: %d\n", elf_info->read_word(elf_info));
    printf("     sh_info: %d\n", elf_info->read_word(elf_info));
    printf("sh_addralign: %ld\n", elf_info->read_xword(elf_info));
    long sh_entsize = elf_info->read_xword(elf_info);
    printf("  sh_entsize: %ld\n", sh_entsize);
    printf("\n");

    if (section_name != NULL)
    {
      if (strcmp(".comment", section_name) == 0)
      {
        print_elf_comment(elf_info->buffer + sh_offset, sh_size);
      }
        else
      if (strcmp(".strtab", section_name) == 0 || sh_type == 3)
      {
        print_elf_string_table(elf_info->buffer+sh_offset, sh_size);
      }
        else
      if (strcmp(".shstrtab", section_name) == 0)
      {
        print_elf_string_table(elf_info->buffer + sh_offset, sh_size);
      }
        else
      if (strcmp(".rel.text", section_name) == 0)
      {
        // Probably should get a size here too :(
        int symtab_offset = find_section_offset(elf_info, SHT_SYMTAB, ".symtab", NULL);
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".strtab", NULL);

        if (elf_info->bitwidth == 32)
        {
          print_elf_relocation32(elf_info, sh_offset, sh_size, symtab_offset, strtab_offset);
        }
          else
        {
          print_elf_relocation64(elf_info, sh_offset, sh_size);
        }
      }
        else
      if (strcmp(".symtab", section_name) == 0)
      {
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".strtab", NULL);
        if (elf_info->bitwidth == 32)
        {
          print_elf_symtab_32(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset);
        }
          else
        if (elf_info->bitwidth == 64)
        {
          print_elf_symtab_64(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset);
        }
      }
        else
      if (strcmp(".dynsym", section_name) == 0)
      {
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".dynstr", NULL);
        if (elf_info->bitwidth == 32)
        {
          print_elf_symtab_32(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset);
        }
          else
        if (elf_info->bitwidth == 64)
        {
          print_elf_symtab_64(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset);
        }
      }
        else
      if (strcmp(".ARM.attributes", section_name) == 0 || sh_type == 3)
      {
        print_elf_arm_attrs(elf_info->buffer + sh_offset, sh_size);
      }
#if 0
        else
      if (strcmp(".dynamic", section_name) == 0)
      {
        print_elf_dynamic(elf_info, sh_offset, sh_size);
      }
#endif
    }

    elf_info->file_ptr = marker;
  }
}

