/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "file_io.h"
#include "magic_elf.h"

void *find_symbol_address(elf_info_t *elf_info, const char *symbol_name)
{
  unsigned long offset, offset_end;
  unsigned int t;

  offset = elf_info->sym_tbl_offset;
  offset_end = offset+elf_info->sym_tbl_len;

/*
printf("offset=%lx\n",elf_info->str_sym_tbl_offset);
printf("offset=%lx\n",elf_info->str_tbl_offset);
*/

  if (elf_info->buffer[4] == 1)
  {
    // 32 bit.
    while(offset < offset_end)
    {
      t = elf_info->get_word(elf_info, offset);

      if (t != 0 && strcmp(symbol_name, (char *)elf_info->buffer + elf_info->str_sym_tbl_offset + t) == 0)
      {
        return elf_info->buffer + elf_info->get_addr(elf_info,offset + 4);
      }

      offset += 16;
    }
  }
    else
  {
    while(offset < offset_end)
    {
      t = elf_info->get_word(elf_info, offset);

      if (t != 0 && strcmp(symbol_name, (char *)elf_info->buffer + elf_info->str_sym_tbl_offset + t) == 0)
      {
        return elf_info->buffer + elf_info->get_addr(elf_info, offset + 8);
      }

      offset += 24;
    }
  }

  return NULL;
}

long address_to_offset(elf_info_t *elf_info, long address)
{
  unsigned long offset = elf_info->e_shoff;
  unsigned long sh_address;
  unsigned long sh_size;
  int count;

  for (count = 0; count < elf_info->e_shnum; count++)
  {
    if (elf_info->buffer[4] == 1)
    {
      // 32 bit.
      sh_address = elf_info->get_addr(elf_info, offset + 12);
      sh_size = elf_info->get_addr(elf_info, offset + 20);
      if (address >= sh_address && address < sh_address+sh_size)
      {
        return elf_info->get_offset(elf_info, offset + 16) + (address - sh_address);
      }
    }
      else
    {
      sh_address = elf_info->get_addr(elf_info, offset + 16);
      sh_size = elf_info->get_addr(elf_info, offset + 32);
      if (address >= sh_address && address < sh_address + sh_size)
      {
        return elf_info->get_offset(elf_info, offset + 24) + (address - sh_address);
      }
    }

    offset += elf_info->e_shentsize;
  }

  return -1;
}

long find_symbol_offset(elf_info_t *elf_info, const char *symbol_name)
{
  unsigned long offset, offset_end;
  unsigned int t;

  offset = elf_info->sym_tbl_offset;
  offset_end = offset + elf_info->sym_tbl_len;

  if (elf_info->buffer[4] == 1)
  {
    // 32 bit.
    while(offset < offset_end)
    {
      t = elf_info->get_word(elf_info, offset);

      if (t != 0 && strcmp(symbol_name, (char *)elf_info->buffer + elf_info->str_sym_tbl_offset + t) == 0)
      {
        return address_to_offset(elf_info, elf_info->get_addr(elf_info, offset + 4));
      }
      offset += 16;
    }
  }
    else
  {
    while(offset < offset_end)
    {
      t = elf_info->get_word(elf_info, offset);

      if (t != 0 && strcmp(symbol_name, (char *)elf_info->buffer + elf_info->str_sym_tbl_offset + t)==0)
      {
        return address_to_offset(elf_info, elf_info->get_addr(elf_info, offset + 8));
      }

      offset += 24;
    }
  }

  return -1;
}

unsigned long find_section_offset(
  elf_info_t *elf_info,
  int section,
  const char *sec_name,
  long *len)
{
  unsigned long offset;
  int count;
  int t;

  if (len != NULL) { *len = 0; }
  offset = elf_info->e_shoff;

  for (count = 0; count < elf_info->e_shnum; count++)
  {
    if (elf_info->get_word(elf_info, offset + 4) == section)
    {
      t = elf_info->get_word(elf_info, offset);

      if (sec_name == NULL || (t != 0 && strcmp(sec_name, (char *)elf_info->buffer + elf_info->str_tbl_offset + t) == 0))
      {
        if (elf_info->buffer[4] == 1)
        {
          // 32 bit.
          if (len != NULL)
          {
            *len = elf_info->get_xword(elf_info, offset + 20);
          }

          return elf_info->get_offset(elf_info, offset + 16);
        }
          else
        {
          if (len != NULL)
          {
            *len=elf_info->get_xword(elf_info, offset + 32);
          }

          return elf_info->get_offset(elf_info, offset + 24);
        }
      }
    }

    offset += elf_info->e_shentsize;
  }

  return 0;
}

#if 0
const char *get_elf_string(elf_info_t *elf_info, int index)
{
  int i;
  char *s;
  static const char *oops="\?\?\?";

  i = 1;
  s = (char *)elf_info->buffer+elf_info->str_tbl_offset;

  if (index == 0) return s;

  s++;

  while(i != index)
  {
    while(*s != 0) s++;
    s++;
    i++;

    if (*s == 0)
    {
      return oops;
    }
  }

  return s;
}
#endif

