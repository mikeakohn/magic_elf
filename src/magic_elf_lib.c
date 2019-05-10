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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

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

  if (elf_info->buffer[4] == 1) /* 32 bit */
  {
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
    if (elf_info->buffer[4] == 1) /* 32 bit */
    {
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

  if (elf_info->buffer[4] == 1) /* 32 bit */
  {
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
        if (elf_info->buffer[4] == 1) /* 32 bit */
        {
          if (len != NULL) { *len = elf_info->get_xword(elf_info, offset + 20); }
          return elf_info->get_offset(elf_info, offset + 16);
        }
          else
        {
          if (len != NULL) { *len=elf_info->get_xword(elf_info, offset + 32); }
          return elf_info->get_offset(elf_info, offset + 24);
        }
      }
    }

    offset += elf_info->e_shentsize;
  }

  return 0;
}

static int set_functs(elf_info_t *elf_info)
{
  // int shdr_offset;
  int e_shstrndx;
  long len;

  if (elf_info->buffer[0] != 0x7f ||
      elf_info->buffer[1] != 'E' ||
      elf_info->buffer[2] != 'L' ||
      elf_info->buffer[3] != 'F')
  { return -1; }

  if (elf_info->buffer[5] == 1) /* Little Endian */
  {
    elf_info->get_half = (void *)get_int16_le;
    elf_info->get_word = (void *)get_int32_le;
    elf_info->read_half = (void *)read_int16_le;
    elf_info->read_word = (void *)read_int32_le;
    elf_info->read_int16 = (void *)read_int16_le;
    elf_info->read_int32 = (void *)read_int32_le;
    elf_info->read_int64 = (void *)read_int64_le;

    if (elf_info->buffer[4] == 1) /* 32 bit */
    {
      elf_info->read_addr = (void *)read_int32_le;
      elf_info->get_addr = (void *)get_int32_le;
    }
      else
    if (elf_info->buffer[4] == 2) /* 64 bit */
    {
      elf_info->read_addr = (void *)read_int64_le;
      elf_info->get_addr = (void *)get_int64_le;
    }
      else
    { return -3; }
  }
    else
  if (elf_info->buffer[5] == 2) /* Big Endian */
  {
    elf_info->get_half = (void *)get_int16_be;
    elf_info->get_word = (void *)get_int32_be;
    elf_info->read_half = (void *)read_int16_be;
    elf_info->read_word = (void *)read_int32_be;
    elf_info->read_int16 = (void *)read_int16_be;
    elf_info->read_int32 = (void *)read_int32_be;
    elf_info->read_int64 = (void *)read_int64_be;

    if (elf_info->buffer[4] == 1) /* 32 bit */
    {
      elf_info->read_addr = (void *)read_int32_be;
      elf_info->get_addr = (void *)get_int32_be;
    }
      else
    if (elf_info->buffer[4] == 2) /* 64 bit */
    {
      elf_info->read_addr = (void *)read_int64_be;
      elf_info->get_addr = (void *)get_int64_be;
    }
      else
    { return -3; }
  }
    else
  { return -2; }

  elf_info->read_offset = elf_info->read_addr;
  elf_info->get_offset = elf_info->get_addr;
  elf_info->read_xword = elf_info->read_addr;
  elf_info->get_xword = elf_info->get_addr;
  elf_info->read_int8 = (void *)read_int8;

  if (elf_info->buffer[4] == 1) /* 32 bit */
  {
    elf_info->e_entry = elf_info->get_addr(elf_info, 8 + 16);
    elf_info->e_phoff = elf_info->get_offset(elf_info, 12 + 16);
    elf_info->e_shoff = elf_info->get_offset(elf_info, 16 + 16);
    elf_info->e_phentsize = elf_info->get_half(elf_info, 26 + 16);
    elf_info->e_phnum = elf_info->get_half(elf_info, 28 + 16);
    elf_info->e_shentsize = elf_info->get_half(elf_info, 30 + 16);
    elf_info->e_shnum = elf_info->get_half(elf_info, 32 + 16);
    e_shstrndx = elf_info->get_half(elf_info, 34 + 16);
    elf_info->str_tbl_offset =
      elf_info->get_offset(elf_info, elf_info->e_shoff + (e_shstrndx * elf_info->e_shentsize) + 16);
  }
    else
  {
    elf_info->e_entry = elf_info->get_addr(elf_info, 8 + 16);
    elf_info->e_phoff = elf_info->get_offset(elf_info, 16 + 16);
    elf_info->e_shoff = elf_info->get_offset(elf_info, 24 + 16);
    elf_info->e_phentsize = elf_info->get_half(elf_info, 38 + 16);
    elf_info->e_phnum = elf_info->get_half(elf_info, 40 + 16);
    elf_info->e_shentsize = elf_info->get_half(elf_info, 42 + 16);
    elf_info->e_shnum = elf_info->get_half(elf_info, 44 + 16);
    e_shstrndx = elf_info->get_half(elf_info, 46 + 16);
    elf_info->str_tbl_offset =
      elf_info->get_offset(elf_info, elf_info->e_shoff + (e_shstrndx * elf_info->e_shentsize) + 24);
  }

  elf_info->str_sym_tbl_offset = find_section_offset(elf_info, SHT_STRTAB, ".strtab", NULL);
  elf_info->sym_tbl_offset = find_section_offset(elf_info, SHT_SYMTAB, NULL, &len);
  elf_info->sym_tbl_len = len;

#if 0
printf("%lx %lx\n", elf_info->sym_tbl_offset, elf_info->str_sym_tbl_offset);
printf("%ld\n\n", elf_info->str_sym_tbl_len);
printf("%lx\n", elf_info->e_entry);
printf("%lx\n", elf_info->e_phoff);
printf("%lx\n", elf_info->e_shoff);
printf("pensize %d\n", elf_info->e_phentsize);
printf("%d\n", elf_info->e_phnum);
printf("sendsize %d\n", elf_info->e_shentsize);
printf("%d\n", elf_info->e_shnum);
printf("%d\n", e_shstrndx);
printf("strings: %lx\n", elf_info->str_tbl_offset);
printf("symbols: %lx\n", elf_info->sym_tbl_offset);
#endif

  return 0;
}

elf_info_t *open_elf(const char *filename)
{
  elf_info_t *elf_info;
  struct stat stat_buf;
  int fd;

  fd = open(filename, O_RDONLY);

  if (fd == -1) { return NULL; }
  fstat(fd, &stat_buf);

  elf_info = (elf_info_t *)malloc(sizeof(elf_info_t));
  memset(elf_info, 0, sizeof(elf_info_t));

#ifdef _WIN32
  close(fd);
  elf_info->fd = CreateFile(filename, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
  elf_info->mem_handle = CreateFileMapping(elf_info->fd, NULL, PAGE_READONLY, 0, stat_buf.st_size, NULL);
  elf_info->buffer = (uint8_t *)MapViewOfFile(elf_info->mem_handle, FILE_MAP_READ, 0, 0, stat_buf.st_size);
#else
  elf_info->fd = fd;
  elf_info->buffer = mmap(0, stat_buf.st_size, PROT_EXEC|PROT_READ, MAP_SHARED, fd, 0);
#endif

  //elf_info->buffer = mmap(NULL, stat_buf.st_size, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, fd, 0);
  //elf_info->buffer = mmap(NULL, stat_buf.st_size, PROT_EXEC|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, fd, 0);

  if (set_functs(elf_info) != 0)
  {
    close_elf(&elf_info);
    return 0;
  }

  return elf_info;
}

elf_info_t *open_elf_from_mem(void *mem_ptr)
{
  elf_info_t *elf_info;

  elf_info = (elf_info_t *)malloc(sizeof(elf_info_t));
  memset(elf_info, 0, sizeof(elf_info_t));

  elf_info->buffer = mem_ptr;

  if (set_functs(elf_info) != 0)
  {
    close_elf(&elf_info);
    return 0;
  }

  return elf_info;
}

void close_elf(elf_info_t **elf_info)
{
  if ((*elf_info)->fd != 0)
  {
#ifdef _WIN32
    UnmapViewOfFile((*elf_info)->mem);
    CloseHandle((*elf_info)->mem_handle);
    CloseHandle((*elf_info)->fd);
#else
    munmap((*elf_info)->buffer, (*elf_info)->buffer_len);
    close((*elf_info)->fd);
#endif
  }

  free(*elf_info);
  *elf_info = NULL;
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

