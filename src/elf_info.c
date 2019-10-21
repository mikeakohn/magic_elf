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
#include "elf_info.h"
//#include "magic_elf_lib.h"
#include "set_functions.h"

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

  if (set_functions(elf_info) != 0)
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

  if (set_functions(elf_info) != 0)
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

