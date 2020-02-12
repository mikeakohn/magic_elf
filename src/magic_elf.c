/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

  Useful page: http://www.sco.com/developers/gabi/latest/contents.html
               http://www.iecc.com/linker/linker10.html

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "magic_elf.h"
#include "modify.h"
#include "print_elf_header.h"
#include "print_program_headers.h"
#include "print_section_headers.h"

int main(int argc, char *argv[])
{
  elf_info_t *elf_info;
  const char *filename = NULL;
  const char *function_name = NULL;
  const char *symbol_name = NULL;
  uint64_t ret_value = 0;
  long file_offset = 0;
  int bits = 0;
  int pid = 0;
  uint64_t value = 0;
  const char *reg = NULL;
  int r;

  printf(
    "\nmagic_elf - Copyright 2009-2020 by Michael Kohn <mike@mikekohn.net>\n"
    "http://www.mikekohn.net/\n"
    "Version: February 12, 2020\n\n");

  if (argc < 2)
  {
    printf(
      "Usage: magic_elf [ options ] <filename.so>\n"
      "    -modify_function <function_name> <retvalue>\n"
      "    -modify_core <pid> <register> <value>\n"
      "    -show <symbol>\n\n");
    exit(0);
  }

  for (r = 1; r < argc; r++)
  {
    if (strcmp(argv[r],"-modify_function") == 0)
    {
      if (r + 2 >= argc)
      {
        printf("Error: -modify_function requires 2 arguments\n");
        exit(1);
      }

      function_name = argv[r + 1];
      ret_value = atol(argv[r + 2]);
      r += 2;
    }
      else
    if (strcmp(argv[r],"-modify_core") == 0)
    {
      if (r + 2 >= argc)
      {
        printf("Error: -modify_core requires 3 arguments\n");
        exit(1);
      }

      pid = atoi(argv[r + 1]);
      reg = argv[r + 2];
      value = strtol(argv[r + 3], NULL, 0);
      r += 3;
    }
      else
    if (strcmp(argv[r],"-show") == 0)
    {
      if (r + 1 >= argc)
      {
        printf("Error: -show requires 1 arguments\n");
        exit(1);
      }

      symbol_name = argv[r+1];
      r++;
    }
      else
    if (argv[r][0] == '-')
    {
      printf("Unknown option '%s'\n", argv[r]);
      exit(1);
    }
      else
    {
      filename = argv[r];
    }
  }

  elf_info = open_elf(filename);

  if (elf_info == NULL)
  {
    printf("Couldn't open file or not an elf\n");
    exit(0);
  }

  elf_info->core_search.pid = pid;

  if (symbol_name == NULL && function_name == NULL)
  {
    print_elf_header(elf_info);
    print_elf_program_headers(elf_info);
    print_elf_section_headers(elf_info);
  }

  if (function_name != NULL)
  {
    file_offset = find_symbol_offset(elf_info, function_name);

    if (file_offset == -1)
    {
      printf("Error: Can't find function '%s'.\n", function_name);
    }
      else
    {
      bits = 0;
    }

    bits = elf_info->buffer[4] == 1 ? 32 : 64;
  }

  if (symbol_name != NULL)
  {
    file_offset = find_symbol_offset(elf_info,symbol_name);

    if (file_offset == -1)
    {
      printf("Error: Can't find symbol '%s'.\n", symbol_name);
      function_name = NULL;
    }
      else
    {
      printf("%s=%s\n", symbol_name,
         elf_info->buffer + address_to_offset(elf_info, elf_info->get_addr(elf_info, file_offset)));
    }
  }

  if (reg != NULL)
  {
    if (elf_info->core_search.file_offset != 0)
    {
      file_offset = elf_info->core_search.file_offset;
    }
      else
    {
      reg = NULL;

      printf("Could not find pid %d.\n", pid);
    }
  }

  /* printf("offset=%ld\n", file_offset); */

  close_elf(&elf_info);

  if (function_name != NULL)
  {
    modify_function(filename, function_name, file_offset, ret_value, bits);
  }

  if (reg != NULL)
  {
    modify_core(filename, reg, file_offset, value, bits);
  }

  return 0;
}

