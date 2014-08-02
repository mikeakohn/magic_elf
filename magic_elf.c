/*

 magic_elf - The ELF file format analyzer.

 Copyright 2009-2014 - Michael Kohn (mike@mikekohn.net)
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
#include "magic_elf_print.h"

int main(int argc, char *argv[])
{
  elf_info_t *elf_info;
  char *filename = NULL;
  char *function_name = NULL;
  char *symbol_name = NULL;
  uint64_t ret_value = 0;
  long file_offset = 0;
  int bits = 0;
  int r;

  printf("\nmagic_elf - Copyright 2009-2014 by Michael Kohn <mike@mikekohn.net>\n");
  printf("http://www.mikekohn.net/\n");
  printf("Version: February 2, 2014\n\n");

  if (argc<2)
  {
    printf("Usage: magic_elf [ options ] <filename.so>\n");
    printf("    -modify <function_name> <retvalue>\n");
    printf("    -show <symbol>\n\n");
    exit(0);
  }

  for (r = 1; r < argc; r++)
  {
    if (strcmp(argv[r],"-modify") == 0)
    {
      if (r + 2 >= argc)
      { printf("Error: -modify requires 2 arguments\n"); exit(1); }

      function_name = argv[r + 1];
      ret_value = atol(argv[r + 2]);
      r += 2;
    }
      else
    if (strcmp(argv[r],"-show") == 0)
    {
      if (r + 1 >= argc)
      { printf("Error: -show requires 1 arguments\n"); exit(1); }

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
  if (elf_info == 0)
  {
    printf("Couldn't open file or not an elf\n");
    exit(0);
  }


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

    if (elf_info->buffer[4] == 1)
    { bits = 32; }
      else
    if (elf_info->buffer[4] == 2)
    { bits = 64; }
  }

  if (symbol_name != NULL)
  {
    file_offset=find_symbol_offset(elf_info,symbol_name);
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

  /* printf("offset=%ld\n", file_offset); */

  close_elf(&elf_info);

  if (function_name != NULL)
  {
    FILE *fp = fopen(filename, "rb+");
    fseek(fp, file_offset, SEEK_SET);
    if (bits == 64)
    {
      putc(0x48, fp);
      putc(0xb8, fp);
      putc(ret_value & 0xff, fp);
      putc((ret_value >> 8) & 0xff, fp);
      putc((ret_value >> 16) & 0xff, fp);
      putc((ret_value >> 24) & 0xff, fp);
      putc((ret_value >> 32) & 0xff, fp);
      putc((ret_value >> 40) & 0xff, fp);
      putc((ret_value >> 48) & 0xff, fp);
      putc((ret_value >> 56) & 0xff, fp);
      putc(0xc3, fp);
    }
      else
    if (bits == 32)
    {
      putc(0xb8, fp);
      putc(ret_value & 0xff, fp);
      putc((ret_value >> 8) & 0xff, fp);
      putc((ret_value >> 16) & 0xff, fp);
      putc((ret_value >> 24) & 0xff, fp);
      putc(0xc3, fp);
    }
    fclose(fp);

    printf("Function %s modified to do nothing except return %" PRId64 ".\n", function_name, ret_value);
  }

  return 0;
}


