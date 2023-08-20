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
#include <string.h>

#include "Display.h"
#include "Elf.h"
#include "Java.h"
#include "Modify.h"

int main(int argc, char *argv[])
{
  Elf *elf;
  const char *filename = NULL;
  const char *function_name = NULL;
  const char *symbol_name = NULL;
  uint64_t ret_value = 0;
  uint32_t pid = 0;
  uint64_t value = 0;
  const char *reg = NULL;
  bool run_java_extract = false;
  int r;

  printf(
    "\nmagic_elf - Copyright 2009-2023 by Michael Kohn <mike@mikekohn.net>\n"
    "https://www.mikekohn.net/\n"
    "Version: August 20, 2023\n\n");

  if (argc < 2)
  {
    printf(
      "Usage: magic_elf [ options ] <filename.so>\n"
      "    -modify_function <function_name> <retvalue>\n"
      "    -modify_core <pid> <register> <value>\n"
      "    -show <symbol>\n"
      "    -extract_java\n\n");
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

      symbol_name = argv[r + 1];
      r++;
    }
      else
    if (strcmp(argv[r],"-extract_java") == 0)
    {
      run_java_extract = true;
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

  if (filename == nullptr)
  {
    printf("Error: No filename selected.\n");
    exit(-1);
  }

  if (run_java_extract)
  {
    Java::extract(filename);
    exit(0);
  }

  if (reg != NULL)
  {
    int err = Modify::set_core_register_value(filename, reg, value, pid);

    if (err != 0)
    {
      printf("Error: Could not modify register.\n");
    }

    exit(err);
  }

  if (function_name != NULL)
  {
    int err = Modify::modify_function(filename, function_name, ret_value);

    if (err != 0)
    {
      printf("Error: Could not modify function.\n");
    }

    exit(err);
  }

  if (symbol_name != NULL)
  {
    Display::symbol_value(filename, symbol_name);
    exit(0);
  }

  elf = Elf::open_elf(filename);

  if (elf == NULL)
  {
    printf("Couldn't open file or not an elf\n");
    exit(0);
  }

  if (symbol_name == NULL && function_name == NULL)
  {
    elf->print_header();
    elf->print_program_headers();
    elf->print_section_headers();
  }

  delete elf;

  return 0;
}

