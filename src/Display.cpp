/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "defines.h"
#include "Display.h"
#include "Elf.h"

int Display::symbol_value(const char *filename, const char *symbol_name)
{
  Elf *elf = Elf::open_elf(filename);

  if (elf == nullptr)
  {
    return -1;
  }

  uint64_t file_offset = elf->find_symbol_offset(symbol_name);

  if (file_offset == 0)
  {
    printf("Error: Symbol %s not found.\n", symbol_name);
  }
    else
  {
    uint64_t offset = elf->address_to_offset(elf->get_addr(file_offset));

    printf("%s=%s\n", symbol_name, elf->buffer + offset);
  }

  delete elf;

  return 0;
}

