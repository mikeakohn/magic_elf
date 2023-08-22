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
#include "Elf.h"
#include "Modify.h"

int Modify::modify_function(
  const char *filename,
  const char *function_name,
  uint64_t ret_value)
{
  Elf *elf = Elf::open_elf(filename, true);

  if (elf == nullptr)
  {
    return -1;
  }

  if (! (elf->header.e_machine == EM_X86_32 ||
         elf->header.e_machine == EM_X86_64))
  {
    printf("Error: Unsupported machine type for function modification.\n");
    return -2;
  }

  uint64_t offset = elf->find_symbol_offset(function_name);

  if (offset == 0)
  {
    printf("Error: Function %s not found.\n", function_name);
    delete elf;
    return -1;
  }

  elf->set_writable();

  if (elf->bitwidth == 32)
  {
    elf->buffer[offset + 0] = 0xb8;
    elf->buffer[offset + 1] = ret_value & 0xff;
    elf->buffer[offset + 2] = (ret_value >> 8) & 0xff;
    elf->buffer[offset + 3] = (ret_value >> 16) & 0xff;
    elf->buffer[offset + 4] = (ret_value >> 24) & 0xff;
    elf->buffer[offset + 5] =0xc3;
  }
    else
  {
    elf->buffer[offset + 0] = 0x48;
    elf->buffer[offset + 1] = 0xb8;
    elf->buffer[offset + 2] = ret_value & 0xff;
    elf->buffer[offset + 3] = (ret_value >> 8) & 0xff;
    elf->buffer[offset + 4] = (ret_value >> 16) & 0xff;
    elf->buffer[offset + 5] = (ret_value >> 24) & 0xff;
    elf->buffer[offset + 6] = (ret_value >> 32) & 0xff;
    elf->buffer[offset + 7] = (ret_value >> 40) & 0xff;
    elf->buffer[offset + 8] = (ret_value >> 48) & 0xff;
    elf->buffer[offset + 9] = (ret_value >> 56) & 0xff;
    elf->buffer[offset + 10] = 0xc3;
  }

  elf->set_readonly();

  printf("Function %s modified to do nothing except return %" PRId64 ".\n",
    function_name, ret_value);

  delete elf;

  return 0;
}

int Modify::set_core_register_value(
  const char *filename,
  const char *reg,
  uint64_t value,
  uint32_t pid)
{
  Elf *elf = Elf::open_elf(filename, true);

  if (elf == nullptr)
  {
    return -1;
  }

  uint64_t reg_offset;
  int reg_index = elf->get_register_index(reg, reg_offset);

  if (reg_index < 0)
  {
    printf("Error: Unknown register.\n");
    return -3;
  }

  for (int count = 0; count < elf->get_program_count(); count++)
  {
    Program program;
    elf->read_program(program);

    if (program.p_type == PT_NOTE)
    {
      uint64_t offset = elf->get_core_registers_from_note(program, pid);

      printf("   current_value=0x%" PRIx64 "\n",
        elf->read_reg(offset + reg_offset));

      if (elf->set_writable() != 0)
      {
        printf("Error: File is readonly.\n");
        return -1;
      }

      elf->write_reg(offset + reg_offset, value);
      elf->set_readonly();
      printf("       new_value=0x%" PRIx64 "\n",
        elf->read_reg(offset + reg_offset));

      delete elf;
      return 0;
    }
  }

  delete elf;

  printf("Error: Program section not found.\n");

  return -2;
}

