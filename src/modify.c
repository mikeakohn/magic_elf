/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "modify.h"

// FIXME: This doesn't take care of big endian.

int modify_function(
  const char *filename,
  const char *function_name,
  long file_offset,
  uint64_t ret_value,
  int bits)
{
  FILE *fp = fopen(filename, "rb+");

  fseek(fp, file_offset, SEEK_SET);

  if (bits == 32)
  {
    putc(0xb8, fp);
    putc(ret_value & 0xff, fp);
    putc((ret_value >> 8) & 0xff, fp);
    putc((ret_value >> 16) & 0xff, fp);
    putc((ret_value >> 24) & 0xff, fp);
    putc(0xc3, fp);
  }
    else
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

  fclose(fp);

  printf("Function %s modified to do nothing except return %" PRId64 ".\n",
    function_name, ret_value);

  return 0;
}

static char *regs32[] =
{
  "ebx",
  "ecx",
  "edx",
  "esi",
  "edi",
  "ebp",
  "eax",
  "xds",
  "xes",
  "xfs",
  "xgs",
  "orig_eax",
  "eip",
  "xcs",
  "eflags",
  "esp",
  "xss",
  NULL
};

static char *regs64[] =
{
  "r15",
  "r14",
  "r13",
  "r12",
  "rbp",
  "rbx",
  "r11",
  "r10",
  "r9",
  "r8",
  "rax",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "orig_rax",
  "rip",
  "cs",
  "eflags",
  "rsp",
  "ss",
  "fs_base",
  "gs_base",
  "ds",
  "es",
  "fs",
  "gs",
  NULL
};

int modify_core(
  const char *filename,
  const char *reg,
  long file_offset,
  uint64_t value,
  int bits)
{
  int index;
  int bytes;
  int n;

  if (bits == 32)
  {
    index = 0;

    while(regs32[index] != NULL)
    {
      if (strcasecmp(regs32[index], reg) == 0) { break; }
      index++;
    }

    if (regs32[index] == NULL)
    {
      printf("Could not find register named %s\n", reg);
      return -1;
    }

    file_offset += index * 4;
    bytes = 4;
  }
    else
  {
    index = 0;

    while(regs64[index] != NULL)
    {
      if (strcasecmp(regs64[index], reg) == 0) { break; }
      index++;
    }

    if (regs64[index] == NULL)
    {
      printf("Could not find register named %s\n", reg);
      return -1;
    }

    file_offset += index * 8;
    bytes = 8;
  }

  printf("Modifying %s with 0x%lx\n", reg, value);

  FILE *fp = fopen(filename, "rb+");

  fseek(fp, file_offset, SEEK_SET);

  for (n = 0; n < bytes; n++)
  {
    putc(value & 0xff, fp);
    value = value >> 8;
  }

  fclose(fp);

  return 0;
}

