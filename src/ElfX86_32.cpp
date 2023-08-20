/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdint.h>
#include <inttypes.h>

#include "ElfX86_32.h"

ElfX86_32::ElfX86_32()
{
}

ElfX86_32::~ElfX86_32()
{
}

void ElfX86_32::print_registers()
{
  uint32_t ebx = (uint32_t)read_int32();
  uint32_t ecx = (uint32_t)read_int32();
  uint32_t edx = (uint32_t)read_int32();
  uint32_t esi = (uint32_t)read_int32();
  uint32_t edi = (uint32_t)read_int32();
  uint32_t ebp = (uint32_t)read_int32();
  uint32_t eax = (uint32_t)read_int32();
  uint32_t xds = (uint32_t)read_int32();
  uint32_t xes = (uint32_t)read_int32();
  uint32_t xfs = (uint32_t)read_int32();
  uint32_t xgs = (uint32_t)read_int32();
  uint32_t orig_eax = (uint32_t)read_int32();
  uint32_t eip = (uint32_t)read_int32();
  uint32_t xcs = (uint32_t)read_int32();
  uint32_t eflags = (uint32_t)read_int32();
  uint32_t esp = (uint32_t)read_int32();
  uint32_t xss = (uint32_t)read_int32();

  printf("      EBX: %08x  ECX: %08x    EDX: %08x  ESI: %08x\n",
    ebx, ecx, edx, esi);
  printf("      EDI: %08x  EBP: %08x    EAX: %08x  XDS: %08x\n",
    edi, ebp, eax, xds);
  printf("      XES: %08x  XFS: %08x    XGS: %08x  ORIG_EAX: %08x\n",
    xes, xfs, xgs, orig_eax);
  printf("      EIP: %08x  XCS: %08x EFLAGS: %08x  ESP: %08x\n",
    eip, xcs, eflags, esp);
  printf("      XSS: %08x\n", xss);

  Program program;
  uint64_t offset;

  int program_index = get_program_header(program, offset, eip);

  if (program_index != -1)
  {
    printf("     <program header: %d>\n", program_index);
  }
}

int ElfX86_32::get_register_index(const char *name, uint64_t &offset)
{
  const char *regs[] =
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

  for (int index = 0; regs[index] != NULL; index++)
  {
    if (strcasecmp(regs[index], name) == 0)
    {
      offset = index * 4;
      return index;
    }
  }

  return -1;
}

