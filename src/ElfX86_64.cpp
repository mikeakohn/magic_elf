/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdint.h>
#include <inttypes.h>

#include "ElfX86_64.h"

ElfX86_64::ElfX86_64()
{
}

ElfX86_64::~ElfX86_64()
{
}

void ElfX86_64::print_registers()
{
  uint64_t r15 = (uint64_t)read_int64();
  uint64_t r14 = (uint64_t)read_int64();
  uint64_t r13 = (uint64_t)read_int64();
  uint64_t r12 = (uint64_t)read_int64();
  uint64_t rbp = (uint64_t)read_int64();
  uint64_t rbx = (uint64_t)read_int64();
  uint64_t r11 = (uint64_t)read_int64();
  uint64_t r10 = (uint64_t)read_int64();
  uint64_t r9 = (uint64_t)read_int64();
  uint64_t r8 = (uint64_t)read_int64();
  uint64_t rax = (uint64_t)read_int64();
  uint64_t rcx = (uint64_t)read_int64();
  uint64_t rdx = (uint64_t)read_int64();
  uint64_t rsi = (uint64_t)read_int64();
  uint64_t rdi = (uint64_t)read_int64();
  uint64_t orig_rax = (uint64_t)read_int64();
  uint64_t rip = (uint64_t)read_int64();
  uint64_t cs = (uint64_t)read_int64();
  uint64_t eflags = (uint64_t)read_int64();
  uint64_t rsp = (uint64_t)read_int64();
  uint64_t ss = (uint64_t)read_int64();
  uint64_t fs_base = (uint64_t)read_int64();
  uint64_t gs_base = (uint64_t)read_int64();
  uint64_t ds = (uint64_t)read_int64();
  uint64_t es = (uint64_t)read_int64();
  uint64_t fs = (uint64_t)read_int64();
  uint64_t gs = (uint64_t)read_int64();

  printf("      R15: %016" PRIx64 "     R14: %016" PRIx64 "   R13: %016" PRIx64 "\n",
    r15, r14, r13);
  printf("      R12: %016" PRIx64 "     RBP: %016" PRIx64 "   RBX: %016" PRIx64 "\n",
    r12, rbp, rbx);
  printf("      R11: %016" PRIx64 "     R10: %016" PRIx64 "    R9: %016" PRIx64 "\n",
    r11, r10, r9);
  printf("       R8: %016" PRIx64 "     RAX: %016" PRIx64 "   RCX: %016" PRIx64 "\n",
    r8, rax, rcx);
  printf("      RDX: %016" PRIx64 "     RSI: %016" PRIx64 "   RDI: %016" PRIx64 "\n",
    rdx, rsi, rdi);
  printf(" ORIG_RAX: %016" PRIx64 "     RIP: %016" PRIx64 "    CS: %016" PRIx64 "\n",
    orig_rax, rip, cs);
  printf("   EFLAGS: %016" PRIx64 "     RSP: %016" PRIx64 "    SS: %016" PRIx64 "\n",
    eflags, rsp, ss);
  printf("  FS_BASE: %016" PRIx64 " GS_BASE: %016" PRIx64 "    DS: %016" PRIx64 "\n",
    fs_base, gs_base, ds);
  printf("       ES: %016" PRIx64 "      FS: %016" PRIx64 "    GS: %016" PRIx64 "\n",
    es, fs, gs);

  Program program;
  uint64_t offset;
  int program_index;

  program_index = get_program_header(program, offset, rip);

  if (program_index != -1)
  {
    printf("     <RIP program header: %d>\n", program_index);
  }

  program_index = get_program_header(program, offset, rsp);

  if (program_index != -1)
  {
    printf("     <RSP program header: %d>\n", program_index);
  }
}

int ElfX86_64::get_register_index(const char *name, uint64_t &offset)
{
  const char *regs[] =
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

  for (int index = 0; regs[index] != NULL; index++)
  {
    if (strcasecmp(regs[index], name) == 0)
    {
      offset = index * 8;
      return index;
    }
  }

  return -1;
}

