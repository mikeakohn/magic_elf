/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "file_io.h"
#include "magic_elf.h"
//#include "print_program_headers.h"

static int find_program_header(elf_info_t *elf_info, uint64_t address)
{
  int count;
  int program_header = -1;
  long marker = elf_info->file_ptr;

  //uint32_t p_type;
  //uint32_t p_flags;
  //uint64_t p_offset;
  uint64_t p_vaddr;
  //uint64_t p_paddr;
  //uint64_t p_filesz;
  uint64_t p_memsz;

  for(count = 0; count < elf_info->e_phnum; count++)
  {
    elf_info->file_ptr = elf_info->e_phoff + (elf_info->e_phentsize * count);

    if (elf_info->bitwidth == 32)
    {
      elf_info->read_word(elf_info); // p_type
      elf_info->read_offset(elf_info); // p_offset
      p_vaddr = elf_info->read_addr(elf_info);
      elf_info->read_addr(elf_info); // p_addr
      elf_info->read_word(elf_info); // p_filesz
      p_memsz = elf_info->read_word(elf_info);
    }
    else
    {
      elf_info->read_word(elf_info); // p_type
      elf_info->read_word(elf_info); // p_flags
      elf_info->read_offset(elf_info); // p_offset
      p_vaddr = elf_info->read_addr(elf_info);
      elf_info->read_addr(elf_info); // p_addr
      elf_info->read_xword(elf_info); // p_filesz
      p_memsz = elf_info->read_xword(elf_info);
    }

    //printf("%d] %lx %lx %lx\n", count, address, p_vaddr, p_memsz);
    if (address >= p_vaddr && address < p_vaddr + p_memsz)
    {
      program_header = count;
      break;
    }
  }

  elf_info->file_ptr = marker;

  return program_header;
}

void print_core_siginfo(elf_info_t *elf_info)
{
  long marker = elf_info->file_ptr;
  printf("        signal_number: %d\n", elf_info->read_int32(elf_info));
  printf("           extra_code: %d\n", elf_info->read_int32(elf_info));
  printf("                errno: %d\n", elf_info->read_int32(elf_info));
  elf_info->file_ptr = marker;
}

#if 0
void print_core_regs(elf_info_t *elf_info)
{
  long marker = elf_info->file_ptr;
    printf("      R15: %016lx  R14: %016lx   R13: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("      R12: %016lx  RBP: %016lx   RBX: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("      R11: %016lx  R10: %016lx    R9: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("       R8: %016lx  RAX: %016lx   RCX: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("      RDX: %016lx  RSI: %016lx   RDI: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf(" ORIG_RAX: %016lx  RIP: %016lx    CS: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("   EFLAGS: %016lx  RSP: %016lx    SS: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("  FS_BASE: %016lx GS_BASE: %016lx    DS: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
    printf("       ES: %016lx   FS: %016lx    GS: %016lx\n",
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info),
      (uint64_t)elf_info->read_int64(elf_info));
  elf_info->file_ptr = marker;
}
#endif

void print_core_prstatus(elf_info_t *elf_info)
{
  long marker = elf_info->file_ptr;
  uint64_t tv_sec;
  uint64_t tv_usec;

  printf("        signal_number: %d\n", elf_info->read_int32(elf_info));
  printf("           extra_code: %d\n", elf_info->read_int32(elf_info));
  printf("                errno: %d\n", elf_info->read_int32(elf_info));
  printf("               cursig: %d\n", elf_info->read_int16(elf_info));
  // FIXME - only 64 bit
  elf_info->file_ptr += 2;
  printf("              sigpend: %ld\n", elf_info->read_offset(elf_info));
  printf("              sighold: %ld\n", elf_info->read_offset(elf_info));

  int pid = elf_info->read_int32(elf_info);

  printf("                  pid: %d\n", pid);
  printf("                 ppid: %d\n", elf_info->read_int32(elf_info));
  printf("                 pgrp: %d\n", elf_info->read_int32(elf_info));
  printf("                 psid: %d\n", elf_info->read_int32(elf_info));

  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf("            user time: %" PRId64 " %" PRId64 "\n", tv_sec, tv_usec);
  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf("          system time: %" PRId64 " %" PRId64 "\n", tv_sec, tv_usec);
  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf(" cumulative user time: %" PRId64 " %" PRId64 "\n", tv_sec, tv_usec);
  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf("  cumulative sys time: %" PRId64 " %" PRId64 "\n", tv_sec, tv_usec);

  //elf_info->file_ptr = marker;

  if (elf_info->e_machine == 0x3) // x86_32
  {
    if (pid == elf_info->core_search.pid)
    {
      elf_info->core_search.file_offset = elf_info->file_ptr;
    }

    uint32_t ebx = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t ecx = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t edx = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t esi = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t edi = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t ebp = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t eax = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t xds = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t xes = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t xfs = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t xgs = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t orig_eax = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t eip = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t xcs = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t eflags = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t esp = (uint32_t)elf_info->read_int32(elf_info);
    uint32_t xss = (uint32_t)elf_info->read_int32(elf_info);

    printf("      EBX: %08x  ECX: %08x    EDX: %08x  ESI: %08x\n",
      ebx, ecx, edx, esi);
    printf("      EDI: %08x  EBP: %08x    EAX: %08x  XDS: %08x\n",
      edi, ebp, eax, xds);
    printf("      XES: %08x  XFS: %08x    XGS: %08x  ORIG_EAX: %08x\n",
      xes, xfs, xgs, orig_eax);
    printf("      EIP: %08x  XCS: %08x EFLAGS: %08x  ESP: %08x\n",
      eip, xcs, eflags, esp);
    printf("      XSS: %08x\n", xss);

    int program_header = find_program_header(elf_info, eip);

    if (program_header != -1)
    {
      printf("     <program header: %d>\n", program_header);
    }
  }
  else if (elf_info->e_machine == 0x3e) // x86_64
  {
    if (pid == elf_info->core_search.pid)
    {
      elf_info->core_search.file_offset = elf_info->file_ptr;
    }

    uint64_t r15 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r14 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r13 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r12 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rbp = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rbx = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r11 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r10 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r9 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t r8 = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rax = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rcx = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rdx = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rsi = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rdi = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t orig_rax = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rip = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t cs = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t eflags = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t rsp = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t ss = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t fs_base = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t gs_base = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t ds = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t es = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t fs = (uint64_t)elf_info->read_int64(elf_info);
    uint64_t gs = (uint64_t)elf_info->read_int64(elf_info);

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

    int program_header = find_program_header(elf_info, rip);

    program_header = find_program_header(elf_info, rip);
    if (program_header != -1)
    {
      printf("     <RIP program header: %d>\n", program_header);
    }
    program_header = find_program_header(elf_info, rsp);
    if (program_header != -1)
    {
      printf("     <RSP program header: %d>\n", program_header);
    }
  }
  else
  {
    elf_info->file_ptr = marker;
    return;
  }

  elf_info->file_ptr = marker;
}

void print_core_prpsinfo(elf_info_t *elf_info)
{
  long marker = elf_info->file_ptr;
  char filename[16];
  char args[80];
  int n;
  printf("            state: %d\n", elf_info->read_int8(elf_info));
  printf("            sname: %d\n", elf_info->read_int8(elf_info));
  printf("           zombie: %d\n", elf_info->read_int8(elf_info));
  printf("             nice: %d\n", elf_info->read_int8(elf_info));
  // FIXME - only 64 bit
  elf_info->file_ptr += 4;
  printf("             flag: %ld\n", elf_info->read_offset(elf_info));
  //printf("             flag: %d\n", elf_info->read_int32(elf_info));
  printf("              uid: %d\n", elf_info->read_int32(elf_info));
  printf("              gid: %d\n", elf_info->read_int32(elf_info));
  printf("              pid: %d\n", elf_info->read_int32(elf_info));
  printf("             ppid: %d\n", elf_info->read_int32(elf_info));
  printf("             pgrp: %d\n", elf_info->read_int32(elf_info));
  printf("              sid: 0x%x\n", elf_info->read_int32(elf_info));
  for (n = 0; n < 16; n++) { filename[n] = elf_info->read_int8(elf_info); }
  printf("         filename: '%.16s'\n", filename);
  for (n = 0; n < 80; n++) { args[n] = elf_info->read_int8(elf_info); }
  printf("             args: '%.80s'\n", args);
  elf_info->file_ptr = marker;
}

void print_core_mapped_files(elf_info_t *elf_info, int len)
{
  long marker = elf_info->file_ptr;
  long count = elf_info->read_offset(elf_info);
  char *filename = (char *)elf_info->buffer + marker;
  int n;

  printf("            count: %ld\n", count);
  printf("        page size: %ld\n", elf_info->read_offset(elf_info));

  if (elf_info->bitwidth == 32)
  {
    printf("            Page Offset   Start    End\n");
    filename += 4 * 2 + (count * 4 *3);

    for (n = 0; n < count; n++)
    {
       uint32_t page_offset = elf_info->read_int32(elf_info);
       uint32_t start = elf_info->read_int32(elf_info);
       uint32_t end = elf_info->read_int32(elf_info);
       printf("            %08x %08x %08x\n", start, end, page_offset);
       printf("            %s\n\n", filename);
       filename += strlen(filename) + 1;
    }
  }
  else
  {
    printf("            Page Offset      Start            End\n");
    filename += 8 * 2 + (count * 8 *3);

    for (n = 0; n < count; n++)
    {
       uint64_t start = elf_info->read_int64(elf_info);
       uint64_t end = elf_info->read_int64(elf_info);
       uint64_t page_offset = elf_info->read_int64(elf_info);
       printf("            %016" PRIx64 " %016" PRIx64" %016" PRIx64 "\n", page_offset, start, end);
       printf("            %s\n\n", filename);
       filename += strlen(filename) + 1;
    }
  }

  elf_info->file_ptr = marker;
}

