/*

 magic_elf - The ELF file format analyzer.

 Copyright 2009-2017 - Michael Kohn (mike@mikekohn.net)
 http://www.mikekohn.net/

 This program falls under the BSD license. 

*/

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "magic_elf.h"
#include "magic_elf_io.h"

/* What a waste of memory if this is in the lib */

void print_elf_header(elf_info_t *elf_info)
{
  const char *type_string;
  const char *os_abi;
  const char *machine;
  int t;

  printf("Elf Header\n");
  printf("---------------------------------------------\n");
  printf("    e_ident: ");
  for (t = 0; t < 16; t++)
  {
    printf("%02x ", elf_info->buffer[t]);
  }
  printf("\n");

  printf("             EI_MAGIC=0x7f ELF\n");
  printf("             EI_CLASS=%d ",elf_info->buffer[4]);
  if (elf_info->buffer[4] == 1)
  { printf("(32 bit)\n"); elf_info->bitwidth = 32; }
    else
  if (elf_info->buffer[4] == 2)
  { printf("(64 bit)\n"); elf_info->bitwidth = 64; }
    else
  { printf("(Invalid)\n"); elf_info->bitwidth = 0; }

  printf("             EI_DATA=%d ", elf_info->buffer[5]);
  if (elf_info->buffer[5] == 1)
  { printf("(Little Endian)\n"); }
    else
  if (elf_info->buffer[5] == 2)
  { printf("(Big Endian)\n"); }

  printf("             EI_VERSION=%d\n", elf_info->buffer[6]);

  switch(elf_info->buffer[7])
  {
    case 0: os_abi = "(Unix SysV ABI)"; break;
    case 1: os_abi = "(HP-UX)"; break;
    case 2: os_abi = "(NetBSD)"; break;
    case 6: os_abi = "(Solaris)"; break;
    case 7: os_abi = "(AIX)"; break;
    case 8: os_abi = "(IRIX)"; break;
    case 9: os_abi = "(FreeBSD)"; break;
    case 10: os_abi = "(Tru64)"; break;
    case 11: os_abi = "(Novell Modesto)"; break;
    case 12: os_abi = "(OpenBSD)"; break;
    case 13: os_abi = "(OpenVMS)"; break;
    case 14: os_abi = "(HP Non-Stop Kernel)"; break;
    case 15: os_abi = "(Amiga Research OS)"; break;
    case 255: os_abi = "(Embedded)"; break;
    default: os_abi = "(Unknown)"; break;
  }

  printf("             EI_OSABI=%d %s\n", elf_info->buffer[7], os_abi);
  printf("             EI_ABIVER=%d\n", elf_info->buffer[8]);

  elf_info->file_ptr = 16;

  t = elf_info->read_half(elf_info);
  switch(t)
  {
    case 0: type_string = "(No type)"; break;
    case 1: type_string = "(Relocatable)"; break;
    case 2: type_string = "(Executable)"; break;
    case 3: type_string = "(Shared Object)"; break;
    case 4: type_string = "(Core File)"; break;
    case 0xfe00: type_string = "(OS-specific:ET_LOOS)"; break;
    case 0xfeff: type_string = "(OS-specific:ET_HIOS)"; break;
    case 0xff00: type_string = "(Processor-specific:ET_LOPROC)"; break;
    case 0xffff: type_string = "(Processor-specific:ET_HIPROC)"; break;
    default: type_string = "(\?\?\?)"; break;
  }

  printf("     e_type: %02x %s\n", t, type_string);

  elf_info->e_machine = elf_info->read_half(elf_info);
  switch(elf_info->e_machine)
  {
    case 0: machine = "(None)"; break;
    case 1: machine = "(AT&T WE 32100)"; break;
    case 2: machine = "(SPARC)"; break;
    case 3: machine = "(x86-32)"; break;
    case 4: machine = "(Motorola 68000)"; break;
    case 5: machine = "(Motorola 88000)"; break;
    case 7: machine = "(Intel 80860)"; break;
    case 8: machine = "(MIPS R3000)"; break;
    case 10: machine = "(MIPS R3000 Little-Endian)"; break;
    case 15: machine = "(PA-RISC)"; break;
    case 17: machine = "(Fujitsu VPP500)"; break;
    case 18: machine = "(Enhanced SPARC)"; break;
    case 19: machine = "(Intel 80960)"; break;
    case 20: machine = "(PowerPC)"; break;
    case 21: machine = "(PowerPC 64 bit)"; break;
    case 22: machine = "(IBM System/390)"; break;
    case 23: machine = "(IBM Cell SPU)"; break;
    case 36: machine = "(NEC V800)"; break;
    case 37: machine = "(Fujitsu FR20)"; break;
    case 38: machine = "(TRW RH-32)"; break;
    case 39: machine = "(Motorola RCE)"; break;
    case 40: machine = "(ARM)"; break;
    case 41: machine = "(Alpha)"; break;
    case 42: machine = "(Hitachi SH)"; break;
    case 43: machine = "(Sparc V9)"; break;
    case 44: machine = "(Siemens Tricore)"; break;
    case 45: machine = "(ARC)"; break;
    case 46: machine = "(Hitachi H8/300)"; break;
    case 47: machine = "(Hitachi H8/300H)"; break;
    case 48: machine = "(Hitachi H8S)"; break;
    case 49: machine = "(Hitachi H8/500)"; break;
    case 50: machine = "(Itanium IA-64)"; break;
    case 51: machine = "(MIPS-X)"; break;
    case 52: machine = "(Motorola Coldfire)"; break;
    case 53: machine = "(Motorola M68HC12)"; break;
    case 54: machine = "(Fujitsu MMA)"; break;
    case 55: machine = "(Siemens PCP)"; break;
    case 56: machine = "(Sony nCPU)"; break;
    case 57: machine = "(Denso NDR1)"; break;
    case 58: machine = "(Motorola Star)"; break;
    case 59: machine = "(Toyota ME16)"; break;
    case 60: machine = "(ST ST100)"; break;
    case 61: machine = "(TinyJ)"; break;
    case 62: machine = "(x86-64)"; break;
    case 63: machine = "(Sony DSP)"; break;
    case 64: machine = "(DEC PDP-10)"; break;
    case 65: machine = "(DEC PDP-11)"; break;
    case 66: machine = "(Siemens FX66)"; break;
    case 67: machine = "(ST ST9+)"; break;
    case 68: machine = "(ST ST7)"; break;
    case 69: machine = "(Motorola MC68HC16)"; break;
    case 70: machine = "(Motorola MC68HC11)"; break;
    case 71: machine = "(Motorola MC68HC08)"; break;
    case 72: machine = "(Motorola MC68HC05)"; break;
    case 73: machine = "(Silicon Graphics SVx)"; break;
    case 74: machine = "(ST ST19)"; break;
    case 75: machine = "(Digital VAX)"; break;
    case 76: machine = "(Axis EXTRAX)"; break;
    case 77: machine = "(Infineon Technologies)"; break;
    case 78: machine = "(Element 14)"; break;
    case 79: machine = "(LSI Logic)"; break;
    case 80: machine = "(Donald Knuth's edu)"; break;
    case 81: machine = "(Harvard Uni machine independant)"; break;
    case 82: machine = "(SiTera Prism)"; break;
    case 83: machine = "(Atmel AVR 8bit)"; break;
    case 84: machine = "(Fujitsu FR30)"; break;
    case 85: machine = "(Mitsubishi D10V)"; break;
    case 86: machine = "(Mitsubishi D30V)"; break;
    case 87: machine = "(NEC v850)"; break;
    case 88: machine = "(Mitsubishi M32R)"; break;
    case 89: machine = "(Mitsubishi MN10300)"; break;
    case 90: machine = "(Mitsubishi M310200)"; break;
    case 91: machine = "(picoJava)"; break;
    case 92: machine = "(OpenRISC)"; break;
    case 93: machine = "(ARC Cores Tangent-A5)"; break;
    case 94: machine = "(Tensilica Xtensa)"; break;
    case 95: machine = "(Alphamosaic VideoCore)"; break;
    case 96: machine = "(Thompson Multimedia)"; break;
    case 97: machine = "(National Semiconductor 32000)"; break;
    case 98: machine = "(Tenor Network TPC)"; break;
    case 99: machine = "(Trebia SNP1000)"; break;
    case 100: machine = "(ST ST200)"; break;
    case 101: machine = "(Ubicom IP2xxx)"; break;
    case 102: machine = "(MAXProcessor)"; break;
    case 103: machine = "(National Semiconductor Compact RISC)"; break;
    case 104: machine = "(Fujitsu F2MC16)"; break;
    case 105: machine = "(TI MSP430)"; break;
    case 106: machine = "(Analog Devices Blackfin)"; break;
    case 107: machine = "(Seiko S1C33)"; break;
    case 108: machine = "(Sharp embedded)"; break;
    case 109: machine = "(Arca RISC)"; break;
    case 110: machine = "(PKU-Unity)"; break;
    case 165: machine = "(8051)"; break;
    case 186: machine = "(STM8)"; break;
    case 204: machine = "(PIC)"; break;
    case 220: machine = "(Z80)"; break;
    default: machine = "(Unknown)"; break;
  }

  printf("  e_machine: 0x%x %s\n", elf_info->e_machine, machine);

  printf("  e_version: %d\n", elf_info->read_word(elf_info));
  printf("    e_entry: 0x%lx (virt addr)\n", elf_info->read_addr(elf_info));
  printf("    e_phoff: 0x%lx (program header table offset)\n", elf_info->read_offset(elf_info));
  printf("    e_shoff: 0x%lx (section header table offset)\n", elf_info->read_offset(elf_info));
  printf("    e_flags: 0x%08x (processor specific flags)\n", elf_info->read_word(elf_info));
  printf("   e_ehsize: 0x%08x (elf header size)\n", elf_info->read_half(elf_info));
  printf("e_phentsize: %d (program header table size)\n", elf_info->read_half(elf_info));
  printf("    e_phnum: %d (program header table count)\n", elf_info->read_half(elf_info));
  printf("e_shentsize: %d (section header size)\n", elf_info->read_half(elf_info));
  printf("    e_shnum: %d (section header count)\n", elf_info->read_half(elf_info));
  printf(" e_shstrndx: %d (section header string table index)\n", elf_info->read_half(elf_info));

  printf("\n");
}

static void print_core_siginfo(elf_info_t *elf_info)
{
  long marker = elf_info->file_ptr;
  printf("        signal_number: %d\n", elf_info->read_int32(elf_info));
  printf("           extra_code: %d\n", elf_info->read_int32(elf_info));
  printf("                errno: %d\n", elf_info->read_int32(elf_info));
  elf_info->file_ptr = marker;
}

#if 0
static void print_core_regs(elf_info_t *elf_info)
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

int find_program_header(elf_info_t *elf_info, uint64_t address)
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

static void print_core_prstatus(elf_info_t *elf_info)
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
  printf("                  pid: %d\n", elf_info->read_int32(elf_info));
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

static void print_core_prpsinfo(elf_info_t *elf_info)
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

static void print_core_mapped_files(elf_info_t *elf_info, int len)
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

const char *get_program_header_type(int type)
{
  const char *types[] =
  {
    "NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS", "NUM"
  };

  if (type <= 8)
  {
    return types[type];
  }

  if (type == 0x6474e550) { return "GNU_EH_FRAME"; }
  if (type == 0x6474e551) { return "GNU_STACK"; }
  if (type == 0x6474e552) { return "GNU_RELRO"; }

  return "UNKNOWN";
}

void print_elf_program_headers(elf_info_t *elf_info)
{
int count;
long marker;
unsigned int p_type;
int p_flags;
int namesz,descsz,type;
long p_offset,p_filesz;
int n;
const char *flags[] =
{
  "---", "--X", "-W-", "-WX", "R--", "R-X", "RW-", "RWX"
};

  elf_info->file_ptr = elf_info->e_phoff;

  printf("Elf Program Headers (count=%d)\n\n", elf_info->e_phnum);

  for(count = 0; count < elf_info->e_phnum; count++)
  {
    marker = elf_info->file_ptr + elf_info->e_phentsize;

    printf("Program Header %d (offset=0x%04" PRIx64 ")\n", count, elf_info->file_ptr);
    printf("---------------------------------------------\n");

    if (elf_info->bitwidth == 32)
    {
      p_type = elf_info->read_word(elf_info);
      printf("  p_type: %d (%s)\n", p_type, get_program_header_type(p_type));
      p_offset = elf_info->read_offset(elf_info);
      printf("p_offset: 0x%lx\n", p_offset);
      printf(" p_vaddr: 0x%lx\n", elf_info->read_addr(elf_info));
      printf(" p_paddr: 0x%lx\n", elf_info->read_addr(elf_info));
      p_filesz = elf_info->read_word(elf_info);
      printf("p_filesz: %ld\n", p_filesz);
      printf(" p_memsz: %d\n", elf_info->read_word(elf_info));
      p_flags = elf_info->read_word(elf_info);
      printf(" p_flags: %d %s%s%s\n", p_flags, flags[p_flags&7],
        (p_flags & 0xff0000) == 0xff0000 ? " MASKOS" : "",
        (p_flags & 0xff000000) == 0xff000000 ? " MASKPROC" : "");
      printf(" p_align: %d\n", elf_info->read_word(elf_info));
    }
    else
    {
      p_type = elf_info->read_word(elf_info);
      p_flags = elf_info->read_word(elf_info);
      p_offset = elf_info->read_offset(elf_info);
      printf("  p_type: %d (%s)\n", p_type, get_program_header_type(p_type));
      printf(" p_flags: %d %s%s%s\n", p_flags, flags[p_flags&7],
        (p_flags & 0xff0000) == 0xff0000 ? " MASKOS" : "",
        (p_flags & 0xff000000) == 0xff000000 ? " MASKPROC" : "");
      printf("p_offset: 0x%lx\n", p_offset);
      printf(" p_vaddr: 0x%lx\n", elf_info->read_addr(elf_info));
      printf(" p_paddr: 0x%lx\n", elf_info->read_addr(elf_info));
      p_filesz = elf_info->read_xword(elf_info);
      printf("p_filesz: 0x%lx\n", p_filesz);
      printf(" p_memsz: 0x%lx\n", elf_info->read_xword(elf_info));
      printf(" p_align: 0x%lx\n", elf_info->read_xword(elf_info));
    }

    // If this is a NOTE section
    if (p_type == 4)
    {
      uint32_t align_mask = elf_info->bitwidth == 32 ? 3 : 7;
      int namesz_align;
      int descsz_align;
      int bytes_used = 0;
      char name[1024];
      elf_info->file_ptr = p_offset;

      printf("\n");

      while(bytes_used < p_filesz)
      {
        //printf("bytes_used=%d / %ld\n", bytes_used, p_filesz);
        namesz = elf_info->read_word(elf_info);
        descsz = elf_info->read_word(elf_info);
        type = elf_info->read_word(elf_info);

        namesz_align = (namesz + align_mask) & ~align_mask;
        descsz_align = (descsz + align_mask) & ~align_mask;

        if (namesz < 1023)
        {
          for (n = 0; n < namesz; n++)
          {
            name[n] = elf_info->read_int8(elf_info);
          }
          name[n] = 0;

          elf_info->file_ptr += namesz_align - namesz;
        }
        else
        {
          elf_info->file_ptr += namesz_align;
          name[0] = 0;
        }

        // FIXME - There's a lot more things that can be put in here.
        // They will come back as unknown, but can be added as needed.
        printf("%8s 0x%04x  [0x%x ", name, descsz, type);

        // FIXME - Um. When there is a GNU section I'm 4 bytes off.  Why?
        if (strcmp(name, "GNU") == 0)
        {
          printf("]\n");
          //printf("%lx\n", elf_info->file_ptr);
          for (n = 0; n < descsz; n++)
          {
            uint8_t c = elf_info->read_int8(elf_info);

            if (c >= ' ' && c < 127)
            {
              printf("%c", c);
            }
            else
            {
              printf("<%02x>", c);
            }
          }
          printf("\n");
          break;
        }

        int is_core = 0;
        if (strcmp(name, "CORE") == 0) { is_core = 1; }

        switch(type)
        {
          case 1:
            printf("NT_PRSTATUS]\n");
            if (is_core) { print_core_prstatus(elf_info); }
            break;
          case 2:
            printf("NT_PRFPREG]\n");
            //print_core_regs(elf_info);
            break;
          case 3:
            printf("NT_PRPSINFO]\n");
            if (is_core) { print_core_prpsinfo(elf_info); }
            break;
          case 4: printf("NT_TASKSTRUCT]\n"); break;
          case 6: printf("NT_AUXV]\n"); break;
          case 0x200: printf("NT_386_TLS]\n"); break;
          case 0x53494749:
            printf("NT_SIGINFO]\n");
            if (is_core) { print_core_siginfo(elf_info); }
            break;
          case 0x46494c45:
            printf("NT_FILE]\n");
            print_core_mapped_files(elf_info, descsz);
            break;
          case 0x46e62b7f: printf("NT_PRXFPREG]\n"); break;
          default:
            printf("unknown]\n");
            break;
        }

        elf_info->file_ptr += descsz_align;

        bytes_used += (4 * 3) + namesz_align + descsz_align;
      }
    }

    printf("\n");

    elf_info->file_ptr = marker;
  }
}

static void print_elf_comment(unsigned char *comment, int sh_size)
{
  int n;
  for (n = 0; n < sh_size; n++)
  {
    if (comment[n] >= 32 && comment[n] < 127)
    { printf("%c", comment[n]); }
      else
    { printf("[%02x]", comment[n]); }
  }
  printf("\n\n");
}

static void print_elf_symtab_32(elf_info_t *elf_info, int offset, int sh_size, int sh_entsize, int strtab_offset)
{
  int n;
  char *strtab = (char *)elf_info->buffer + strtab_offset;
  for (n = 0; n < sh_size; n = n + sh_entsize)
  {
    strtab_offset = elf_info->get_word(elf_info, offset+n);
    printf("   %-30s [%d] 0x%lx %d %d %d %d\n",
      strtab + strtab_offset,
      strtab_offset,
      elf_info->get_addr(elf_info, offset + n + 4),
      elf_info->get_word(elf_info, offset + n + 8),
      *(elf_info->buffer + offset + n + 12),
      *(elf_info->buffer + offset + n + 13),
      elf_info->get_half(elf_info, offset + n + 14)
    );
  }
  printf("\n\n");
}

static void print_elf_symtab_64(elf_info_t *elf_info, int offset, int sh_size, int sh_entsize, int strtab_offset)
{
  int n;
  char *strtab = (char *)elf_info->buffer + strtab_offset;
  for (n = 0; n < sh_size; n = n + sh_entsize)
  {
    strtab_offset = elf_info->get_word(elf_info, offset+n);
    printf("%-30s [%d] 0x%lx %ld %d %d %d\n",
      strtab + strtab_offset,
      strtab_offset,
      elf_info->get_addr(elf_info, offset + n + 8),
      elf_info->get_xword(elf_info, offset + n + 16),
      *(elf_info->buffer+offset + n + 4),
      *(elf_info->buffer+offset + n + 5),
      elf_info->get_half(elf_info, offset + n + 6)
    );
  }
  printf("\n\n");
}

static void print_elf_string_table(unsigned char *table, int sh_size)
{
  int index = 0;
  int len = 0;
  int n;

  for (n = 0; n < sh_size; n++)
  {
    if (len == 0) { printf("\n   [%d] %d: ", n, index++); }
    if (table[n] >= 32 && table[n] < 127)
    { printf("%c", table[n]); }
      else
    {
      if (table[n] == 0) { len = 0; continue; }
      printf("[%02x]", table[n]);
    }

    len++;
  }
  printf("\n\n");
}

#if 0
static void print_elf_dynamic(elf_info_t *elf_info, int offset, int size)
{
char *dynamic_tag[] = {
  "DT_NULL",
  "DT_NEEDED",
  "DT_PLTRELSZ",
  "DT_PLGOT",
  "DT_HASH",
  "DT_STRTAB",
  "DT_SYMTAB",
  "DT_REALA",
  "DT_REALASZ",
  "DT_REALAENT",
  "DT_STRSZ",
  "DT_SYMENT",
  "DT_INIT",
  "DT_FINI",
  "DT_SONAME",
  "DT_RPATH",
  "DT_SYMBOLIC"
};
unsigned int d_tag;
unsigned int d_un;
int n;

  for (n=0; n<size; n=n+8)
  {
    d_tag=elf_info->get_word(elf_info, offset+n);
    d_un=elf_info->get_word(elf_info, offset+n+4);

    printf("0x%08x ", d_un);

    if (d_tag>16) { printf("??? (%d)\n", d_tag); }
    else { printf("%s\n", dynamic_tag[d_tag]); }
  }
}
#endif

static void print_elf_arm_attrs(unsigned char *attrs, int sh_size)
{
  int n;
  char text[17];
  int ptr;

  ptr = 0;

  for (n = 0; n < sh_size; n++)
  {
    if ((n % 16) == 0)
    {
      if (ptr != 0) { text[ptr] = 0; printf("  %s", text); ptr = 0; }
      printf("\n");
    }
    printf(" %02x", attrs[n]);
    if (attrs[n] >= 48 && attrs[n] < 120) { text[ptr++] = attrs[n]; }
    else { text[ptr++] = '.'; }
  }

  text[ptr] = 0;
  printf("  %s\n\n", text);
  //int pos = 6 + strlen((char *)attrs + 5);

  printf("   Version: %c\n", attrs[0]);
  printf("      Size: %d\n", attrs[1] | (attrs[2] << 8) | (attrs[3] << 16) | (attrs[4] << 24));
  printf("VendorName: %s\n", attrs+5);
  printf("\n");
}

void print_elf_section_headers(elf_info_t *elf_info)
{
  int count;
  int t;
  long i;
  long marker;

  elf_info->file_ptr = elf_info->e_shoff;

  printf("Elf Section Headers (count=%d)\n\n", elf_info->e_shnum);

  for(count = 0; count<elf_info->e_shnum; count++)
  {
    marker = elf_info->file_ptr+elf_info->e_shentsize;

    printf("Section Header %d (offset=0x%04" PRIx64 ")\n", count, elf_info->file_ptr);
    printf("---------------------------------------------\n");

    t = elf_info->read_word(elf_info);
    printf("     sh_name: %d", t);
    char *section_name = NULL;
    if (t != 0)
    {
      section_name = (char *)(elf_info->buffer + elf_info->str_tbl_offset + t);
      printf(" (%s)\n", section_name);
    }
      else
    { printf("\n"); }

    int sh_type = elf_info->read_word(elf_info);
    printf("     sh_type: %d ", sh_type);

    switch(sh_type)
    {
      case 0: { printf("(SHT_NULL)\n"); break; }
      case 1: { printf("(SHT_PROGBITS)\n"); break; }
      case 2: { printf("(SHT_SYMTAB)\n"); break; }
      case 3: { printf("(SHT_STRTAB)\n"); break; }
      case 4: { printf("(SHT_RELA)\n"); break; }
      case 5: { printf("(SHT_HASH)\n"); break; }
      case 6: { printf("(SHT_DYNAMIC)\n"); break; }
      case 7: { printf("(SHT_NOTE)\n"); break; }
      case 8: { printf("(SHT_NOBITS)\n"); break; }
      case 9: { printf("(SHT_REL)\n"); break; }
      case 10: { printf("(SHT_SHLIB)\n"); break; }
      case 11: { printf("(SHT_DYNSYM)\n"); break; }
      case 14: { printf("(SHT_INIT_ARRAY)\n"); break; }
      case 15: { printf("(SHT_FINI_ARRAY)\n"); break; }
      case 16: { printf("(SHT_PREINIT_ARRAY)\n"); break; }
      case 17: { printf("(SHT_GROUP)\n"); break; }
      case 18: { printf("(SHT_SYMTAB_SHNDX)\n"); break; }
      case 0x60000000: { printf("(SHT_LOOS)\n"); break; }
      case 0x6fffffff: { printf("(SHT_HIOS)\n"); break; }
      case 0x70000000: { printf("(SHT_LOPROC)\n"); break; }
      case 0x7fffffff: { printf("(SHT_HIPROC)\n"); break; }
      case 0x80000000: { printf("(SHT_LOUSER)\n"); break; }
      case 0xffffffff: { printf("(SHT_HIUSER)\n"); break; }
      default: printf("(Unknown)\n");
    }

    i = elf_info->read_xword(elf_info);
    printf("    sh_flags: 0x%lx (", i);

    if ((i & 0x1) != 0) { printf("SHF_WRITE "); }
    if ((i & 0x2) != 0) { printf("SHF_ALLOC "); }
    if ((i & 0x4) != 0) { printf("SHF_EXECINSTR "); }
    if ((i & 0x10) != 0) { printf("SHF_MERGE "); }
    if ((i & 0x20) != 0) { printf("SHF_STRINGS "); }
    if ((i & 0x40) != 0) { printf("SHF_INFO_LINK "); }
    if ((i & 0x80) != 0) { printf("SHF_LINK_ORDER "); }
    if ((i & 0x100) != 0) { printf("SHF_OS_NONCONFORMING "); }
    if ((i & 0x200) != 0) { printf("SHF_GROUP "); }
    if ((i & 0x400) != 0) { printf("SHF_TLS "); }
    if ((i & 0xff00000) != 0) { printf("SHF_MASKOS "); }
    if ((i & 0xf0000000) != 0) { printf("SHF_MASKPROC "); }
    printf(")\n");

    printf("     sh_addr: 0x%lx\n", elf_info->read_addr(elf_info));
    long sh_offset = elf_info->read_offset(elf_info);
    long sh_size = elf_info->read_xword(elf_info);
    printf("   sh_offset: 0x%lx\n", sh_offset);
    printf("     sh_size: %ld\n", sh_size);
    printf("     sh_link: %d\n", elf_info->read_word(elf_info));
    printf("     sh_info: %d\n", elf_info->read_word(elf_info));
    printf("sh_addralign: %ld\n", elf_info->read_xword(elf_info));
    long sh_entsize = elf_info->read_xword(elf_info);
    printf("  sh_entsize: %ld\n", sh_entsize);
    printf("\n");

    if (section_name != NULL)
    {
      if (strcmp(".comment", section_name) == 0)
      {
        print_elf_comment(elf_info->buffer + sh_offset, sh_size);
      }
        else
      if (strcmp(".strtab", section_name) == 0 || sh_type == 3)
      {
        print_elf_string_table(elf_info->buffer+sh_offset, sh_size);
      }
        else
      if (strcmp(".shstrtab", section_name) == 0)
      {
        print_elf_string_table(elf_info->buffer + sh_offset, sh_size);
      }
        else
      if (strcmp(".symtab", section_name) == 0)
      {
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".strtab", NULL);
        if (elf_info->bitwidth == 32)
        { print_elf_symtab_32(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
          else
        if (elf_info->bitwidth == 64)
        { print_elf_symtab_64(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
      }
        else
      if (strcmp(".dynsym", section_name) == 0)
      {
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".dynstr", NULL);
        if (elf_info->bitwidth == 32)
        { print_elf_symtab_32(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
          else
        if (elf_info->bitwidth == 64)
        { print_elf_symtab_64(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
      }
        else
      if (strcmp(".ARM.attributes", section_name) == 0 || sh_type == 3)
      {
        print_elf_arm_attrs(elf_info->buffer+sh_offset, sh_size);
      }
#if 0
        else
      if (strcmp(".dynamic", section_name) == 0)
      {
        print_elf_dynamic(elf_info, sh_offset, sh_size);
      }
#endif
    }

/*
if (elf_info->file_ptr != marker)
{
  printf("%ld %ld\n", elf_info->file_ptr,marker + elf_info->e_shentsize);
exit(0);
}
*/

    elf_info->file_ptr = marker;
  }
}



