/*

 magic_elf - The ELF file format analyzer.

 Copyright 2009-2014 - Michael Kohn (mike@mikekohn.net)
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
int t;

  printf("Elf Header\n");
  printf("---------------------------------------------\n");
  printf("    e_ident: ");
  for (t=0; t<16; t++)
  {
    printf("%02x ",elf_info->buffer[t]);
  }
  printf("\n");

  printf("             EI_MAGIC=0x7f ELF\n");
  printf("             EI_CLASS=%d ",elf_info->buffer[4]);
  if (elf_info->buffer[4]==1)
  { printf("(32 bit)\n"); elf_info->bitwidth=32; }
    else
  if (elf_info->buffer[4]==2)
  { printf("(64 bit)\n"); elf_info->bitwidth=64; }
    else
  { printf("(Invalid)\n"); elf_info->bitwidth=0; }

  printf("             EI_DATA=%d ",elf_info->buffer[5]);
  if (elf_info->buffer[5]==1)
  { printf("(Little Endian)\n"); }
    else
  if (elf_info->buffer[5]==2)
  { printf("(Big Endian)\n"); }

  printf("             EI_VERSION=%d\n",elf_info->buffer[6]);
  printf("             EI_OSABI=%d ",elf_info->buffer[7]);

  switch(elf_info->buffer[7])
  {
    case 0: { printf("(Unix SysV ABI)\n"); break; }
    case 1: { printf("(HP-UX)\n"); break; }
    case 2: { printf("(NetBSD)\n"); break; }
    case 6: { printf("(Solaris)\n"); break; }
    case 7: { printf("(AIX)\n"); break; }
    case 8: { printf("(IRIX)\n"); break; }
    case 9: { printf("(FreeBSD)\n"); break; }
    case 10: { printf("(Tru64)\n"); break; }
    case 11: { printf("(Novell Modesto)\n"); break; }
    case 12: { printf("(OpenBSD)\n"); break; }
    case 13: { printf("(OpenVMS)\n"); break; }
    case 14: { printf("(HP Non-Stop Kernel)\n"); break; }
    case 15: { printf("(Amiga Research OS)\n"); break; }
    case 255: { printf("(Embedded)\n"); break; }
    default: printf("(Unknown)\n");
  }

  printf("             EI_ABIVER=%d\n",elf_info->buffer[8]);

  elf_info->file_ptr=16;

  t=elf_info->read_half(elf_info);
  printf("     e_type: %02x ",t);
  switch(t)
  {
    case 0: { printf("(No type)\n"); break; }
    case 1: { printf("(Relocatable)\n"); break; }
    case 2: { printf("(Executable)\n"); break; }
    case 3: { printf("(Shared Object)\n"); break; }
    case 4: { printf("(Core File)\n"); break; }
    case 0xfe00: { printf("(OS-specific:ET_LOOS)\n"); break; }
    case 0xfeff: { printf("(OS-specific:ET_HIOS)\n"); break; }
    case 0xff00: { printf("(Processor-specific:ET_LOPROC)\n"); break; }
    case 0xffff: { printf("(Processor-specific:ET_HIPROC)\n"); break; }
    default: printf("(\?\?\?)\n");
  }

  elf_info->e_machine = elf_info->read_half(elf_info);
  printf("  e_machine: 0x%x ",elf_info->e_machine);
  switch(elf_info->e_machine)
  {
    case 0: { printf("(None)\n"); break; }
    case 1: { printf("(AT&T WE 32100)\n"); break; }
    case 2: { printf("(SPARC)\n"); break; }
    case 3: { printf("(x86-32)\n"); break; }
    case 4: { printf("(Motorola 68000)\n"); break; }
    case 5: { printf("(Motorola 88000)\n"); break; }
    case 7: { printf("(Intel 80860)\n"); break; }
    case 8: { printf("(MIPS RS3000)\n"); break; }
    case 10: { printf("(MIPS RS3000 Little-Endian)\n"); break; }
    case 15: { printf("(PA-RISC)\n"); break; }
    case 17: { printf("(Fujitsu VPP500)\n"); break; }
    case 18: { printf("(Enhanced SPARC)\n"); break; }
    case 19: { printf("(Intel 80960)\n"); break; }
    case 20: { printf("(PowerPC)\n"); break; }
    case 21: { printf("(PowerPC 64 bit)\n"); break; }
    case 22: { printf("(IBM System/390)\n"); break; }
    case 36: { printf("(NEC V800)\n"); break; }
    case 37: { printf("(Fujitsu FR20)\n"); break; }
    case 38: { printf("(TRW RH-32)\n"); break; }
    case 39: { printf("(Motorola RCE)\n"); break; }
    case 40: { printf("(ARM)\n"); break; }
    case 41: { printf("(Alpha)\n"); break; }
    case 42: { printf("(Hitachi SH)\n"); break; }
    case 43: { printf("(Sparc V9)\n"); break; }
    case 44: { printf("(Siemens Tricore)\n"); break; }
    case 45: { printf("(ARC)\n"); break; }
    case 46: { printf("(Hitachi H8/300)\n"); break; }
    case 47: { printf("(Hitachi H8/300H)\n"); break; }
    case 48: { printf("(Hitachi H8S)\n"); break; }
    case 49: { printf("(Hitachi H8/500)\n"); break; }
    case 50: { printf("(Itanium IA-64)\n"); break; }
    case 51: { printf("(MIPS-X)\n"); break; }
    case 52: { printf("(Motorola Coldfire)\n"); break; }
    case 53: { printf("(Motorola M68HC12)\n"); break; }
    case 54: { printf("(Fujitsu MMA)\n"); break; }
    case 55: { printf("(Siemens PCP)\n"); break; }
    case 56: { printf("(Sony nCPU)\n"); break; }
    case 57: { printf("(Denso NDR1)\n"); break; }
    case 58: { printf("(Motorola Star)\n"); break; }
    case 59: { printf("(Toyota ME16)\n"); break; }
    case 60: { printf("(ST ST100)\n"); break; }
    case 61: { printf("(TinyJ)\n"); break; }
    case 62: { printf("(x86-64)\n"); break; }
    case 63: { printf("(Sony DSP)\n"); break; }
    case 64: { printf("(DEC PDP-10)\n"); break; }
    case 65: { printf("(DEC PDP-11)\n"); break; }
    case 66: { printf("(Siemens FX66)\n"); break; }
    case 67: { printf("(ST ST9+)\n"); break; }
    case 68: { printf("(ST ST7)\n"); break; }
    case 69: { printf("(Motorola MC68HC16)\n"); break; }
    case 70: { printf("(Motorola MC68HC11)\n"); break; }
    case 71: { printf("(Motorola MC68HC08)\n"); break; }
    case 72: { printf("(Motorola MC68HC05)\n"); break; }
    case 73: { printf("(Silicon Graphics SVx)\n"); break; }
    case 74: { printf("(ST ST19)\n"); break; }
    case 75: { printf("(Digital VAX)\n"); break; }
    case 76: { printf("(Axis EXTRAX)\n"); break; }
    case 77: { printf("(Infineon Technologies)\n"); break; }
    case 78: { printf("(Element 14)\n"); break; }
    case 79: { printf("(LSI Logic)\n"); break; }
    case 80: { printf("(Donald Knuth's edu)\n"); break; }
    case 81: { printf("(Harvard Uni machine independant)\n"); break; }
    case 82: { printf("(SiTera Prism)\n"); break; }
    case 83: { printf("(Atmel AVR 8bit)\n"); break; }
    case 84: { printf("(Fujitsu FR30)\n"); break; }
    case 85: { printf("(Mitsubishi D10V)\n"); break; }
    case 86: { printf("(Mitsubishi D30V)\n"); break; }
    case 87: { printf("(NEC v850)"); break; }
    case 88: { printf("(Mitsubishi M32R)\n"); break; }
    case 89: { printf("(Mitsubishi MN10300)\n"); break; }
    case 90: { printf("(Mitsubishi M310200)\n"); break; }
    case 91: { printf("(picoJava)\n"); break; }
    case 92: { printf("(OpenRISC)\n"); break; }
    case 93: { printf("(ARC Cores Tangent-A5)\n"); break; }
    case 94: { printf("(Tensilica Xtensa)\n"); break; }
    case 95: { printf("(Alphamosaic VideoCore)\n"); break; }
    case 96: { printf("(Thompson Multimedia)\n"); break; }
    case 97: { printf("(National Semiconductor 32000)\n"); break; }
    case 98: { printf("(Tenor Network TPC)\n"); break; }
    case 99: { printf("(Trebia SNP1000)\n"); break; }
    case 100: { printf("(ST ST200)\n"); break; }
    case 101: { printf("(Ubicom IP2xxx)\n"); break; }
    case 102: { printf("(MAXProcessor)\n"); break; }
    case 103: { printf("(National Semiconductor Compact RISC)\n"); break; }
    case 104: { printf("(Fujitsu F2MC16)\n"); break; }
    case 105: { printf("(TI MSP430)\n"); break; }
    case 106: { printf("(Analog Devices Blackfin)\n"); break; }
    case 107: { printf("(Seiko S1C33)\n"); break; }
    case 108: { printf("(Sharp embedded)\n"); break; }
    case 109: { printf("(Arca RISC)\n"); break; }
    case 110: { printf("(PKU-Unity)\n"); break; }
    default: printf("(Unknown)\n");
  }

  printf("  e_version: %d\n",elf_info->read_word(elf_info));
  printf("    e_entry: 0x%lx (virt addr)\n",elf_info->read_addr(elf_info));
  printf("    e_phoff: 0x%lx (program header table offset)\n",elf_info->read_offset(elf_info));
  printf("    e_shoff: 0x%lx (section header table offset)\n",elf_info->read_offset(elf_info));
  printf("    e_flags: 0x%08x (processor specific flags)\n",elf_info->read_word(elf_info));
  printf("   e_ehsize: 0x%08x (elf header size)\n",elf_info->read_half(elf_info));
  printf("e_phentsize: %d (program header table size)\n",elf_info->read_half(elf_info));
  printf("    e_phnum: %d (program header table count)\n",elf_info->read_half(elf_info));
  printf("e_shentsize: %d (section header size)\n",elf_info->read_half(elf_info));
  printf("    e_shnum: %d (section header count)\n",elf_info->read_half(elf_info));
  printf(" e_shstrndx: %d (section header string table index)\n",elf_info->read_half(elf_info));

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
  printf("              sigpend: %" PRId64 "\n", elf_info->read_offset(elf_info));
  printf("              sighold: %" PRId64 "\n", elf_info->read_offset(elf_info));
  printf("                  pid: %d\n", elf_info->read_int32(elf_info));
  printf("                 ppid: %d\n", elf_info->read_int32(elf_info));
  printf("                 pgrp: %d\n", elf_info->read_int32(elf_info));
  printf("                 psid: %d\n", elf_info->read_int32(elf_info));

  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf("            user time: %ld %ld\n", tv_sec, tv_usec);
  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf("          system time: %ld %ld\n", tv_sec, tv_usec);
  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf(" cumulative user time: %ld %ld\n", tv_sec, tv_usec);
  tv_sec = elf_info->read_offset(elf_info);
  tv_usec = elf_info->read_offset(elf_info);
  printf("  cumulative sys time: %ld %ld\n", tv_sec, tv_usec);

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

    printf("      R15: %016lx     R14: %016lx   R13: %016lx\n",
      r15, r14, r13);
    printf("      R12: %016lx     RBP: %016lx   RBX: %016lx\n",
      r12, rbp, rbx);
    printf("      R11: %016lx     R10: %016lx    R9: %016lx\n",
      r11, r10, r9);
    printf("       R8: %016lx     RAX: %016lx   RCX: %016lx\n",
      r8, rax, rcx);
    printf("      RDX: %016lx     RSI: %016lx   RDI: %016lx\n",
      rdx, rsi, rdi);
    printf(" ORIG_RAX: %016lx     RIP: %016lx    CS: %016lx\n",
      orig_rax, rip, cs);
    printf("   EFLAGS: %016lx     RSP: %016lx    SS: %016lx\n",
      eflags, rsp, ss);
    printf("  FS_BASE: %016lx GS_BASE: %016lx    DS: %016lx\n",
      fs_base, gs_base, ds);
    printf("       ES: %016lx      FS: %016lx    GS: %016lx\n",
      es, fs, gs);

    int program_header = find_program_header(elf_info, rip);

    if (program_header != -1)
    {
      printf("     <program header: %d>\n", program_header);
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
  printf("             flag: %" PRId64 "\n", elf_info->read_offset(elf_info));
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
       printf("            %016lx %016lx %016lx\n", page_offset, start, end);
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

    printf("Program Header %d\n",count);
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
          for (n = 0; n < descsz; n++) { printf("%c", elf_info->read_int8(elf_info)); }
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
  for (n=0; n<sh_size; n++)
  {
    if (comment[n]>=32 && comment[n]<127)
    { printf("%c", comment[n]); }
      else
    { printf("[%02x]", comment[n]); }
  }
  printf("\n\n");
}

static void print_elf_symtab_32(elf_info_t *elf_info, int offset, int sh_size, int sh_entsize, int strtab_offset)
{
  int n;
  char *strtab=(char *)elf_info->buffer+strtab_offset;
  for (n=0; n<sh_size; n=n+sh_entsize)
  {
    strtab_offset=elf_info->get_word(elf_info, offset+n);
    printf("   %-30s [%d] 0x%lx %d %d %d %d\n",
      strtab+strtab_offset,
      strtab_offset,
      elf_info->get_addr(elf_info, offset+n+4),
      elf_info->get_word(elf_info, offset+n+8),
      *(elf_info->buffer+offset+n+12),
      *(elf_info->buffer+offset+n+13),
      elf_info->get_half(elf_info, offset+n+14)
    );
  }
  printf("\n\n");
}

static void print_elf_symtab_64(elf_info_t *elf_info, int offset, int sh_size, int sh_entsize, int strtab_offset)
{
  int n;
  char *strtab=(char *)elf_info->buffer+strtab_offset;
  for (n=0; n<sh_size; n=n+sh_entsize)
  {
    strtab_offset=elf_info->get_word(elf_info, offset+n);
    printf("%-30s [%d] 0x%lx %ld %d %d %d\n",
      strtab+strtab_offset,
      strtab_offset,
      elf_info->get_addr(elf_info, offset+n+8),
      elf_info->get_xword(elf_info, offset+n+16),
      *(elf_info->buffer+offset+n+4),
      *(elf_info->buffer+offset+n+5),
      elf_info->get_half(elf_info, offset+n+6)
    );
  }
  printf("\n\n");
}

static void print_elf_string_table(unsigned char *table, int sh_size)
{
  int index=0;
  int len=0;
  int n;

  for (n=0; n<sh_size; n++)
  {
    if (len==0) { printf("\n   [%d] %d: ", n, index++); }
    if (table[n]>=32 && table[n]<127)
    { printf("%c", table[n]); }
      else
    {
      if (table[n]==0) { len=0; continue; }
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

  ptr=0;

  for (n=0; n<sh_size; n++)
  {
    if (n%16==0)
    {
      if (ptr!=0) { text[ptr]=0; printf("  %s", text); ptr=0; }
      printf("\n");
    }
    printf(" %02x", attrs[n]);
    if (attrs[n]>=48 && attrs[n]<120) { text[ptr++]=attrs[n]; }
    else { text[ptr++]='.'; }
  }

  text[ptr]=0;
  printf("  %s\n\n", text);
  //int pos=6+strlen((char *)attrs+5);

  printf("   Version: %c\n", attrs[0]);
  printf("      Size: %d\n", attrs[1]|(attrs[2]<<8)|(attrs[3]<<16)|(attrs[4]<<24));
  printf("VendorName: %s\n", attrs+5);
  printf("\n");
}

void print_elf_section_headers(elf_info_t *elf_info)
{
int count;
int t;
long i;
long marker;

  elf_info->file_ptr=elf_info->e_shoff;

  printf("Elf Section Headers (count=%d)\n\n",elf_info->e_shnum);

  for(count=0; count<elf_info->e_shnum; count++)
  {
    marker=elf_info->file_ptr+elf_info->e_shentsize;

    printf("Section Header %d\n",count);
    printf("---------------------------------------------\n");

    t=elf_info->read_word(elf_info);
    printf("     sh_name: %d",t);
    char *section_name=NULL;
    if (t!=0)
    {
      section_name=(char *)(elf_info->buffer+elf_info->str_tbl_offset+t);
      printf(" (%s)\n",section_name);
    }
      else
    { printf("\n"); }

    int sh_type=elf_info->read_word(elf_info);
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

    i=elf_info->read_xword(elf_info);
    printf("    sh_flags: 0x%lx (",i);

    if ((i&0x1)!=0) { printf("SHF_WRITE "); }
    if ((i&0x2)!=0) { printf("SHF_ALLOC "); }
    if ((i&0x4)!=0) { printf("SHF_EXECINSTR "); }
    if ((i&0x10)!=0) { printf("SHF_MERGE "); }
    if ((i&0x20)!=0) { printf("SHF_STRINGS "); }
    if ((i&0x40)!=0) { printf("SHF_INFO_LINK "); }
    if ((i&0x80)!=0) { printf("SHF_LINK_ORDER "); }
    if ((i&0x100)!=0) { printf("SHF_OS_NONCONFORMING "); }
    if ((i&0x200)!=0) { printf("SHF_GROUP "); }
    if ((i&0x400)!=0) { printf("SHF_TLS "); }
    if ((i&0xff00000)!=0) { printf("SHF_MASKOS "); }
    if ((i&0xf0000000)!=0) { printf("SHF_MASKPROC "); }
    printf(")\n");

    printf("     sh_addr: 0x%lx\n",elf_info->read_addr(elf_info));
    long sh_offset=elf_info->read_offset(elf_info);
    long sh_size=elf_info->read_xword(elf_info);
    printf("   sh_offset: 0x%lx\n",sh_offset);
    printf("     sh_size: %ld\n",sh_size);
    printf("     sh_link: %d\n",elf_info->read_word(elf_info));
    printf("     sh_info: %d\n",elf_info->read_word(elf_info));
    printf("sh_addralign: %ld\n",elf_info->read_xword(elf_info));
    long sh_entsize=elf_info->read_xword(elf_info);
    printf("  sh_entsize: %ld\n",sh_entsize);
    printf("\n");

    if (section_name!=NULL)
    {
      if (strcmp(".comment", section_name)==0)
      {
        print_elf_comment(elf_info->buffer+sh_offset, sh_size);
      }
        else
      if (strcmp(".strtab", section_name)==0 || sh_type==3)
      {
        print_elf_string_table(elf_info->buffer+sh_offset, sh_size);
      }
        else
      if (strcmp(".shstrtab", section_name)==0)
      {
        print_elf_string_table(elf_info->buffer+sh_offset, sh_size);
      }
        else
      if (strcmp(".symtab", section_name)==0)
      {
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".strtab", NULL);
        if (elf_info->bitwidth==32)
        { print_elf_symtab_32(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
          else
        if (elf_info->bitwidth==64)
        { print_elf_symtab_64(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
      }
        else
      if (strcmp(".dynsym", section_name)==0)
      {
        int strtab_offset = find_section_offset(elf_info, SHT_STRTAB, ".dynstr", NULL);
        if (elf_info->bitwidth==32)
        { print_elf_symtab_32(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
          else
        if (elf_info->bitwidth==64)
        { print_elf_symtab_64(elf_info, sh_offset, sh_size, sh_entsize, strtab_offset); }
      }
        else
      if (strcmp(".ARM.attributes", section_name)==0 || sh_type==3)
      {
        print_elf_arm_attrs(elf_info->buffer+sh_offset, sh_size);
      }
#if 0
        else
      if (strcmp(".dynamic", section_name)==0)
      {
        print_elf_dynamic(elf_info, sh_offset, sh_size);
      }
#endif
    }

/*
if (elf_info->file_ptr!=marker)
{
  printf("%ld %ld\n",elf_info->file_ptr,marker+elf_info->e_shentsize);
exit(0);
}
*/

    elf_info->file_ptr=marker;
  }
}



