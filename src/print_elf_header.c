/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2022 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

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
#include "print_elf_header.h"

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
  printf("             EI_CLASS=%d ", elf_info->buffer[4]);

  if (elf_info->buffer[4] == 1)
  {
    printf("(32 bit)\n");
    elf_info->bitwidth = 32;
  }
    else
  if (elf_info->buffer[4] == 2)
  {
    printf("(64 bit)\n");
    elf_info->bitwidth = 64;
  }
    else
  {
    printf("(Invalid)\n");
    elf_info->bitwidth = 0;
  }

  printf("             EI_DATA=%d ", elf_info->buffer[5]);

  if (elf_info->buffer[5] == 1)
  {
    printf("(Little Endian)\n");
  }
    else
  if (elf_info->buffer[5] == 2)
  {
    printf("(Big Endian)\n");
  }

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
    case 4643: machine = "(Epiphany)"; break;
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

