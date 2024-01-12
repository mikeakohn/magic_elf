/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2024 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdint.h>

#include "Header.h"

const char *Header::get_class_type()
{
  switch (ei_class)
  {
    case 1:  return "(32 bit)";
    case 2:  return "(64 bit)";
    default: return "(Invalid)";
  }
}

const char *Header::get_data_type()
{
  switch (ei_data)
  {
    case 1:  return "(Little Endian)";
    case 2:  return "(Big Endian)";
    default: return "(Invalid)";
  }
}

const char *Header::get_osabi_type()
{
  switch (ei_osabi)
  {
    case 0:   return "(Unix SysV ABI)";
    case 1:   return "(HP-UX)";
    case 2:   return "(NetBSD)";
    case 6:   return "(Solaris)";
    case 7:   return "(AIX)";
    case 8:   return "(IRIX)";
    case 9:   return "(FreeBSD)";
    case 10:  return "(Tru64)";
    case 11:  return "(Novell Modesto)";
    case 12:  return "(OpenBSD)";
    case 13:  return "(OpenVMS)";
    case 14:  return "(HP Non-Stop Kernel)";
    case 15:  return "(Amiga Research OS)";
    case 255: return "(Embedded)";
    default:  return "(Unknown)";
  }
}

const char *Header::get_type_type()
{
  switch (e_type)
  {
    case 0:      return "(No type)";
    case 1:      return "(Relocatable)";
    case 2:      return "(Executable)";
    case 3:      return "(Shared Object)";
    case 4:      return "(Core File)";
    case 0xfe00: return "(OS-specific:ET_LOOS)";
    case 0xfeff: return "(OS-specific:ET_HIOS)";
    case 0xff00: return "(Processor-specific:ET_LOPROC)";
    case 0xffff: return "(Processor-specific:ET_HIPROC)";
    default:     return "(\?\?\?)";
  }
}

const char *Header::get_machine_type()
{
  switch (e_machine)
  {
    case 0:    return "(None)";
    case 1:    return "(AT&T WE 32100)";
    case 2:    return "(SPARC)";
    case 3:    return "(x86-32)";
    case 4:    return "(Motorola 68000)";
    case 5:    return "(Motorola 88000)";
    case 7:    return "(Intel 80860)";
    case 8:    return "(MIPS R3000)";
    case 10:   return "(MIPS R3000 Little-Endian)";
    case 15:   return "(PA-RISC)";
    case 17:   return "(Fujitsu VPP500)";
    case 18:   return "(Enhanced SPARC)";
    case 19:   return "(Intel 80960)";
    case 20:   return "(PowerPC)";
    case 21:   return "(PowerPC 64 bit)";
    case 22:   return "(IBM System/390)";
    case 23:   return "(IBM Cell SPU)";
    case 36:   return "(NEC V800)";
    case 37:   return "(Fujitsu FR20)";
    case 38:   return "(TRW RH-32)";
    case 39:   return "(Motorola RCE)";
    case 40:   return "(ARM)";
    case 41:   return "(Alpha)";
    case 42:   return "(Hitachi SH)";
    case 43:   return "(Sparc V9)";
    case 44:   return "(Siemens Tricore)";
    case 45:   return "(ARC)";
    case 46:   return "(Hitachi H8/300)";
    case 47:   return "(Hitachi H8/300H)";
    case 48:   return "(Hitachi H8S)";
    case 49:   return "(Hitachi H8/500)";
    case 50:   return "(Itanium IA-64)";
    case 51:   return "(MIPS-X)";
    case 52:   return "(Motorola Coldfire)";
    case 53:   return "(Motorola M68HC12)";
    case 54:   return "(Fujitsu MMA)";
    case 55:   return "(Siemens PCP)";
    case 56:   return "(Sony nCPU)";
    case 57:   return "(Denso NDR1)";
    case 58:   return "(Motorola Star)";
    case 59:   return "(Toyota ME16)";
    case 60:   return "(ST ST100)";
    case 61:   return "(TinyJ)";
    case 62:   return "(x86-64)";
    case 63:   return "(Sony DSP)";
    case 64:   return "(DEC PDP-10)";
    case 65:   return "(DEC PDP-11)";
    case 66:   return "(Siemens FX66)";
    case 67:   return "(ST ST9+)";
    case 68:   return "(ST ST7)";
    case 69:   return "(Motorola MC68HC16)";
    case 70:   return "(Motorola MC68HC11)";
    case 71:   return "(Motorola MC68HC08)";
    case 72:   return "(Motorola MC68HC05)";
    case 73:   return "(Silicon Graphics SVx)";
    case 74:   return "(ST ST19)";
    case 75:   return "(Digital VAX)";
    case 76:   return "(Axis EXTRAX)";
    case 77:   return "(Infineon Technologies)";
    case 78:   return "(Element 14)";
    case 79:   return "(LSI Logic)";
    case 80:   return "(Donald Knuth's edu)";
    case 81:   return "(Harvard Uni machine independant)";
    case 82:   return "(SiTera Prism)";
    case 83:   return "(Atmel AVR 8bit)";
    case 84:   return "(Fujitsu FR30)";
    case 85:   return "(Mitsubishi D10V)";
    case 86:   return "(Mitsubishi D30V)";
    case 87:   return "(NEC v850)";
    case 88:   return "(Mitsubishi M32R)";
    case 89:   return "(Mitsubishi MN10300)";
    case 90:   return "(Mitsubishi M310200)";
    case 91:   return "(picoJava)";
    case 92:   return "(OpenRISC)";
    case 93:   return "(ARC Cores Tangent-A5)";
    case 94:   return "(Tensilica Xtensa)";
    case 95:   return "(Alphamosaic VideoCore)";
    case 96:   return "(Thompson Multimedia)";
    case 97:   return "(National Semiconductor 32000)";
    case 98:   return "(Tenor Network TPC)";
    case 99:   return "(Trebia SNP1000)";
    case 100:  return "(ST ST200)";
    case 101:  return "(Ubicom IP2xxx)";
    case 102:  return "(MAXProcessor)";
    case 103:  return "(National Semiconductor Compact RISC)";
    case 104:  return "(Fujitsu F2MC16)";
    case 105:  return "(TI MSP430)";
    case 106:  return "(Analog Devices Blackfin)";
    case 107:  return "(Seiko S1C33)";
    case 108:  return "(Sharp embedded)";
    case 109:  return "(Arca RISC)";
    case 110:  return "(PKU-Unity)";
    case 165:  return "(8051)";
    case 183:  return "(aarch64 / ARM64)";
    case 186:  return "(STM8)";
    case 204:  return "(PIC)";
    case 220:  return "(Z80)";
    case 243:  return "(RISC-V)";
    case 247:  return "(eBPF)";
    case 4643: return "(Epiphany)";
    default:   return "(Unknown)";
  }
}

