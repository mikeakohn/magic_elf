/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include "Section.h"

const char *Section::get_section_type()
{
  switch (sh_type)
  {
    case 0:          return "(SHT_NULL)";
    case 1:          return "(SHT_PROGBITS)";
    case 2:          return "(SHT_SYMTAB)";
    case 3:          return "(SHT_STRTAB)";
    case 4:          return "(SHT_RELA)";
    case 5:          return "(SHT_HASH)";
    case 6:          return "(SHT_DYNAMIC)";
    case 7:          return "(SHT_NOTE)";
    case 8:          return "(SHT_NOBITS)";
    case 9:          return "(SHT_REL)";
    case 10:         return "(SHT_SHLIB)";
    case 11:         return "(SHT_DYNSYM)";
    case 14:         return "(SHT_INIT_ARRAY)";
    case 15:         return "(SHT_FINI_ARRAY)";
    case 16:         return "(SHT_PREINIT_ARRAY)";
    case 17:         return "(SHT_GROUP)";
    case 18:         return "(SHT_SYMTAB_SHNDX)";
    case 0x60000000: return "(SHT_LOOS)";
    case 0x6fffffff: return "(SHT_HIOS)";
    case 0x70000000: return "(SHT_LOPROC)";
    case 0x7fffffff: return "(SHT_HIPROC)";
    case 0x80000000: return "(SHT_LOUSER)";
    case 0xffffffff: return "(SHT_HIUSER)";
    default:         return "(Unknown)";
  }
}

std::string Section::get_flags_type()
{
  std::string value = "";

  if ((sh_flags & 0x00000001) != 0) { value += "SHF_WRITE "; }
  if ((sh_flags & 0x00000002) != 0) { value += "SHF_ALLOC "; }
  if ((sh_flags & 0x00000004) != 0) { value += "SHF_EXECINSTR "; }
  if ((sh_flags & 0x00000010) != 0) { value += "SHF_MERGE "; }
  if ((sh_flags & 0x00000020) != 0) { value += "SHF_STRINGS "; }
  if ((sh_flags & 0x00000040) != 0) { value += "SHF_INFO_LINK "; }
  if ((sh_flags & 0x00000080) != 0) { value += "SHF_LINK_ORDER "; }
  if ((sh_flags & 0x00000100) != 0) { value += "SHF_OS_NONCONFORMING "; }
  if ((sh_flags & 0x00000200) != 0) { value += "SHF_GROUP "; }
  if ((sh_flags & 0x00000400) != 0) { value += "SHF_TLS "; }
  if ((sh_flags & 0x0ff00000) != 0) { value += "SHF_MASKOS "; }
  if ((sh_flags & 0xf0000000) != 0) { value += "SHF_MASKPROC "; }

  return value;
}

