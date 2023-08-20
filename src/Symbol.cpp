/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdint.h>

#include "Symbol.h"

const char *Symbol::get_symbol_binding()
{
  switch (st_info >> 4)
  {
    case 0:  return "LOCAL";
    case 1:  return "GLOBAL";
    case 2:  return "WEAK";
    case 10: return "LOOS";
    case 12: return "HIOS";
    case 13: return "LOPROC";
    case 15: return "HIPROC";
    default: return "";
  }
}

const char *Symbol::get_symbol_type()
{
  switch (st_info & 0xf) 
  {
    case 0:  return "NOTYPE";
    case 1:  return "OBJECT";
    case 2:  return "FUNC";
    case 3:  return "SECTION";
    case 4:  return "FILE";
    case 10: return "LOOS";
    case 12: return "HIOS";
    case 13: return "LOPROC";
    case 15: return "HIPROC";
    default: return "";
  }
}

