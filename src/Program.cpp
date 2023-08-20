/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include "defines.h"
#include "Program.h"

const char *Program::get_header_type()
{
  const char *types[] =
  {
    "NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS", "NUM"
  };

  if (p_type <= 8)
  {
    return types[p_type];
  }

  if (p_type == 0x6474e550) { return "GNU_EH_FRAME"; }
  if (p_type == 0x6474e551) { return "GNU_STACK"; }
  if (p_type == 0x6474e552) { return "GNU_RELRO"; }

  return "UNKNOWN";
}

const char *Program::get_flags_type()
{
  const char *flags[] =
  {
    "---", "--X", "-W-", "-WX", "R--", "R-X", "RW-", "RWX"
  };

  return flags[p_flags & 7];
}

const char *Program::get_note_type(int type)
{
  switch (type)
  {
    case NT_PRSTATUS:   return "NT_PRSTATUS";
    case NT_PRFPREG:    return "NT_PRFPREG";
    case NT_PRPSINFO:   return "NT_PRPSINFO";
    case NT_TASKSTRUCT: return "NT_TASKSTRUCT";
    case NT_AUXV:       return "NT_AUXV";
    case NT_386_TLS:    return "NT_386_TLS";
    case NT_SIGINFO:    return "NT_SIGINFO";
    case NT_FILE:       return "NT_FILE";
    case NT_PRXFPREG:   return "NT_PRXFPREG";
    default:            return "[unknown]";
  }
}

