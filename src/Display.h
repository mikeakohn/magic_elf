/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_DISPLAY_H
#define MAGIC_ELF_DISPLAY_H

#include <stdint.h>

class Display
{
public:
  static int symbol_value(const char *filename, const char *symbol_name);

private:
  Display();
  ~Display();
};

#endif

