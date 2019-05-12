/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

  Useful page: http://www.sco.com/developers/gabi/latest/contents.html

*/

#include <stdio.h>
#include <stdlib.h>

#include "magic_elf.h"
#include "magic_elf_print.h"

int main(int argc, char *argv[])
{
  elf_info_t *elf_info;

  int (*add_nums)(int a, int b);

  printf("\nmagic_elf - Copyright 2009 by Michael Kohn <mike@mikekohn.net>\n");
  printf("http://www.mikekohn.net/\n");
  printf("Version: September 4, 2011\n\n");

  elf_info = open_elf("test.so");

  if (elf_info == 0)
  {
    printf("Couldn't open file or not an elf\n");
    exit(0);
  }

  printf("add_nums=%p\n", find_symbol_address(elf_info, "add_nums"));

  add_nums = find_symbol_address(elf_info, "add_nums");

  printf("add_nums(7,100)=%d\n", add_nums(7, 100));

  close_elf(&elf_info);

  return 0;
}

