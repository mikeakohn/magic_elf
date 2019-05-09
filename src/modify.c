/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2019 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "modify.h"

// FIXME: This doesn't take care of big endian.

int modify_function(
  const char *filename,
  const char *function_name,
  long file_offset,
  uint64_t ret_value,
  int bits)
{
  FILE *fp = fopen(filename, "rb+");

  fseek(fp, file_offset, SEEK_SET);

  if (bits == 32)
  {
    putc(0xb8, fp);
    putc(ret_value & 0xff, fp);
    putc((ret_value >> 8) & 0xff, fp);
    putc((ret_value >> 16) & 0xff, fp);
    putc((ret_value >> 24) & 0xff, fp);
    putc(0xc3, fp);
  }
    else
  if (bits == 64)
  {
    putc(0x48, fp);
    putc(0xb8, fp);
    putc(ret_value & 0xff, fp);
    putc((ret_value >> 8) & 0xff, fp);
    putc((ret_value >> 16) & 0xff, fp);
    putc((ret_value >> 24) & 0xff, fp);
    putc((ret_value >> 32) & 0xff, fp);
    putc((ret_value >> 40) & 0xff, fp);
    putc((ret_value >> 48) & 0xff, fp);
    putc((ret_value >> 56) & 0xff, fp);
    putc(0xc3, fp);
  }

  fclose(fp);

  printf("Function %s modified to do nothing except return %" PRId64 ".\n",
    function_name, ret_value);

  return 0;
}

