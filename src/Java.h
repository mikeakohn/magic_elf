/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_JAVA_H
#define MAGIC_ELF_JAVA_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

class Java
{
public:
  static void extract(const char *filename);

private:
  Java() { }
  ~Java() { }

  struct Code
  {       
    int length;
    int size;
    uint8_t *data;
    uint16_t class_name;
    uint32_t *constant_index;
    int constant_index_size;
    long start;
  };

  static uint16_t get_uint8(FILE *in, struct Code *code);
  static uint16_t get_uint16(FILE *in, struct Code *code);
  static uint32_t get_uint32(FILE *in, struct Code *code);
  static uint64_t get_uint64(FILE *in, struct Code *code);
  static void copy_attribute(FILE *in, struct Code *code);
  static int extract_header(FILE *in, struct Code *code);
  static int extract_constants(FILE *in, struct Code *code);
  static int extract_info(FILE *in, struct Code *code);
  static int extract_interfaces(FILE *in, struct Code *code);
  static int extract_fields(FILE *in, struct Code *code);
  static int extract_methods(FILE *in, struct Code *code);
  static int extract_attributes(FILE *in, struct Code *code);
  static int dump(struct Code *code);
};

#endif

