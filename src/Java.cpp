/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "Java.h"

void Java::extract(const char *filename)
{
  FILE *in;
  const int cafebabe[] = { 0xca, 0xfe, 0xba, 0xbe };
  int ptr = 0, ch;
  uint64_t progress = 0;
  Code code;

  memset(&code, 0, sizeof(code));

  in = fopen(filename, "rb");

  if (in == NULL)
  {
    printf("Error: Cannot open file %s\n", filename);
    exit(1);
  }

  code.size = 65536;
  code.data = (uint8_t *)malloc(code.size);

  while (1)
  {
    ch = getc(in);
    if (ch == EOF) { break; }

    if (ch == cafebabe[ptr++])
    {
      if (ptr == 4)
      {
        code.start = ftell(in) - 4;
        ptr = 0;
        code.length = 0;

        if (extract_header(in, &code) != 0) { continue; }
        if (extract_constants(in, &code) != 0) { continue; }
        if (extract_info(in, &code) != 0) { continue; }
        if (extract_interfaces(in, &code) != 0) { continue; }
        if (extract_fields(in, &code) != 0) { continue; }
        if (extract_methods(in, &code) != 0) { continue; }
        if (extract_attributes(in, &code) != 0) { continue; }

        dump(&code);
      }
    }
    else
    {
      ptr = 0;
    }

    progress++;

    if ((progress % 10000000) == 0)
    {
      printf("%" PRId64 "MB %ld\n", progress / 1024 / 1024, ftell(in));
    }
  }

  free(code.constant_index);
  free(code.data);

  fclose(in);
}

uint16_t Java::get_uint8(FILE *in, Code *code)
{
  int ptr = code->length;

  if (code->length + 1 > code->size)
  {
    code->size *= 2;
    code->data = (uint8_t *)realloc(code->data, code->size);
  }

  code->data[code->length++] = getc(in);

  return code->data[ptr + 0];
}

uint16_t Java::get_uint16(FILE *in, Code *code)
{
  int ptr = code->length;

  if (code->length + 2 > code->size)
  {
    code->size *= 2;
    code->data = (uint8_t *)realloc(code->data, code->size);
  }

  code->data[code->length++] = getc(in);
  code->data[code->length++] = getc(in);

  return (code->data[ptr + 0] << 8) | code->data[ptr + 1];
}

uint32_t Java::get_uint32(FILE *in, Code *code)
{
  int ptr = code->length;

  if (code->length + 4 > code->size)
  {
    code->size *= 2;
    code->data = (uint8_t *)realloc(code->data, code->size);
  }

  code->data[code->length++] = getc(in);
  code->data[code->length++] = getc(in);
  code->data[code->length++] = getc(in);
  code->data[code->length++] = getc(in);

  return (code->data[ptr + 0] << 24) | \
         (code->data[ptr + 1] << 16) | \
         (code->data[ptr + 2] << 8) | \
          code->data[ptr + 3];
}

uint64_t Java::get_uint64(FILE *in, Code *code)
{
  int n;

  if (code->length + 8 > code->size)
  {
    code->size *= 2;
    code->data = (uint8_t *)realloc(code->data, code->size);
  }

  for (n = 0; n < 8; n++)
  {
    code->data[code->length++] = getc(in);
  }

  // Should never need to actually return this.
  return 0;
}

void Java::copy_attribute(FILE *in, Code *code)
{
  uint32_t n;

  get_uint16(in, code);
  uint32_t length = get_uint32(in, code);

  for (n = 0; n < length; n++)
  {
    get_uint8(in, code);
  }
}

int Java::extract_header(FILE *in, Code *code)
{
  code->length = 10;
  code->data[0] = 0xca;
  code->data[1] = 0xfe;
  code->data[2] = 0xba;
  code->data[3] = 0xbe;

  int n = fread(code->data + 4, 1, 6, in);
  if (n != 6) { return -1; }
  if (code->data[6] != 0 || code->data[7] < 0x2d) { return -1; }

  return 0;
}

int Java::extract_constants(FILE *in, Code *code)
{
  int constant_count = (code->data[8] << 8) | code->data[9];
  int length, n, r;

  if (code->constant_index_size < constant_count * 4)
  {
    code->constant_index = (uint32_t *)realloc(
      code->constant_index,
      constant_count * sizeof(uint32_t));

    code->constant_index_size = constant_count;
  }

  for (n = 1; n < constant_count; n++)
  {
    code->constant_index[n] = code->length;

    uint8_t tag = get_uint8(in, code);

    switch (tag)
    {
      case 1:
        // UTF-8.
        length = get_uint16(in, code);
        for (r = 0; r < length; r++) { get_uint8(in, code); }
        break;
      case 3:
        // Integer.
        get_uint32(in, code);
        break;
      case 4:
        // Float.
        get_uint32(in, code);
        break;
      case 5:
        // Long.
        get_uint64(in, code);
        n++;
        break;
      case 6:
        // Double.
        get_uint64(in, code);
        n++;
        break;
      case 7:
        // Class.
        get_uint16(in, code);
        break;
      case 8:
        // String.
        get_uint16(in, code);
        break;
      case 9:
        // FieldRef.
        get_uint16(in, code);
        get_uint16(in, code);
        break;
      case 10:
        // MethodRef.
        get_uint16(in, code);
        get_uint16(in, code);
        break;
      case 11:
        // InterfaceMethodRef.
        get_uint16(in, code);
        get_uint16(in, code);
        break;
      case 12:
        // NameAndType.
        get_uint16(in, code);
        get_uint16(in, code);
        break;
      case 15:
        // MethodHandle.
        get_uint8(in, code);
        get_uint16(in, code);
        break;
      case 16:
        // MethodType.
        get_uint16(in, code);
        break;
      case 18:
        // InvokeDynamic.
        get_uint32(in, code);
        break;
      case 19:
      case 20:
        // Unknown?
        get_uint16(in, code);
        break;
      default:
        printf("Unknown constant tag %d at %d / %ld\n",
          tag, code->length, code->start);
        return -1;
    }
  }

  return 0;
}

int Java::extract_info(FILE *in, Code *code)
{
  int offset;

  get_uint16(in, code);
  int class_index = get_uint16(in, code);
  get_uint16(in, code);

  offset = code->constant_index[class_index];
  code->class_name = (code->data[offset + 1] << 8) | code->data[offset + 2];

  return 0;
}

int Java::extract_interfaces(FILE *in, Code *code)
{
  int interface_count = get_uint16(in, code);
  int n;

  for (n = 0; n < interface_count; n++)
  {
    get_uint16(in, code);
  }

  return 0;
}

int Java::extract_fields(FILE *in, Code *code)
{
  int field_count = get_uint16(in, code);
  int n, r;

  for (n = 0; n < field_count; n++)
  {
    get_uint16(in, code);
    get_uint16(in, code);
    get_uint16(in, code);
    int attribute_count = get_uint16(in, code);

    for (r = 0; r < attribute_count; r++)
    {
      copy_attribute(in, code);
    }
  }

  return 0;
}

int Java::extract_methods(FILE *in, Code *code)
{
  int method_count = get_uint16(in, code);
  int n, r;

  for (n = 0; n < method_count; n++)
  {
    get_uint16(in, code);
    get_uint16(in, code);
    get_uint16(in, code);
    int attribute_count = get_uint16(in, code);

    for (r = 0; r < attribute_count; r++)
    {
      copy_attribute(in, code);
    }
  }

  return 0;
}

int Java::extract_attributes(FILE *in, Code *code)
{
  int attribute_count = get_uint16(in, code);
  int n;

  for (n = 0; n < attribute_count; n++)
  {
    copy_attribute(in, code);
  }

  return 0;
}

int Java::dump(Code *code)
{
  int offset = code->constant_index[code->class_name];
  int length = (code->data[offset + 1] << 8) | code->data[offset + 2];

  char *filename = (char *)alloca(length + sizeof(".class"));

  int i;
  for (i = 0; i < length; i++)
  {
    int ch = code->data[offset + 3 + i];
    filename[i] = ch == '/' ? '.' : ch;
  }

  filename[i] = 0;
  strcat(filename, ".class");

  printf("Found %s at %ld.\n", filename, code->start);

  FILE *out = fopen(filename, "wb");

  if (out == NULL)
  {
    printf("Error: Cannot open file %s for writing.\n", filename);
    return -1;
  }

  fwrite(code->data, 1, code->length, out);

  fclose(out);

  return 0;
}

