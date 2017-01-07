/*

magic_elf - The ELF file format analyzer.

Copyright 2009-2017 - Michael Kohn (mike@mikekohn.net)
http://www.mikekohn.net/

This program falls under the BSD license. 

*/

#include <stdint.h>

#include "magic_elf_io.h"

uint16_t get_int16_be(elf_info_t *elf_info, long offset)
{
  uint16_t i;

  i = GET_BIG_ENDIAN16(elf_info->buffer, offset);

  return i;
}

uint32_t get_int32_be(elf_info_t *elf_info, long offset)
{
uint32_t i;

  i = GET_BIG_ENDIAN32(elf_info->buffer, offset);

  return i;
}

uint64_t get_int64_be(elf_info_t *elf_info, long offset)
{
  uint64_t i;

  i = GET_BIG_ENDIAN64(elf_info->buffer, offset);

  return i;
}

uint16_t get_int16_le(elf_info_t *elf_info, long offset)
{
  uint16_t i;

  i = GET_LITTLE_ENDIAN16(elf_info->buffer, offset);

  return i;
}

uint32_t get_int32_le(elf_info_t *elf_info, long offset)
{
  uint32_t i;

  i = GET_LITTLE_ENDIAN32(elf_info->buffer, offset);

  return i;
}

uint64_t get_int64_le(elf_info_t *elf_info, long offset)
{
  uint64_t i;

  i = GET_LITTLE_ENDIAN64(elf_info->buffer, offset);

  return i;
}

uint16_t read_int16_be(elf_info_t *elf_info)
{
  uint16_t i;

  i = GET_BIG_ENDIAN16(elf_info->buffer, elf_info->file_ptr);

  elf_info->file_ptr += 2;
  return i;
}

uint32_t read_int32_be(elf_info_t *elf_info)
{
  uint32_t i;

  i = GET_BIG_ENDIAN32(elf_info->buffer, elf_info->file_ptr);

  elf_info->file_ptr += 4;
  return i;
}

uint64_t read_int64_be(elf_info_t *elf_info)
{
  uint64_t i;

  i = GET_BIG_ENDIAN64(elf_info->buffer, elf_info->file_ptr);

  elf_info->file_ptr += 8;
  return i;
}

uint16_t read_int16_le(elf_info_t *elf_info)
{
  uint16_t i;

  i = GET_LITTLE_ENDIAN16(elf_info->buffer, elf_info->file_ptr);

  elf_info->file_ptr += 2;
  return i;
}

uint32_t read_int32_le(elf_info_t *elf_info)
{
  uint32_t i;

  i = GET_LITTLE_ENDIAN32(elf_info->buffer, elf_info->file_ptr);

  elf_info->file_ptr += 4;
  return i;
}

uint64_t read_int64_le(elf_info_t *elf_info)
{
  uint64_t i;

  i = GET_LITTLE_ENDIAN64(elf_info->buffer, elf_info->file_ptr);

  elf_info->file_ptr += 8;
  return i;
}

uint8_t read_int8(elf_info_t *elf_info)
{
  return elf_info->buffer[elf_info->file_ptr++];
}


