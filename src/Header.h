/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2024 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_HEADER_H
#define MAGIC_ELF_HEADER_H

#include <string.h>
#include <stdint.h>

struct Header
{
  Header() :
    ei_class      { 0 },
    ei_data       { 0 },
    ei_version    { 0 },
    ei_osabi      { 0 },
    ei_abiversion { 0 },
    e_type        { 0 },
    e_machine     { 0 },
    e_version     { 0 },
    e_entry       { 0 },
    e_phoff       { 0 },
    e_shoff       { 0 },
    e_flags       { 0 },
    e_ehsize      { 0 },
    e_phentsize   { 0 },
    e_phnum       { 0 },
    e_shentsize   { 0 },
    e_shnum       { 0 },
    e_shstrndx    { 0 }
  {
    memset(e_ident, 0, sizeof(e_ident));
  }

  ~Header()
  {
  }

  const char *get_class_type();
  const char *get_data_type();
  const char *get_osabi_type();
  const char *get_type_type();
  const char *get_machine_type();

  uint8_t e_ident[16];

  uint8_t ei_class;
  uint8_t ei_data;
  uint8_t ei_version;
  uint8_t ei_osabi;
  uint8_t ei_abiversion;

  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;

  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint32_t e_ehsize;
  uint32_t e_phentsize;
  uint32_t e_phnum;
  uint32_t e_shentsize;
  uint32_t e_shnum;
  uint32_t e_shstrndx;
};

#endif

