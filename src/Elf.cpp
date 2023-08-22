/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include "defines.h"
#include "Elf.h"
#include "Elf32.h"
#include "Elf64.h"
#include "ElfX86_32.h"
#include "ElfX86_64.h"
#include "file_io.h"

Elf::Elf() :
  fd                  { -1 },
  bitwidth            { 0 },
  buffer_len          { 0 },
  file_ptr            { 0 },
  is_little_endian    { true },
  string_table_offset { 0 },
  symbol_table_offset { 0 },
  symbol_table_length { 0 },
  str_sym_tbl_offset  { 0 }
{
}

Elf::~Elf()
{
  if (fd > 0)
  {
#ifdef _WIN32
    UnmapViewOfFile(mem);
    CloseHandle(mem_handle);
    CloseHandle(fd);
#else
    munmap(buffer, buffer_len);
    close(fd);
#endif
  }
}

Elf *Elf::open_elf(const char *filename, bool writable)
{
  Elf *elf;

  // Open file to figure out if it's little endian / 32 or 64 bit.
  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) { return NULL; }

  uint8_t buffer[20];
  if (fread(buffer, 1, sizeof(buffer), fp) != sizeof(buffer))
  {
    printf("Error: File not found.\n");
    fclose(fp);
    return NULL;
  }

  fclose(fp);

  int ei_class = buffer[4];
  int ei_data  = buffer[5];
  int e_machine = ei_data == 1 ?
    buffer[18] | (buffer[19] << 8) :
    buffer[19] | (buffer[18] << 8);

  elf = create_instance(ei_class, e_machine);

  elf->is_little_endian = buffer[5] == 1;

  if (elf->read_file(filename, writable) != 0)
  {
    printf("Error: Cannot open file (readonly?).\n");
    delete elf;
    return nullptr;
  }

  elf->read_header();

  return elf;
}

Elf *Elf::open_elf_from_mem(void *mem_ptr)
{
  Elf *elf;
  uint8_t *ident = (uint8_t *)mem_ptr;

  int ei_data  = ident[5];
  int e_machine = ei_data == 1 ?
    ident[18] | (ident[19] << 8) :
    ident[19] | (ident[18] << 8);

  elf = create_instance(ident[4], e_machine);

  elf->is_little_endian = ident[5] == 1;
  elf->buffer = (uint8_t *)mem_ptr;

  return elf;
}

int Elf::read_file(const char *filename, bool writable)
{
  struct stat stat_buf;

  fd = open(filename, writable ? O_RDWR : O_RDONLY);

  if (fd == -1) { return -1; }
  fstat(fd, &stat_buf);

  buffer_len = stat_buf.st_size;

#ifdef _WIN32
  close(fd);

  fd = CreateFile(
    filename,
    FILE_READ_DATA,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_READONLY,
    NULL);

  mem_handle = CreateFileMapping(
    fd,
    NULL,
    PAGE_READONLY,
    0,
    buffer_len,
    NULL);

  buffer = (uint8_t *)MapViewOfFile(
    mem_handle,
    FILE_MAP_READ,
    0,
    0,
    buffer_len);
#else
  buffer = (uint8_t *)mmap(
    NULL,
    buffer_len,
    //PROT_EXEC | PROT_READ,
    PROT_READ,
    MAP_SHARED,
    fd,
    0);
#endif

  return 0;
}

int Elf::read_header()
{
  memcpy(header.e_ident, buffer, 16);

  header.ei_class      = header.e_ident[4];
  header.ei_data       = header.e_ident[5];
  header.ei_version    = header.e_ident[6];
  header.ei_osabi      = header.e_ident[7];
  header.ei_abiversion = header.e_ident[8];

  set_file_ptr(16);

  header.e_type      = read_half();
  header.e_machine   = read_half();
  header.e_version   = read_word();
  header.e_entry     = read_addr();
  header.e_phoff     = read_offset();
  header.e_shoff     = read_offset();
  header.e_flags     = read_word();
  header.e_ehsize    = read_half();
  header.e_phentsize = read_half();
  header.e_phnum     = read_half();
  header.e_shentsize = read_half();
  header.e_shnum     = read_half();
  header.e_shstrndx  = read_half();

  compute_string_table_offset();

  str_sym_tbl_offset = find_section_offset(SHT_STRTAB, ".strtab", NULL);
  symbol_table_offset = find_section_offset(SHT_SYMTAB, NULL, &symbol_table_length);

  return 0;
}

void Elf::print_header()
{
  printf("Elf Header\n");
  printf("---------------------------------------------\n");
  printf("    e_ident:");

  for (int t = 0; t < 16; t++)
  {
    printf(" %02x", header.e_ident[t]);
  }
  printf("\n");

  printf("             EI_MAGIC=0x7f ELF\n");
  printf("             EI_CLASS=%d %s\n",
    header.ei_class,
    header.get_class_type());

  printf("             EI_DATA=%d %s\n",
    header.ei_data,
    header.get_data_type());

  printf("             EI_VERSION=%d\n", header.ei_version);
  printf("             EI_OSABI=%d %s\n",
     header.ei_osabi,
     header.get_osabi_type());
  printf("             EI_ABIVER=%d\n", header.ei_abiversion);

  set_file_ptr(16);

  printf("     e_type: %02x %s\n", header.e_type, header.get_type_type());
  printf("  e_machine: 0x%x %s\n", header.e_machine, header.get_machine_type());
  printf("  e_version: %d\n", header.e_version);
  printf("    e_entry: 0x%" PRIx64 " (virt addr)\n", header.e_entry);
  printf("    e_phoff: 0x%" PRIx64 " (program header table offset)\n",
    header.e_phoff);
  printf("    e_shoff: 0x%" PRIx64 " (section header table offset)\n",
    header.e_shoff);
  printf("    e_flags: 0x%08x (processor specific flags)\n", header.e_flags);
  printf("   e_ehsize: 0x%08x (elf header size)\n", header.e_ehsize);
  printf("e_phentsize: %d (program header table size)\n", header.e_phentsize);
  printf("    e_phnum: %d (program header table count)\n", header.e_phnum);
  printf("e_shentsize: %d (section header size)\n", header.e_shentsize);
  printf("    e_shnum: %d (section header count)\n", header.e_shnum);
  printf(" e_shstrndx: %d (section header string table index)\n\n",
    header.e_shstrndx);
}

void Elf::print_program_headers()
{
  printf("Elf Program Headers (count=%d)\n\n", get_program_count());

  for (int count = 0; count < get_program_count(); count++)
  {
    set_file_ptr(get_program_offset() + (get_program_size() * count));

    printf("Program Header %d (offset=0x%04" PRIx64 ")\n", count, file_ptr);
    printf("---------------------------------------------\n");

    Program program;
    read_program(program);
    print_program(program);

    if (program.p_type == PT_NOTE)
    {
      print_program_note(program);
    }
  }
}

void Elf::print_program_note(Program &program)
{
  uint32_t align_mask = bitwidth == 32 ? 3 : 7;
  uint64_t bytes_used = 0;

  set_file_ptr(program.p_offset);

  while (bytes_used < program.p_filesz)
  {
    int namesz = read_word();
    int descsz = read_word();
    int type   = read_word();

    int namesz_align = (namesz + align_mask) & ~align_mask;
    int descsz_align = (descsz + align_mask) & ~align_mask;
    char name[1024];

    read_note_name(name, sizeof(name), namesz, namesz_align);

    // FIXME - There's a lot more things that can be put in here.
    // They will come back as unknown, but can be added as needed.
    printf("%8s 0x%04x  [0x%x] %s\n",
      name, descsz, type, program.get_note_type(type));

    // FIXME - Um. When there is a GNU section it's 4 bytes off. Why?
    if (strcmp(name, "GNU") == 0)
    {
      for (int n = 0; n < descsz; n++)
      {
        uint8_t c = read_int8();

        if (c >= ' ' && c < 127)
        {
          printf("%c", c);
        }
        else
        {
          printf("<%02x>", c);
        }
      }
      printf("\n");
      break;
    }

    bool is_core = strcmp(name, "CORE") == 0;

    switch (type)
    {
      case NT_PRSTATUS:
        if (is_core) { print_core_prstatus(); }
        break;
      case NT_PRFPREG:
        //print_core_regs();
        break;
      case 3:
        if (is_core) { print_core_prpsinfo(); }
        break;
      case NT_SIGINFO:
        if (is_core) { print_core_siginfo(); }
        break;
      case NT_FILE:
        print_core_mapped_files(descsz);
        break;
      default:
        break;
    }

    file_ptr += descsz_align;

    bytes_used += (4 * 3) + namesz_align + descsz_align;
  }

  printf("\n");
}

uint64_t Elf::get_core_registers_from_note(Program &program, uint32_t pid)
{
  uint32_t align_mask = bitwidth == 32 ? 3 : 7;
  uint64_t bytes_used = 0;

  push_ptr();

  set_file_ptr(program.p_offset);

  while (bytes_used < program.p_filesz)
  {
    int namesz = read_word();
    int descsz = read_word();
    int type   = read_word();

    int namesz_align = (namesz + align_mask) & ~align_mask;
    int descsz_align = (descsz + align_mask) & ~align_mask;
    char name[1024];

    read_note_name(name, sizeof(name), namesz, namesz_align);

    if (strcmp(name, "CORE") == 0)
    {
      if (type == NT_PRSTATUS)
      {
        push_ptr();
        PRStatus prstatus;
        read_core_prstatus(prstatus);
        uint64_t offset = file_ptr;
        pop_ptr();

        if (prstatus.pid == pid)
        {
          pop_ptr();
          return offset;
        }
      }
    }

    file_ptr += descsz_align;

    bytes_used += (4 * 3) + namesz_align + descsz_align;
  }

  pop_ptr();

  return 0;
}

void Elf::read_note_name(char *name, int length, int namesz, int namesz_align)
{
  if (namesz < length - 1)
  {
    int n;
    for (n = 0; n < namesz; n++) { name[n] = read_int8(); }
    name[n] = 0;

    file_ptr += namesz_align - namesz;
  }
    else
  {
    file_ptr += namesz_align;
    name[0] = 0;
  }
}

void Elf::read_core_prstatus(PRStatus &prstatus)
{
  prstatus.signal_number = read_int32();
  prstatus.extra_code = read_int32();
  prstatus._errno = read_int32();
  prstatus.cursig = read_int16();

  if (bitwidth == 64)
  {
    prstatus.unknown_1 = read_int16();
  }

  prstatus.sigpend = read_offset();
  prstatus.sighold = read_offset();

  prstatus.pid = read_int32();
  prstatus.ppid = read_int32();
  prstatus.pgrp = read_int32();
  prstatus.psid = read_int32();

  prstatus.user_time_sec = read_offset();
  prstatus.user_time_usec = read_offset();
  prstatus.system_time_sec = read_offset();
  prstatus.system_time_usec = read_offset();
  prstatus.cumulative_user_time_sec = read_offset();
  prstatus.cumulative_user_time_usec = read_offset();
  prstatus.cumulative_system_time_sec = read_offset();
  prstatus.cumulative_system_time_usec = read_offset();
}

void Elf::print_core_prstatus()
{
  push_ptr();

  PRStatus prstatus;
  read_core_prstatus(prstatus);

  printf("        signal_number: %d\n", prstatus.signal_number);
  printf("           extra_code: %d\n", prstatus.extra_code);
  printf("                errno: %d\n", prstatus._errno);
  printf("               cursig: %d\n", prstatus.cursig);

  printf("              sigpend: %" PRId64 "\n", prstatus.sigpend);
  printf("              sighold: %" PRId64 "\n", prstatus.sighold);

  printf("                  pid: %d\n", prstatus.pid);
  printf("                 ppid: %d\n", prstatus.ppid);
  printf("                 pgrp: %d\n", prstatus.pgrp);
  printf("                 psid: %d\n", prstatus.psid);

  printf("            user time: %" PRId64 " %" PRId64 "\n",
    prstatus.user_time_sec,
    prstatus.user_time_usec);
  printf("          system time: %" PRId64 " %" PRId64 "\n",
    prstatus.system_time_sec,
    prstatus.system_time_usec);
  printf(" cumulative user time: %" PRId64 " %" PRId64 "\n",
    prstatus.cumulative_user_time_sec,
    prstatus.cumulative_user_time_usec);
  printf("  cumulative sys time: %" PRId64 " %" PRId64 "\n",
    prstatus.cumulative_system_time_sec,
    prstatus.cumulative_system_time_usec);

  print_registers();
  pop_ptr();
}

void Elf::print_core_prpsinfo()
{
  push_ptr();

  char filename[16];
  char args[80];
  int n;
  printf("            state: %d\n", read_int8());
  printf("            sname: %d\n", read_int8());
  printf("           zombie: %d\n", read_int8());
  printf("             nice: %d\n", read_int8());
  // FIXME - only 64 bit?
  file_ptr += 4;
  printf("             flag: %" PRId64 "\n", read_offset());
  //printf("             flag: %d\n", read_int32());
  printf("              uid: %d\n", read_int32());
  printf("              gid: %d\n", read_int32());
  printf("              pid: %d\n", read_int32());
  printf("             ppid: %d\n", read_int32());
  printf("             pgrp: %d\n", read_int32());
  printf("              sid: 0x%x\n", read_int32());
  for (n = 0; n < 16; n++) { filename[n] = read_int8(); }
  printf("         filename: '%.16s'\n", filename);
  for (n = 0; n < 80; n++) { args[n] = read_int8(); }
  printf("             args: '%.80s'\n", args);

  pop_ptr();
}

void Elf::print_core_siginfo()
{
  push_ptr();

  printf("        signal_number: %d\n", read_int32());
  printf("           extra_code: %d\n", read_int32());
  printf("                errno: %d\n", read_int32());

  pop_ptr();
}

void Elf::print_section_headers()
{
  printf("Elf Section Headers (count=%d)\n\n", get_section_count());

  for (int count = 0; count < get_section_count(); count++)
  {
    set_file_ptr(get_section_offset() + (get_section_size() * count));

    printf("Section Header %d (offset=0x%04" PRIx64 ")\n", count, file_ptr);
    printf("---------------------------------------------\n");

    Section section;
    read_section(section);
    print_section(section);
  }
}

void Elf::print_section(Section &section)
{
  std::string section_name = get_string(section.sh_name);

  printf("     sh_name: %d (%s)\n", section.sh_name, section_name.c_str());
  printf("     sh_type: %d %s\n", section.sh_type, section.get_section_type());
  printf("    sh_flags: 0x%" PRIx64 " (%s)\n",
    section.sh_flags,
    section.get_flags_type().c_str());
  printf("     sh_addr: 0x%" PRIx64 "\n", section.sh_addr);
  printf("   sh_offset: 0x%" PRIx64 "\n", section.sh_offset);
  printf("     sh_size: %" PRId64 "\n", section.sh_size);
  printf("     sh_link: %d\n", section.sh_link);
  printf("     sh_info: %d\n", section.sh_info);
  printf("sh_addralign: %" PRId64 "\n", section.sh_addralign);
  printf("  sh_entsize: %" PRId64 "\n\n", section.sh_entsize);

  print_section_data(section, section_name);
}

void Elf::print_symbol(Symbol &symbol, uint64_t string_table_offset)
{
  printf("  %s\n", buffer + string_table_offset + symbol.st_name);
  printf("     name: %d\n", symbol.st_name);
  printf("     info: %d (%s) (%s)\n",
    symbol.st_info,
    symbol.get_symbol_binding(),
    symbol.get_symbol_type());
  printf("    other: %d\n", symbol.st_other);
  printf("    shndx: %d\n", symbol.st_shndx);
  printf("    value: %" PRId64 " (0x%" PRIx64 ")\n",
    symbol.st_value,
    symbol.st_value);
  printf("     size: %" PRId64 "\n", symbol.st_size);
}

void Elf::print_section_data(Section &section, std::string &name)
{
  if (name == "") { return; }

  if (name == ".comment")
  {
    print_section_comment((char *)buffer + section.sh_offset, section.sh_size);
  }
    else
  if (name == ".strtab" || section.sh_type == SHT_STRTAB)
  {
    print_section_string_table(buffer + section.sh_offset, section.sh_size);
  }
    else
  if (name == ".shstrtab")
  {
    print_section_string_table(buffer + section.sh_offset, section.sh_size);
  }
    else
  if (name == ".rel.text")
  {
    // Probably should get a size here too :(
    int symtab_offset = find_section_offset(SHT_SYMTAB, ".symtab", NULL);
    int strtab_offset = find_section_offset(SHT_STRTAB, ".strtab", NULL);

    print_section_relocation(
      section.sh_offset,
      section.sh_size,
      symtab_offset,
      strtab_offset);
  }
    else
  if (name == ".symtab")
  {
    int strtab_offset = find_section_offset(SHT_STRTAB, ".strtab", NULL);

    print_section_symbol_table(
      section.sh_offset,
      section.sh_size,
      section.sh_entsize,
      strtab_offset);
  }
    else
  if (name == ".dynsym")
  {
    int strtab_offset = find_section_offset(SHT_STRTAB, ".dynstr", NULL);
    print_section_symbol_table(
      section.sh_offset,
      section.sh_size,
      section.sh_entsize,
      strtab_offset);
  }
    else
  if (name == ".ARM.attributes" || section.sh_type == SHT_STRTAB)
  {
    print_section_arm_attrs(buffer + section.sh_offset, section.sh_size);
  }
#if 0
    else
  if (name == ".dynamic")
  {
    print_section_dynamic(section.sh_offset, section.sh_size);
  }
#endif
}

void Elf::print_section_comment(const char *comment, int size)
{
  for (int n = 0; n < size; n++)
  {
    if (comment[n] >= 32 && comment[n] < 127)
    {
      printf("%c", comment[n]);
    }
      else
    {
      printf("[%02x]", comment[n]);
    }
  }

  printf("\n\n");
}

void Elf::print_section_string_table(uint8_t *table, int size)
{
  int index = 0;
  int len = 0;

  for (int n = 0; n < size; n++)
  {
    if (len == 0) { printf("\n   [%d] %d: ", n, index++); }

    if (table[n] >= 32 && table[n] < 127)
    {
      printf("%c", table[n]);
    }
      else
    {
      if (table[n] == 0) { len = 0; continue; }
      printf("[%02x]", table[n]);
    }

    len++;
  }

  printf("\n\n");
}

void Elf::print_section_symbol_table(
  int offset,
  int sh_size,
  int sh_entsize,
  int string_table_offset)
{
  push_ptr();

  set_file_ptr(offset);
  uint64_t end = file_ptr + sh_size;
  Symbol symbol;

  while (file_ptr < end)
  {
    read_symbol(symbol);
    print_symbol(symbol, string_table_offset);
  }

  pop_ptr();
}

void Elf::print_section_arm_attrs(uint8_t *attrs, int sh_size)
{
  char text[17];
  int ptr;

  ptr = 0;

  for (int n = 0; n < sh_size; n++)
  {
    if ((n % 16) == 0)
    {
      if (ptr != 0) { text[ptr] = 0; printf("  %s", text); ptr = 0; }
      printf("\n");
    }

    printf(" %02x", attrs[n]);
    text[ptr++] = attrs[n] >= 48 && attrs[n] < 120 ?  attrs[n] : '.';
  }

  text[ptr] = 0;
  printf("  %s\n\n", text);

  printf("   Version: %c\n", attrs[0]);
  printf("      Size: %d\n", attrs[1] | (attrs[2] << 8) | (attrs[3] << 16) | (attrs[4] << 24));
  printf("VendorName: %s\n", attrs+5);
  printf("\n");
}

uint64_t Elf::find_section_offset(
  uint32_t type,
  const char *section_name,
  uint64_t *len)
{
  if (len != nullptr) { *len = 0; }

  for (int count = 0; count < get_section_count(); count++)
  {
    set_file_ptr(get_section_offset() + (get_section_size() * count));

    Section section;
    read_section(section);

    if (section.sh_type == type)
    {
      const char *name = "";

      if (section.sh_name != 0)
      {
        name = (char *)buffer + get_string_table_offset() + section.sh_name;
      }

      if (section_name == NULL || strcmp(section_name, name) == 0)
      {
        if (len != nullptr) { *len = section.sh_size; }
        return section.sh_offset;
      }
    }
  }

  return 0;
}

uint64_t Elf::find_symbol_offset(const char *name)
{
  set_file_ptr(get_symbol_table_offset());
  uint64_t end = file_ptr + get_symbol_table_length();
  Symbol symbol;

  while (file_ptr < end)
  {
    read_symbol(symbol);
    char *symbol_name = (char *)buffer + str_sym_tbl_offset +  symbol.st_name;

    if (strcmp(symbol_name, name) == 0)
    {
      const int section_index = symbol.st_shndx;
      set_file_ptr(get_section_offset() + (get_section_size() * section_index));
      Section section;
      read_section(section);

      return section.sh_offset + (symbol.st_value - section.sh_addr);
    }
  }

  return 0;
}

uint64_t Elf::address_to_offset(uint64_t address)
{
  // Search through sections for an address and compute the offset into
  // the file.

  for (int count = 0; count < get_section_count(); count++)
  {
    set_file_ptr(get_section_offset() + (get_section_size() * count));

    Section section;
    read_section(section);

    const uint64_t start = section.sh_addr;
    const uint64_t end = section.sh_addr + section.sh_size;

    if (address >= start && address < end)
    {
      return section.sh_offset + (address - start);
    }
  }

  return 0;
}

int Elf::get_program_header(
  Program &program,
  uint64_t &offset,
  uint64_t address)
{
  for (uint32_t count = 0; count < header.e_phnum; count++)
  {
    set_file_ptr(header.e_phoff + (header.e_phentsize * count));
    offset = file_ptr;
    read_program(program);

    const uint64_t low = program.p_vaddr;
    const uint64_t high = program.p_vaddr + program.p_memsz;

    if (address >= low && address < high) { return count; }
  }

  return -1;
}

uint16_t Elf::read_int16(uint64_t offset)
{
  if (is_little_endian)
  {
    return GET_LITTLE_ENDIAN16(buffer, offset);
  }
    else
  {
    return GET_BIG_ENDIAN16(buffer, offset);
  }
}

uint32_t Elf::read_int32(uint64_t offset)
{
  if (is_little_endian)
  {
    return GET_LITTLE_ENDIAN32(buffer, offset);
  }
    else
  {
    return GET_BIG_ENDIAN32(buffer, offset);
  }
}

uint64_t Elf::read_int64(uint64_t offset)
{
  if (is_little_endian)
  {
    return GET_LITTLE_ENDIAN64(buffer, offset);
  }
    else
  {
    return GET_BIG_ENDIAN64(buffer, offset);
  }
}

int Elf::set_writable()
{
  if (mprotect(buffer, buffer_len, PROT_READ | PROT_WRITE) == -1)
  {
    return -1;
  }

  return 0;
}

void Elf::set_readonly()
{
  mprotect(buffer, buffer_len, PROT_READ);
}

Elf *Elf::create_instance(int ei_class, int e_machine)
{
  if (ei_class == 1)
  {
    switch (e_machine)
    {
      case EM_X86_32: return new ElfX86_32();
      default:        return new Elf32();
    }
  }
    else
  {
    switch (e_machine)
    {
      case EM_X86_64: return new ElfX86_64();
      default:        return new Elf32();
    }
  }
}

