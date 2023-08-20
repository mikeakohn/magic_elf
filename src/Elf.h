/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_ELF_INFO_H
#define MAGIC_ELF_ELF_INFO_H

#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <vector>

#include "Header.h"
#include "Program.h"
#include "PRStatus.h"
#include "Section.h"
#include "Symbol.h"

class Elf
{
public:
  Elf();
  virtual ~Elf();

  static Elf *open_elf(const char *filename, bool writable = false);
  static Elf *open_elf_from_mem(void *mem_ptr);

  int read_file(const char *filename, bool writable = false);

  int read_header();
  virtual void compute_string_table_offset() = 0;

  virtual int read_program(Program &program) = 0;
  virtual int read_section(Section &section) = 0;
  virtual int read_symbol(Symbol &symbol) = 0;

  virtual void print_program(Program &program) = 0;
  virtual void print_section(Section &section);
  virtual void print_symbol(Symbol &symbol, uint64_t string_table_offset);

  void print_program_note(Program &program);
  void read_note_name(char *name, int length, int namesz, int namesz_align);
  uint64_t get_core_registers_from_note(Program &program, uint32_t pid);

  void read_core_prstatus(PRStatus &prstatus);

  void print_core_prstatus();
  void print_core_prpsinfo();
  void print_core_siginfo();
  virtual void print_core_mapped_files(int descsz) { }
  virtual void print_registers() { }

  void print_section_data(Section &section, std::string &name);
  void print_section_comment(const char *comment, int size);
  void print_section_string_table(uint8_t *table, int size);

  virtual void print_section_relocation(
    int sh_offset,
    int sh_size,
    int symtab_offset,
    int strtab_offset) = 0;

  virtual void print_section_symbol_table(
    int offset,
    int sh_size,
    int sh_entsize,
    int string_table_offset);

  void print_section_arm_attrs(uint8_t *attrs, int sh_size);

  void print_header();
  void print_program_headers();
  void print_section_headers();

  uint64_t find_section_offset(
    uint32_t type,
    const char *section_name,
    uint64_t *len = nullptr);

  uint64_t find_symbol_offset(const char *name);
  uint64_t address_to_offset(uint64_t address);

  int get_program_header(Program &program, uint64_t &offset, uint64_t address);

  int get_program_count()       const { return header.e_phnum; }
  int get_program_offset()      const { return header.e_phoff; }
  int get_program_size()        const { return header.e_phentsize; }
  int get_section_count()       const { return header.e_shnum; }
  int get_section_offset()      const { return header.e_shoff; }
  int get_section_size()        const { return header.e_shentsize; }
  int get_string_table_index()  const { return header.e_shstrndx; }
  int get_string_table_offset() const { return string_table_offset; }
  int get_symbol_table_offset() const { return symbol_table_offset; }
  int get_symbol_table_length() const { return symbol_table_length; }

  virtual uint64_t get_addr(long offset) = 0;
  virtual uint64_t get_offset(long offset) = 0;

  virtual int get_register_index(const char *name, uint64_t &offset)
  {
    return -1;
  }

  int set_writable();
  void set_readonly();

#ifdef _WIN32
  HANDLE fd;
  HANDLE mem;
  HANDLE mem_handle;
#else
  int fd;
#endif
  uint8_t *buffer;
  int bitwidth;
  long buffer_len;
  uint64_t file_ptr;
  bool is_little_endian;

  Header header;

  uint64_t string_table_offset;
  uint64_t symbol_table_offset;
  uint64_t symbol_table_length;
  uint64_t str_sym_tbl_offset;

  virtual uint64_t read_reg(uint64_t offset) = 0;
  virtual void write_reg(uint64_t offset, uint64_t value) = 0;

protected:
  void set_file_ptr(uint64_t offset) { file_ptr = offset; }
  uint64_t get_file_ptr() { return file_ptr; }

  uint8_t read_int8(uint64_t offset) { return buffer[offset]; }
  uint16_t read_int16(uint64_t offset);
  uint32_t read_int32(uint64_t offset);
  uint64_t read_int64(uint64_t offset);

  uint8_t read_int8() { return read_int8(file_ptr++); }

  uint16_t read_int16()
  {
    uint16_t value = read_int16(file_ptr);
    file_ptr += 2;
    return value;
  }

  uint32_t read_int32()
  {
    uint32_t value = read_int32(file_ptr);
    file_ptr += 4;
    return value;
  }

  uint64_t read_int64()
  {
    uint64_t value = read_int64(file_ptr);
    file_ptr += 8;
    return value;
  }

  uint16_t read_half() { return read_int16(); }
  uint32_t read_word() { return read_int32(); }
  uint16_t get_half(long offset) { return read_int16(offset); }
  uint32_t get_word(long offset) { return read_int32(offset); }

  const char *get_string(int offset)
  {
    if (offset == 0) { return ""; }
    return (char *)(buffer + get_string_table_offset() + offset);
  }

  // These shouldn't be used for ELF32.
  //uint32_t read_xword()            { return read_int64(); }
  //uint32_t get_xword(long offset)  { return read_int64(offset); }

  virtual uint64_t read_addr() = 0;
  virtual uint64_t read_offset() = 0;

  void push_ptr() { file_ptr_stack.push_back(file_ptr); }
  void pop_ptr()
  {
    file_ptr = file_ptr_stack.back();
    file_ptr_stack.pop_back();
  }

private:
  static Elf *create_instance(int ei_class, int e_machine);
  std::vector<uint64_t> file_ptr_stack;
};

#endif

