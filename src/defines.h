/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_DEFINES_H
#define MAGIC_ELF_DEFINES_H

// Here's a crock of SHT.
#define SHT_NULL          0
#define SHT_PROGBITS      1
#define SHT_SYMTAB        2
#define SHT_STRTAB        3
#define SHT_RELA          4
#define SHT_HASH          5
#define SHT_DYNAMIC       6
#define SHT_NOTE          7
#define SHT_NOBITS        8
#define SHT_REL           9
#define SHT_SHLIB         10
#define SHT_DYNSYM        11
#define SHT_INIT_ARRAY    14
#define SHT_FINI_ARRAY    15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP         17
#define SHT_SYMTAB_SHNDX  18
#define SHT_LOOS          0x60000000
#define SHT_HIOS          0x6fffffff
#define SHT_LOPROC        0x70000000
#define SHT_HIPROC        0x7fffffff
#define SHT_LOUSER        0x80000000
#define SHT_HIUSER        0xffffffff

#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4

#define NT_PRSTATUS   1
#define NT_PRFPREG    2
#define NT_PRPSINFO   3
#define NT_TASKSTRUCT 4
#define NT_AUXV       6
#define NT_386_TLS    0x200
#define NT_SIGINFO    0x53494749
#define NT_FILE       0x46494c45
#define NT_PRXFPREG   0x46e62b7f

#define EM_X86_32  3
#define EM_X86_64  62 

#endif

