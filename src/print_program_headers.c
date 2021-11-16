/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2021 - Michael Kohn (mike@mikekohn.net)
  http://www.mikekohn.net/

  This program falls under the BSD license.

*/

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "file_io.h"
#include "magic_elf.h"
#include "print_core.h"
#include "print_program_headers.h"

const char *get_program_header_type(int type)
{
  const char *types[] =
  {
    "NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS", "NUM"
  };

  if (type <= 8)
  {
    return types[type];
  }

  if (type == 0x6474e550) { return "GNU_EH_FRAME"; }
  if (type == 0x6474e551) { return "GNU_STACK"; }
  if (type == 0x6474e552) { return "GNU_RELRO"; }

  return "UNKNOWN";
}

void print_elf_program_headers(elf_info_t *elf_info)
{
  int count;
  long marker;
  unsigned int p_type;
  int p_flags;
  int namesz,descsz,type;
  long p_offset,p_filesz;
  int n;
  const char *flags[] =
  {
    "---", "--X", "-W-", "-WX", "R--", "R-X", "RW-", "RWX"
  };

  elf_info->file_ptr = elf_info->e_phoff;

  printf("Elf Program Headers (count=%d)\n\n", elf_info->e_phnum);

  for (count = 0; count < elf_info->e_phnum; count++)
  {
    marker = elf_info->file_ptr + elf_info->e_phentsize;

    printf("Program Header %d (offset=0x%04" PRIx64 ")\n", count, elf_info->file_ptr);
    printf("---------------------------------------------\n");

    if (elf_info->bitwidth == 32)
    {
      p_type = elf_info->read_word(elf_info);
      printf("  p_type: %d (%s)\n", p_type, get_program_header_type(p_type));
      p_offset = elf_info->read_offset(elf_info);
      printf("p_offset: 0x%lx\n", p_offset);
      printf(" p_vaddr: 0x%lx\n", elf_info->read_addr(elf_info));
      printf(" p_paddr: 0x%lx\n", elf_info->read_addr(elf_info));
      p_filesz = elf_info->read_word(elf_info);
      printf("p_filesz: %ld\n", p_filesz);
      printf(" p_memsz: %d\n", elf_info->read_word(elf_info));
      p_flags = elf_info->read_word(elf_info);
      printf(" p_flags: %d %s%s%s\n", p_flags, flags[p_flags&7],
        (p_flags & 0xff0000) == 0xff0000 ? " MASKOS" : "",
        (p_flags & 0xff000000) == 0xff000000 ? " MASKPROC" : "");
      printf(" p_align: %d\n", elf_info->read_word(elf_info));
    }
    else
    {
      p_type = elf_info->read_word(elf_info);
      p_flags = elf_info->read_word(elf_info);
      p_offset = elf_info->read_offset(elf_info);
      printf("  p_type: %d (%s)\n", p_type, get_program_header_type(p_type));
      printf(" p_flags: %d %s%s%s\n", p_flags, flags[p_flags&7],
        (p_flags & 0xff0000) == 0xff0000 ? " MASKOS" : "",
        (p_flags & 0xff000000) == 0xff000000 ? " MASKPROC" : "");
      printf("p_offset: 0x%lx\n", p_offset);
      printf(" p_vaddr: 0x%lx\n", elf_info->read_addr(elf_info));
      printf(" p_paddr: 0x%lx\n", elf_info->read_addr(elf_info));
      p_filesz = elf_info->read_xword(elf_info);
      printf("p_filesz: 0x%lx\n", p_filesz);
      printf(" p_memsz: 0x%lx\n", elf_info->read_xword(elf_info));
      printf(" p_align: 0x%lx\n", elf_info->read_xword(elf_info));
    }

    // If this is a NOTE section
    if (p_type == 4)
    {
      uint32_t align_mask = elf_info->bitwidth == 32 ? 3 : 7;
      int namesz_align;
      int descsz_align;
      uint64_t bytes_used = 0;
      char name[1024];
      elf_info->file_ptr = p_offset;

      printf("\n");

      while (bytes_used < p_filesz)
      {
        //printf("bytes_used=%d / %ld\n", bytes_used, p_filesz);
        namesz = elf_info->read_word(elf_info);
        descsz = elf_info->read_word(elf_info);
        type = elf_info->read_word(elf_info);

        namesz_align = (namesz + align_mask) & ~align_mask;
        descsz_align = (descsz + align_mask) & ~align_mask;

        if (namesz < 1023)
        {
          for (n = 0; n < namesz; n++)
          {
            name[n] = elf_info->read_int8(elf_info);
          }
          name[n] = 0;

          elf_info->file_ptr += namesz_align - namesz;
        }
        else
        {
          elf_info->file_ptr += namesz_align;
          name[0] = 0;
        }

        // FIXME - There's a lot more things that can be put in here.
        // They will come back as unknown, but can be added as needed.
        printf("%8s 0x%04x  [0x%x ", name, descsz, type);

        // FIXME - Um. When there is a GNU section I'm 4 bytes off.  Why?
        if (strcmp(name, "GNU") == 0)
        {
          printf("]\n");
          //printf("%lx\n", elf_info->file_ptr);
          for (n = 0; n < descsz; n++)
          {
            uint8_t c = elf_info->read_int8(elf_info);

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

        int is_core = 0;
        if (strcmp(name, "CORE") == 0) { is_core = 1; }

        switch(type)
        {
          case 1:
            printf("NT_PRSTATUS]\n");
            if (is_core) { print_core_prstatus(elf_info); }
            break;
          case 2:
            printf("NT_PRFPREG]\n");
            //print_core_regs(elf_info);
            break;
          case 3:
            printf("NT_PRPSINFO]\n");
            if (is_core) { print_core_prpsinfo(elf_info); }
            break;
          case 4: printf("NT_TASKSTRUCT]\n"); break;
          case 6: printf("NT_AUXV]\n"); break;
          case 0x200: printf("NT_386_TLS]\n"); break;
          case 0x53494749:
            printf("NT_SIGINFO]\n");
            if (is_core) { print_core_siginfo(elf_info); }
            break;
          case 0x46494c45:
            printf("NT_FILE]\n");
            print_core_mapped_files(elf_info, descsz);
            break;
          case 0x46e62b7f: printf("NT_PRXFPREG]\n"); break;
          default:
            printf("unknown]\n");
            break;
        }

        elf_info->file_ptr += descsz_align;

        bytes_used += (4 * 3) + namesz_align + descsz_align;
      }
    }

    printf("\n");

    elf_info->file_ptr = marker;
  }
}

