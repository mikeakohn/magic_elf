/*

  magic_elf - The ELF file format analyzer.

  Copyright 2009-2023 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the BSD license.

*/

#ifndef MAGIC_ELF_PRSTATUS_H
#define MAGIC_ELF_PRSTATUS_H

#include <stdint.h>

struct PRStatus
{
  PRStatus()
  {
  }

  ~PRStatus()
  {
  }

  uint32_t signal_number;
  uint32_t extra_code;
  uint32_t _errno;
  uint16_t cursig;
  uint16_t unknown_1;

  uint64_t sigpend;
  uint64_t sighold;

  uint32_t pid;
  uint32_t ppid;
  uint32_t pgrp;
  uint32_t psid;

  uint64_t user_time_sec;
  uint64_t user_time_usec;
  uint64_t system_time_sec;
  uint64_t system_time_usec;
  uint64_t cumulative_user_time_sec;
  uint64_t cumulative_user_time_usec;
  uint64_t cumulative_system_time_sec;
  uint64_t cumulative_system_time_usec;

};

#endif

