magic_elf
=========

magic_elf can do the following:

* Dump contents of ELF files, including core files.

* Allows for modifying function calls so they return specific
  values instead of running the original code.

* Modify saved registers in core files including the stack pointer
  and instruction register. This can be useful for debugging core
  files in gdb where the upper frames of the stack can't resolve
  properly to loaded (or non-existent) shared libraries.

* Extract Java .class files from core dumps generated from JNI crashes.

For info on this program:

https://www.mikekohn.net/file_formats/magic_elf.php

