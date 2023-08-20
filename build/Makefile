VPATH=../src:../tests

DEBUG=-DDEBUG -g
CFLAGS=-Wall -O3 $(DEBUG)
LDFLAGS=
CC=gcc
CXX=g++
#CC=i686-w64-mingw32-gcc
#CXX=i686-w64-mingw32-g++

OBJECTS= \
  Display.o \
  Elf.o \
  Elf32.o \
  Elf64.o \
  ElfX86_32.o \
  ElfX86_64.o \
  Header.o \
  Java.o \
  Modify.o \
  Program.o \
  Section.o \
  Symbol.o

IGNORE= \
  magic_elf_lib.o \
  modify.o \
  print_core.o \
  print_elf_header.o \
  print_program_headers.o \
  print_section_headers.o

default: $(OBJECTS)
	$(CXX) -o ../magic_elf ../src/magic_elf.cpp $(OBJECTS) \
	   $(CFLAGS) $(LDFLAGS)

lib: $(OBJECTS)
	$(CXX) -o libmagic_elf.so magic_elf_lib.o magic_elf_io.o -shared -fPIC $(CFLAGS)

%.o: %.cpp %.h
	$(CXX) -c $< -o $*.o $(CFLAGS)

