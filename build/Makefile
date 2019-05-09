VPATH=../src:../tests

DEBUG=-DDEBUG -g
CFLAGS=-Wall -O3 $(DEBUG)
LDFLAGS=
CC=gcc
#CC=i686-w64-mingw32-gcc

OBJECTS= \
  file_io.o \
  magic_elf_lib.o \
  modify.o \
  print.o

default: $(OBJECTS)
	$(CC) -o ../magic_elf ../src/magic_elf.c $(OBJECTS) \
	   $(CFLAGS) $(LDFLAGS)

lib: $(OBJECTS)
	$(CC) -o libmagicl_elf.so magic_elf_lib.o magic_elf_io.o -shared -fPIC $(CFLAGS)


%.o: %.c %.h
	$(CC) -c $< -o $*.o $(CFLAGS)

