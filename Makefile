
DEBUG=-DDEBUG -g
CFLAGS=-Wall -O3 $(DEBUG)
LDFLAGS=
CC=gcc
#CC=i686-w64-mingw32-gcc
OBJECTS=magic_elf_io.o magic_elf_lib.o magic_elf_print.o

default: $(OBJECTS)
	$(CC) -o magic_elf magic_elf.c $(OBJECTS) \
	   $(CFLAGS) $(LDFLAGS)

lib: $(OBJECTS)
	$(CC) -o libmagicl_elf.so magic_elf_lib.o magic_elf_io.o -shared -fPIC $(CFLAGS)

test_so:
	$(CC) -o test.so test.c -shared -fPIC $(CFLAGS)
	$(CC) -o test32.so test.c -shared -fPIC -m32 $(CFLAGS)

test:
	$(CC) -o test_lib test_lib.c magic_elf_io.o magic_elf_lib.o \
	   magic_elf_print.o \
	   $(CFLAGS) $(LDFLAGS)

%.o: %.c %.h
	$(CC) -c $< -o $*.o $(CFLAGS)


clean:
	@rm -f *.o *.so magic_elf test_lib
	@echo "Clean!"


