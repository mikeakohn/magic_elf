
default:
	@+make -C build

lib: $(OBJECTS)
	$(CC) -o libmagicl_elf.so magic_elf_lib.o magic_elf_io.o -shared -fPIC $(CFLAGS)

test_so:
	$(CC) -o test.so test.c -shared -fPIC $(CFLAGS)
	$(CC) -o test32.so test.c -shared -fPIC -m32 $(CFLAGS)

test:
	$(CC) -o test_lib test_lib.c magic_elf_io.o magic_elf_lib.o \
	   magic_elf_print.o \
	   $(CFLAGS) $(LDFLAGS)

clean:
	@rm -f build/*.o *.so magic_elf test_lib
	@echo "Clean!"

