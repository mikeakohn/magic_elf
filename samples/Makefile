INCLUDE= \
  -I/usr/lib/jvm/java-8-openjdk-amd64/include \
  -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux

default:
	$(CC) -o test.so test.c -shared -fPIC $(CFLAGS)
	$(CC) -o test32.so test.c -shared -fPIC -m32 $(CFLAGS)

test:
	$(CC) -o test_lib test_lib.c \
	  ../build/magic_elf_io.o \
	  ../build/magic_elf_lib.o \
	  ../build/magic_elf_print.o \
	  $(CFLAGS) $(LDFLAGS)

java:
	$(CC) -o libcrash.so crash.c \
	  $(INCLUDE) \
	  -Wall -shared -fPIC -g
	javac Crash.java
	javac Test.java

clean:
	@rm -f test_lib *.so *.class core hs_err_pid*.log
	@echo "Clean!"

