NASM      ?= nasm
CC        ?= gcc
NASMFLAGS ?= -f elf64 -g -F dwarf
LDFLAGS   ?= -pie -Wl,-z,relro,-z,now,-z,noexecstack

# Prefer the portable development link when pkg-config metadata is installed.
# Fedora's runtime-only package is also sufficient on this x86-64 machine;
# discover its current versioned shared object rather than baking in a SONAME.
SODIUM_LIB := $(shell pkg-config --libs libsodium 2>/dev/null || ldconfig -p | awk '/libsodium\.so\./ && /x86-64/ { print $$NF; exit }')
LDLIBS    ?= $(SODIUM_LIB)

.PHONY: all clean

all: asmcrypt

asmcrypt: asmcrypt.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

asmcrypt.o: asmcrypt.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	$(RM) asmcrypt asmcrypt.o
