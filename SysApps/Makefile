Compiler := x86_64-elf-gcc
Cflg := \
-Wall \
-Wextra \
-O2 \
-ffreestanding \
-fno-stack-protector \
-mno-red-zone \
-I../CLibrary/install/x86_64-elf/include

Lflg := \
-nostdlib \
-static \
-L../CLibrary/install/x86_64-elf/lib \
-lc \
-lgcc \
-T ../CLibrary/userland/link.ld


Finale := ../BootImg/.Build

Src := $(shell find . -type f -name '*.c')
Objs := $(patsubst ./%.c,$(Finale)/%.o,$(Src))
Elfs := $(patsubst ./%.c,$(Finale)/%.elf,$(Src))

all: $(Elfs)

$(Finale)/%.o: ./%.c
	@mkdir -p $(dir $@)
	$(Compiler) $(Cflg) -c $< -o $@

../CLibrary/userland/crt0.o: ../CLibrary/userland/crt0.c
	$(Compiler) $(Cflg) -c $< -o $@

../CLibrary/userland/syscalls.o: ../CLibrary/userland/syscalls.c
	$(Compiler) $(Cflg) -c $< -o $@

$(Finale)/%.elf: $(Finale)/%.o ../CLibrary/userland/crt0.o ../CLibrary/userland/syscalls.o
	@mkdir -p $(dir $@)
	$(Compiler) $(Cflg) $^ -o $@ $(Lflg)

clean:
	rm -rf $(Finale) ../CLibrary/userland/crt0.o ../CLibrary/userland/syscalls.o

.PHONY: all clean