Compiler := gcc
Cflg := \
-std=c11 \
-ffreestanding \
-fno-stack-protector \
-fno-stack-check \
-fno-lto \
-fno-pie \
-fno-builtin \
-fno-omit-frame-pointer \
-mno-red-zone \
-mno-mmx \
-mno-sse \
-mno-sse2 \
-mno-sse3 \
-mno-ssse3 \
-mno-sse4.1 \
-mno-sse4.2 \
-mno-sse4 \
-mno-avx \
-mno-avx2 \
-mno-80387 \
-m64 \
-march=x86-64 \
-mcmodel=kernel \
-Wall \
-Wextra \
-Werror \
-Wno-unused-parameter \
-Wno-unused-variable \
-O2 \
-g \
-I../../KModLibs/Includes

FinalTemp := ../.Build
LocalTemp := .Build

ModuleName := 3Tty.ko

Cs := $(wildcard *.c)
Os := $(patsubst %.c,$(LocalTemp)/%.o,$(Cs))

.PHONY: all clean

all: $(FinalTemp)/$(ModuleName)

$(LocalTemp)/%.o: %.c
	@mkdir -p $(dir $@)
	$(Compiler) $(Cflg) -c $< -o $@
$(FinalTemp)/$(ModuleName): $(Os)
	$(Compiler) -nostdlib -r -o $@ $(Os)

clean:
	@rm -rf $(LocalTemp)