#!/bin/bash

#./run.sh img > run with .img
#./run.sh iso > run with .iso

DISK_IMG="./.Build/axeialos.img"
ISO_IMG="./.Build/axeialos.iso"

# SOME SETTINGS
SMP=$2
MEM=$3

if [ "$1" = "img" ]; then
    echo "running with disk image..."
    qemu-system-x86_64 \
      -bios /usr/share/ovmf/OVMF.fd \
      -machine q35 \
      -m $MEM \
      -smp $SMP \
	  -gdb tcp::1234 \
      -serial file:debug.log \
      -d guest_errors,cpu_reset,int,pcall \
      -D qemu.log \
      -no-reboot \
      -no-shutdown \
      -device ahci,id=ahci0 \
      -drive id=hd0,file="$DISK_IMG",format=raw,if=none \
      -device ide-hd,drive=hd0,bus=ahci0.0

elif [ "$1" = "iso" ]; then
    echo "running with ISO image..."
    qemu-system-x86_64 \
      -bios /usr/share/ovmf/OVMF.fd \
      -machine q35 \
      -m $MEM \
      -smp $SMP \
	  -gdb tcp::1234 \
      -serial file:debug.log \
      -d guest_errors,cpu_reset,int,pcall \
      -D qemu.log \
      -no-reboot \
      -no-shutdown \
      -device ahci,id=ahci0 \
      -drive id=hd0,file="$ISO_IMG",format=raw,if=none \
      -device ide-hd,drive=hd0,bus=ahci0.0

else
    echo "usage option 2: ./Run.sh <img | iso> <number of CPU cores> <memory (M | G)>"
	echo "usage option 1: sh Run.sh <img | iso> <number of CPU cores> <memory (M | G)>"
	echo "example usage: sh Run.sh img 4 512M"
    exit 1
fi