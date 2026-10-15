#!/bin/sh
set -eu
cd "$(dirname "$0")"

cc="${HV_CC:-clang}"
"$cc" -Os -ffreestanding -nostdlib -fno-pic -fno-plt \
  -fno-stack-protector -fno-stack-clash-protection \
  -fomit-frame-pointer -fno-asynchronous-unwind-tables -falign-functions=1 \
  -fcf-protection=none -fno-jump-tables -mgeneral-regs-only \
  -mno-red-zone -Wall -Wextra -c vmcb_strike_1270.c -o vmcb_strike_1270.o
"$cc" -DSTRIKE_COMPACT_ENTRY -c entry_1270.S -o entry_1270.o
"${HV_LD:-ld}" -nostdlib -no-pie -T link_strike_1270.ld \
  entry_1270.o vmcb_strike_1270.o -o vmcb_strike_1270.elf
"${HV_OBJCOPY:-objcopy}" -O binary vmcb_strike_1270.elf \
  vmcb_strike_1270.bin
xxd -i -n vmcb_strike_1270 vmcb_strike_1270.bin > vmcb_strike_1270.h
