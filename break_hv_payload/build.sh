#!/bin/sh
set -e
cd "$(dirname "$0")"

# These are host-side x86-64 tools.  Keep them separate from the PS5 SDK's
# target CC/LD/OBJCOPY variables inherited through the outer Makefile.
CC=${HV_CC:-gcc}
LD=${HV_LD:-ld}
OBJCOPY=${HV_OBJCOPY:-objcopy}
CFLAGS="-O2 -ffreestanding -nostdlib -fno-pic -fno-plt \
  -fno-stack-protector -fno-stack-clash-protection \
  -fomit-frame-pointer -fno-asynchronous-unwind-tables \
  -fcf-protection=none -fno-jump-tables -mgeneral-regs-only \
  -mno-red-zone -Wall -Wextra"

$CC $CFLAGS -c break_hv.c -o break_hv.o
$CC -c entry.S -o entry.o

"$LD" -nostdlib -no-pie -T link.ld entry.o break_hv.o -o break_hv.elf

"$OBJCOPY" -O binary break_hv.elf break_hv.bin
xxd -i -n break_hv break_hv.bin > break_hv.h
