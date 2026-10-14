#!/bin/sh
set -e
cd "$(dirname "$0")"

CC=${CC:-gcc}
OUT=${OUT:-break_hv_1001}
CFLAGS="-O2 -ffreestanding -nostdlib -fno-pic -fno-plt \
  -fno-stack-protector -fno-stack-clash-protection \
  -fomit-frame-pointer -fno-asynchronous-unwind-tables \
  -fcf-protection=none -fno-jump-tables -mgeneral-regs-only \
  -mno-red-zone -Wall -Wextra -Werror -DFW_1001_PRODUCTION_STRIKE"

$CC $CFLAGS -c break_hv.c -o "$OUT.o"
$CC -c entry.S -o "$OUT-entry.o"
ld -nostdlib -no-pie -T link.ld "$OUT-entry.o" "$OUT.o" -o "$OUT.elf"
objcopy -O binary "$OUT.elf" "$OUT.bin"
xxd -i -n "$OUT" "$OUT.bin" > "$OUT.h"
