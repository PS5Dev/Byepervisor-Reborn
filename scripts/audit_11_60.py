#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


ap = argparse.ArgumentParser()
ap.add_argument("--ap-bin", default="break_hv_payload/break_hv.bin")
ap.add_argument("--ap-elf", default="break_hv_payload/break_hv.elf")
ap.add_argument("--outer-elf", default="byepervisor_reborn.elf")
ap.add_argument("--objdump", default="llvm-objdump")
args = ap.parse_args()

ap_bin = Path(args.ap_bin).read_bytes()
outer = Path(args.outer_elf).read_bytes()

assert len(ap_bin) <= 0xF00, f"AP payload too large: 0x{len(ap_bin):x}"
assert outer.count(ap_bin) == 1, "outer ELF must contain exactly one AP image"

for opcode in (
    b"\x0f\x01\xd9",  # vmmcall
    b"\x0f\x01\xda",  # vmload
    b"\x0f\x01\xdb",  # vmsave
    b"\x0f\x01\xd8",  # vmrun
    b"\x0f\x22",      # mov to control register
    b"\x0f\x23",      # mov to debug register
    b"\x0f\x30",      # wrmsr
    b"\x0f\x32",      # rdmsr
):
    assert opcode not in ap_bin, f"forbidden AP opcode: {opcode.hex()}"

disassembly = subprocess.check_output(
    [args.objdump, "-d", "--x86-asm-syntax=intel", args.ap_elf], text=True
).splitlines()
write64_calls = sum("call" in line and "<vmcb_write64" in line
                    for line in disassembly)
write32_calls = sum("call" in line and "<vmcb_write32" in line
                    for line in disassembly)
assert write64_calls == 1, f"expected one guarded write64 call site, got {write64_calls}"
assert write32_calls == 1, f"expected one guarded write32 call site, got {write32_calls}"

print(
    f"11.60 AP audit passed: size=0x{len(ap_bin):x}, embedded once, "
    "forbidden-opcode scan clean, write call sites=1+1"
)
