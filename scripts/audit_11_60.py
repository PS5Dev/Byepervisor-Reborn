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

assert len(ap_bin) <= 0x800, f"AP payload too large for hardened staging: 0x{len(ap_bin):x}"
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

main_source = Path("main.c").read_text()
hook_source = Path("issue9_diag.c").read_text()
header_source = Path("include/issue9_diag.h").read_text()

assert "issue9_production_arm(cave" in main_source
assert "issue9_production_cleanup(cave)" in main_source
assert "#define CAVE_STASH_OFF            ISSUE9_PROD_STASH_OFF" in main_source

required_hook = (
    "16 isolated IST6 paths verified",
    "gate last, then bounded TF arm",
    "build_passthrough_stack",
    "KERNEL_GADGET_MOV_RAX_RDI",
    "KERNEL_GADGET_SET_DR7",
    "Stage the AP payload only after the gate is stock and DR7 is clear.",
    "PROD_BREAK_SRC_OFF + PROD_BREAK_COPY_SIZE <= ISSUE9_SAVE_OFF",
    "restore_ists(tss_base, saved_ist)",
)
for marker in required_hook:
    assert marker in hook_source, f"missing hardened hook invariant: {marker}"

restore_pos = hook_source.index(
    "dr0_chain_store(handler, &off, 0x400, db_gate, saved_gate_lo)",
    hook_source.index("static int build_production_handler"),
)
clear_pos = hook_source.index(
    "kgadget(KERNEL_GADGET_SET_DR7)", restore_pos
)
stage_pos = hook_source.index(
    "Stage the AP payload only after the gate is stock and DR7 is clear.",
    clear_pos,
)
assert restore_pos < clear_pos < stage_pos
assert "#define ISSUE9_PROD_STASH_OFF 0x3400ULL" in header_source

print(
    f"11.60 hardened audit passed: AP size=0x{len(ap_bin):x}, embedded once, "
    "forbidden-opcode scan clean, guarded writes=1+1, per-core hook invariants present"
)
