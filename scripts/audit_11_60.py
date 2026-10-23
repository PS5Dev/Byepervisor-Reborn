#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


def disassemble(tool: str, path: str) -> list[str]:
    commands = (
        [tool, "-d", "--x86-asm-syntax=intel", path],
        [tool, "-d", "-Mintel", path],
    )
    last_error = None
    for command in commands:
        try:
            return subprocess.check_output(
                command, text=True, stderr=subprocess.STDOUT
            ).splitlines()
        except subprocess.CalledProcessError as error:
            last_error = error
    raise last_error


ap = argparse.ArgumentParser()
ap.add_argument("--ap-bin", default="break_hv_payload/break_hv.bin")
ap.add_argument("--ap-elf", default="break_hv_payload/break_hv.elf")
ap.add_argument("--outer-elf", default="byepervisor_reborn.elf")
ap.add_argument("--objdump", default="llvm-objdump")
args = ap.parse_args()

ap_bin = Path(args.ap_bin).read_bytes()
outer = Path(args.outer_elf).read_bytes()

assert len(ap_bin) <= 0xD00, (
    f"AP payload too large for 11.60 staging: 0x{len(ap_bin):x}"
)
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

disassembly = disassemble(args.objdump, args.ap_elf)
write64_calls = sum(
    "call" in line and "<vmcb_write64" in line for line in disassembly
)
write32_calls = sum(
    "call" in line and "<vmcb_write32" in line for line in disassembly
)
assert write64_calls == 1, (
    f"expected one guarded write64 call site, got {write64_calls}"
)
assert write32_calls == 1, (
    f"expected one guarded write32 call site, got {write32_calls}"
)

main_source = Path("main.c").read_text()
hook_source = Path("resume_hook_1160.c").read_text()
header_source = Path("include/resume_hook_1160.h").read_text()
ap_source = Path("break_hv_payload/break_hv.c").read_text()
make_source = Path("Makefile").read_text()

required_main = (
    "fw == RESUME_1160_FW_RAW",
    "HV_SCAN_LO_REGULAR",
    "HV_SCAN_HI_REGULAR",
    "HV_SCAN_LO_PRO",
    "HV_SCAN_HI_PRO",
    "preflight_scan_range(kernel_pmap, scan_lo, scan_hi)",
    "resume_hook_1160_arm(cave, kernel_pm_cr3, scan_lo, scan_hi",
    "resume_hook_1160_cleanup(cave)",
    "g_hv_base_pa + rawoff(HV_SYM_HEAP_BASE)",
    "g_hv_base_pa + rawoff(HV_SYM_PCPUS)",
)
for marker in required_main:
    assert marker in main_source, f"missing 11.60 integration invariant: {marker}"

required_hook = (
    "resume_hook_1160_arm",
    "resume_hook_1160_cleanup",
    "16 isolated IST6 paths verified",
    "KERNEL_GADGET_MOV_RAX_RDI",
    "KERNEL_GADGET_SET_DR7",
    "The AP image is copied only after the stock gate and DR7 are restored.",
    "AP_SOURCE_OFF + AP_COPY_SIZE <= SAVE_OFF",
    "restore_ists(tss_base, saved_ist)",
    "STORE_PARAM(0xf18, scan_lo)",
    "STORE_PARAM(0xf40, scan_hi)",
    "kread64(save + SAVE_GATE_LO) != saved_gate_lo",
    "kread64(save + SAVE_ISTS + (uint64_t)cpu * 8) != saved_ist[cpu]",
    "if (restore_ists(tss_base, saved_ist))",
    "Forward an unexpected foreign-core #DB to the stock handler",
    "build_passthrough(fallback, va, stock_db_handler)",
)
for marker in required_hook:
    assert marker in hook_source, f"missing resume-hook invariant: {marker}"

restore_pos = hook_source.index(
    "chain_store(handler, &off, 0x400, db_gate, saved_gate_lo)"
)
clear_pos = hook_source.index("KERNEL_GADGET_SET_DR7", restore_pos)
stage_pos = hook_source.index(
    "The AP image is copied only after the stock gate and DR7 are restored.",
    clear_pos,
)
assert restore_pos < clear_pos < stage_pos

required_ap = (
    "const uint64_t scan_lo = param[3]",
    "const uint64_t scan_hi = param[8]",
    "pointer_bounds(scan_lo, scan_hi, &region_lo, &region_hi)",
    "scan_lo == PRO_SCAN_LO &&",
    "!valid_scan_page(self_msrpm, region_lo, region_hi)",
    "ext[EXT_CANDIDATES + recorded++] = pa",
    "targets != TARGET_COUNT",
    "before != revalidated",
    "rollback_candidates",
    "written != TARGET_COUNT || verified != TARGET_COUNT",
)
for marker in required_ap:
    assert marker in ap_source, f"missing dynamic VMCB invariant: {marker}"

for forbidden in (
    "PRO_FIRST_VMCB",
    "EXPECTED_FIELD_HASH",
    "FIXED_VMCB_BANK",
    "VMCB_BANK_STRIDE",
):
    assert forbidden not in ap_source, (
        f"fixed VMCB-bank evidence leaked into production AP: {forbidden}"
    )

assert "#define RESUME_1160_FW_RAW     0x11600005U" in header_source
assert "#define RESUME_1160_RESULT_OFF 0x3600ULL" in header_source
legacy_name = "issue" + "9"
assert legacy_name not in main_source.lower()
assert legacy_name not in make_source.lower()
for obsolete in (
    f"{legacy_name}_diag.c",
    f"include/{legacy_name}_diag.h",
    f"scripts/audit_{legacy_name}_diag.py",
    f"scripts/audit_{legacy_name}_dr0.py",
    f"scripts/audit_{legacy_name}_resume.py",
):
    assert not Path(obsolete).exists(), f"obsolete diagnostic file remains: {obsolete}"

print(
    f"11.60 production audit passed: AP size=0x{len(ap_bin):x}, embedded once, "
    "forbidden-opcode scan clean, guarded writes=1+1, regular+Pro dynamic "
    "VMCB and per-core resume-hook invariants present"
)
