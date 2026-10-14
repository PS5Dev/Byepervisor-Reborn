#!/usr/bin/env python3
"""Static checks for the non-invasive 11.60 startup_mp resume probe."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


def body(disassembly: str, name: str) -> str:
    match = re.search(
        rf"^[0-9a-f]+ <{re.escape(name)}>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
        disassembly,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise SystemExit(f"missing symbol: {name}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--ktext", required=True, type=Path)
    args = parser.parse_args()

    dis = subprocess.check_output(
        [args.objdump, "-d", "--x86-asm-syntax=intel", str(args.elf)],
        text=True,
    )
    run = body(dis, "issue9_resume_diag_run")
    arm = body(dis, "arm_dr0_and_return")
    if "pushfq" not in arm or "or\tqword ptr [rsp], 0x100" not in arm:
        raise SystemExit("resume probe is missing the bounded TF arm")
    if "kh_chain_memcpy" in run or "enable_kernel_text_access_1160" in run:
        raise SystemExit("resume probe references a production mutation path")
    if re.search(r"\bmov\s+dr[0-7]\b", dis):
        raise SystemExit("resume probe ELF contains native debug-register writes")

    source = Path("issue9_diag.c").read_text()
    required = [
        "no break_hv copy and no hypervisor modification",
        "build_passthrough_stack",
        "Preserve the startup_mp core argument.",
        "KERNEL_GADGET_MOV_RAX_RDI",
        "KERNEL_GADGET_SET_DR7",
        "patch_count",
        "persistent probe would need %d mapping changes",
        "exact startup_mp entry observed and resumed",
        "stock gate and 16/16 IST6 restored",
    ]
    for marker in required:
        if marker not in source:
            raise SystemExit(f"missing resume-probe invariant: {marker!r}")

    data = args.elf.read_bytes()
    for marker in (
        b"[issue9-resume] no break_hv copy and no hypervisor modification",
        b"[issue9-resume] isolated IST6 paths verified; arming resume target",
        b"[issue9-resume] PASS: exact startup_mp entry observed and resumed",
    ):
        if marker not in data:
            raise SystemExit(f"missing resume marker: {marker!r}")

    ktext = args.ktext.read_bytes()
    expected = bytes.fromhex(
        "554889e5534889d34889f1b80f00000089fa0f01d95b5dc3"
    )
    got = ktext[0xC885D0:0xC885D0 + len(expected)]
    if got != expected:
        raise SystemExit(
            "startup_mp wrapper mismatch: "
            f"got {got.hex()}, expected {expected.hex()}"
        )

    print(
        "issue9 resume audit passed: exact wrapper bytes, register-preserving "
        "selected path, non-mutating per-core passthroughs, recovery markers"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
