#!/usr/bin/env python3
"""Static safety checks for the bounded issue #9 diagnostic ELF."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


def symbol_body(disassembly: str, name: str) -> str:
    match = re.search(
        rf"^[0-9a-f]+ <{re.escape(name)}>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
        disassembly,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise SystemExit(f"missing symbol in disassembly: {name}")
    return match.group(1)


def require_order(body: str, needles: list[str], label: str) -> None:
    position = -1
    for needle in needles:
        found = body.find(needle, position + 1)
        if found < 0:
            raise SystemExit(f"{label}: missing ordered instruction {needle!r}")
        position = found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--objdump", default="llvm-objdump")
    args = parser.parse_args()

    raw = subprocess.check_output(
        [args.objdump, "-d", "--x86-asm-syntax=intel", str(args.elf)],
        text=True,
    )
    publish = symbol_body(raw, "publish_and_single_step")

    require_order(
        publish,
        ["call", "pushfq", "or\tqword ptr [rsp], 0x100", "popfq", "nop"],
        "publish path",
    )
    tail = publish[publish.find("pushfq") : publish.find("nop") + len("nop")]
    if "call" in tail:
        raise SystemExit("publish path: call found between pushfq and the stepped nop")

    source = Path("issue9_diag.c").read_text()
    required_source = [
        "KERNEL_GADGET_PIVOT_ADD_RSP28_RET",
        "This must remain the first ROP operation after the entry pivot.",
        "chain_store(segment, &off, db_gate, saved_gate_lo)",
        "KERNEL_GADGET_ST_RCX_RAX",
        "KERNEL_GADGET_POP_RSP",
        "NX retained",
        "_Static_assert((ISSUE9_TOP_OFF & 0xf) == 0",
        "ISSUE9_FRAME_OFF + 0x28 == ISSUE9_TOP_OFF",
    ]
    for marker in required_source:
        if marker not in source:
            raise SystemExit(f"missing ROP diagnostic invariant: {marker!r}")
    if "issue9_stub_start" in raw or "stub_va" in source:
        raise SystemExit("diagnostic must not execute native code from the NX cave")

    data = args.elf.read_bytes()
    required = [
        b"[issue9] no DR0, no resume hook, no hypervisor payload",
        b"[issue9] 16 isolated IST6 ROP stacks verified",
        b"[issue9] teardown verified: stock gate and all 16 IST6 restored",
        b"[issue9] PASS: bounded TF path completed cleanly",
    ]
    for marker in required:
        if marker not in data:
            raise SystemExit(f"missing diagnostic marker: {marker!r}")

    print("issue9 audit passed: NX-cave ROP path, gate-first restore, immediate TF, teardown markers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
