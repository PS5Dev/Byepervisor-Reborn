#!/usr/bin/env python3
"""Static safety checks for the bounded 11.60 DR0 diagnostic."""

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


def tf_tail(body: str, label: str) -> None:
    push = body.find("pushfq")
    nop = body.find("nop", push)
    if push < 0 or nop < 0:
        raise SystemExit(f"{label}: missing TF sequence")
    tail = body[push:nop + 3]
    for marker in ("pushfq", "or\tqword ptr [rsp], 0x100", "popfq", "nop"):
        if marker not in tail:
            raise SystemExit(f"{label}: missing {marker!r}")
    if "call" in tail:
        raise SystemExit(f"{label}: call found inside TF sequence")


def at(blob: bytes, offset: int, expected: bytes, label: str) -> None:
    got = blob[offset:offset + len(expected)]
    if got != expected:
        raise SystemExit(
            f"11.60 ktext {label} mismatch at 0x{offset:x}: "
            f"got {got.hex()}, expected {expected.hex()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--ktext", required=True, type=Path)
    args = parser.parse_args()

    raw = subprocess.check_output(
        [args.objdump, "-d", "--x86-asm-syntax=intel", str(args.elf)],
        text=True,
    )
    arm = symbol_body(raw, "arm_dr0_and_return")
    cleanup = symbol_body(raw, "cleanup_single_step")
    tf_tail(arm, "arm path")
    tf_tail(cleanup, "cleanup path")
    if re.search(r"\bmov\s+dr[0-7]\b", raw):
        raise SystemExit("diagnostic ELF contains a native mov-to-debug-register instruction")

    source = Path("issue9_diag.c").read_text()
    required_source = [
        "no sleep, no resume strike, no hypervisor payload",
        "16 isolated paths published; arming DR0 briefly",
        "Gate restoration is the first mutation.",
        "DR0_HANDLER_OFF + 0x400 <= ISSUE9_SAVE_OFF",
        "arm block readback mismatch",
        "handler block readback mismatch",
        "fallback readback mismatch",
        "recovery state readback failed",
        "restore_ists(tss_base, saved_ist)",
        "KERNEL_GADGET_SET_DR7",
    ]
    for marker in required_source:
        if marker not in source:
            raise SystemExit(f"missing DR0 safety invariant: {marker!r}")

    data = args.elf.read_bytes()
    for marker in (
        b"[issue9-dr0] no sleep, no resume strike, no hypervisor payload",
        b"[issue9-dr0] PASS: intended DR0 hit, no foreign CPU entry",
        b"[issue9-dr0] teardown gate=stock IST6=%s page-table=%s",
    ):
        if marker not in data:
            raise SystemExit(f"missing diagnostic marker: {marker!r}")

    ktext = args.ktext.read_bytes()
    at(ktext, 0x2A5778, bytes.fromhex("0f23c0"), "DBREG_RESUME")
    at(ktext, 0xA7BD86, bytes.fromhex("0f23f84489c0c3"), "SET_DR7")
    at(ktext, 0x34F590 + 0x15, bytes.fromhex("31c05dc3"), "sys_getuid target")

    print(
        "issue9 DR0 audit passed: target/gadgets match dump, per-core readbacks, "
        "bounded TF cleanup, teardown markers"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
