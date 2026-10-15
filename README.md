# Byepervisor Reborn
**Note: This repo should be considered a base exploit for work to be built on top of. It is not useful to regular users in its current release state, this is intended for developers.**

## Summary
PS5 hypervisor exploit for 6.xx - 13.60 firmware. Bug details can be found [here](https://github.com/soniciso1/ps5-hv-writeups/blob/main/s3-resume-startup_mp-ap-launch.md). This bug was initially found by [theflow0](https://x.com/theflow0) and subsequently more people recently w/ assistance of LLMs. The TLDR is that on S3 resume, the `startup_mp` hypercall is invoked on core 0 to initialize the other AP cores (1-15), and takes a reset vector (`rip`) as one of the arguments for where the core will execute from. During this time on cores 1-15, an insecure Nested Page Table (NPT) config is applied. We can abuse this to run some shellcode that has R/W into the hypervisor's address space including the VM Control Blocks (VMCBs).

Very similarly to (one version of) [byepervisor of old](https://github.com/PS5Dev/Byepervisor), this exploits the rest mode path too :)

The following firmware paths are available:

- 12.70 (tested on launch model only)
- 13.60
- 13.20
- 13.00 (untested)

However this bug should technically be exploitable as low as 6.xx. With modifications, it could work on 14.00 as well, but this is not provided here, especially since there is no public 14.00 kernel exploit anyways.

## Important Notes
- You may need to go to Settings -> System -> Power Saving -> Features Available in Rest Mode
  - Set Supply Power to USB Ports to "Always"
- This payload is designed to run through the [elfldr](https://github.com/ps5-payload-dev/elfldr)
  - This is somewhat important because the payload expects to continue running on resume from rest mode, and it relies on elfldr for this
- Post-resume, this payload should leave the system in a state where the kernel can be dumped and patched
  - XOM/xotext is disabled, write is enabled
  - Upon resume, it will print the first 8 bytes of the kernel .text in a notification to demonstrate XOM defeat
- This does not ship with any patches (HEN or otherwise)
  - Consider this a bring your own patches scenario, we didn't feel like doing this.
- This payload needs to be aware of whether or not the console is a pro or a non-pro unit
  - Sony decided to waste their added 2GB precious DDR5 that pro units have on the hypervisor, so it is mapped in a different physical address range
    - `0x062800000` PA for non-pro units
    - `0x8E0800000` PA for pro units
  - Open an issue if the payload mis-identifies what your system is, and note the hex value printed in brackets in the notification
- If the system shuts down when resuming from rest mode, it means the exploit failed
  - If it failed, likely there's something wrong with the payload and your situation is not supported, this exploit should be 99.9% stable

## Build notes
This exploit payload is built using the [PS5-Payload-Dev SDK](https://github.com/ps5-payload-dev/sdk). Note also that the build for `break_hv_payload/` is slightly special, as it gets compiled to a flat binary of minimal size. The entirety of code in `break_hv_payload/` runs in supervisor/kernel mode.

### Firmware 12.70 (launch model)

The default ELF selects the 12.70 path when it detects firmware 12.70:

```sh
make PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
```

The 12.70 path was exercised as a standalone ELF on one launch-model PS5 with firmware 12.70, Relapse, and elfldr. One complete rest/resume run returned to the home screen and displayed the first eight kernel text bytes (`e8 5b c5 58 00 00 00 00`). Its USB result recorded 16 AP VMCBs processed, all 342 planned text-map leaves verified, and a successful kernel text read. The number of leaves changes with KASLR; 853 was also observed on the same console in an earlier boot. The combined ELF builds successfully but still needs a console run.

The 12.70 hook now prepares isolated IST6 fallback paths for all 16 CPUs before publishing its shared debug gate. This hardening builds and passes host checks, but has not yet had a 12.70 console run. `make census_1270.elf` builds a read-only TSS, IDT, and cave preflight for that first validation.

Credit to [Gabe “gzimbric” Zimbric](https://github.com/gzimbric) for diagnosing the [global debug-gate/per-CPU IST race](https://github.com/PS5Dev/Byepervisor-Reborn/issues/9) and developing and validating the [hardened 11.60 hook](https://github.com/gzimbric/Byepervisor-Reborn/commit/340ed30a455e03e9bf29662f257136f9a45d702c). The 12.70 multicore changes here adapt his design.

A writable USB drive at `/mnt/usb0` is optional. When available, the 12.70 path saves a detailed resume log there. Without it, the payload continues and reports the result through its notification and kernel log.

This path rejects firmware or SoC mismatches, unexpected page-table layouts, and dirty data-cave state before arming the resume hook. It leaves kernel text readable and writable after resume. It has not been tested on Slim or Pro hardware, and does not boot Linux or include kernel patches. See [PORT_12_70.md](PORT_12_70.md) for the implementation and test boundary.

## Adding firmware support
To add support for a different firmware, the main thing that needs to be added is the header file in `include/offsets/`. This includes all the kernel offsets that are needed.

Once the offsets have been added, the following functions need to be modified to add cases to the switch statements:
- `kgadget()`
- `kdlsym()`
- `rawoff()`

Some firmwares might require more extensive modifications if gadgets don't exist for them. 6.xx for example likely will not have some gadgets that are used on 13.xx.

## How to use
1. Run kernel exploit chain and get to elfldr
2. Send `byepervisor.elf`
3. Follow the directions of the notifications
