# Byepervisor Reborn
**Note: This repo should be considered a base exploit for work to be built on top of. It is not useful to regular users in its current release state, this is intended for developers.**

## Summary
PS5 hypervisor exploit for 6.xx - 13.60 firmware. Bug details can be found [here](https://github.com/soniciso1/ps5-hv-writeups/blob/main/s3-resume-startup_mp-ap-launch.md). This bug was initially found by [theflow0](https://x.com/theflow0) and subsequently more people recently w/ assistance of LLMs. The TLDR is that on S3 resume, the `startup_mp` hypercall is invoked on core 0 to initialize the other AP cores (1-15), and takes a reset vector (`rip`) as one of the arguments for where the core will execute from. During this time on cores 1-15, an insecure Nested Page Table (NPT) config is applied. We can abuse this to run some shellcode that has R/W into the hypervisor's address space including the VM Control Blocks (VMCBs).

Very similarly to (one version of) [byepervisor of old](https://github.com/PS5Dev/Byepervisor), this exploits the rest mode path too :)

Currently only the following firmwares are fully supported:

- 13.60
- 13.20
- 13.00 (untested)
- 10.01 (regular console; PS5 Pro is not yet supported)

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
