#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AP_1270_PRESTAGE
#define AP_1270_SECOND_MARKER
#define AP_1270_STORE_HANDLER
#include "../khook.c"

#define KBASE 0xffffffff80000000ULL
#define CAVE  0x100000ULL
#define TSS   0x200000ULL
#define IDT   0x300000ULL
#define GATE  (IDT + 16 * KH_VEC_DB)

static uint8_t cave_bytes[KH_SCRATCH_BIG];
static uint8_t tss_bytes[KH_1270_NCPU * KH_TSS_STRIDE];
static uint8_t idt_bytes[0x1000];
static uint64_t saved_gate_lo, saved_gate_hi;
static int gate_writes, ist_writes, gate_first, fail_core = -1;
static int fail_read_core = -1;

uint64_t kgadget(kgadget_t gadget)
{
  return KBASE + 0x1000 + (uint64_t)gadget * 0x10;
}

static uint8_t *mapped(uint64_t addr, size_t len)
{
  if (addr >= CAVE && addr - CAVE <= sizeof cave_bytes &&
      len <= sizeof cave_bytes - (size_t)(addr - CAVE))
    return cave_bytes + (addr - CAVE);
  if (addr >= TSS && addr - TSS <= sizeof tss_bytes &&
      len <= sizeof tss_bytes - (size_t)(addr - TSS))
    return tss_bytes + (addr - TSS);
  if (addr >= IDT && addr - IDT <= sizeof idt_bytes &&
      len <= sizeof idt_bytes - (size_t)(addr - IDT))
    return idt_bytes + (addr - IDT);
  return NULL;
}

static int ist_core(uint64_t addr)
{
  if (addr < TSS || addr >= TSS + sizeof tss_bytes)
    return -1;
  uint64_t off = addr - TSS;
  return off % KH_TSS_STRIDE == KH_TSS_IST(6)
       ? (int)(off / KH_TSS_STRIDE) : -1;
}

static int mock_read(uint64_t addr, void *dst, size_t len)
{
  uint8_t *p = mapped(addr, len);
  if (!p || (fail_read_core >= 0 &&
             ist_core(addr) == fail_read_core && len == 8))
    return -1;
  memcpy(dst, p, len);
  return 0;
}

static int mock_write(uint64_t addr, const void *src, size_t len)
{
  uint8_t *p = mapped(addr, len);
  if (!p || (fail_core >= 0 && ist_core(addr) == fail_core && len == 8))
    return -1;
  if (addr == GATE && len == 8) {
    if (ist_writes == KH_1270_NCPU)
      gate_first = 1;
    gate_writes++;
  }
  if (ist_core(addr) >= 0 && len == 8)
    ist_writes++;
  memcpy(p, src, len);
  return 0;
}

static uint64_t read64(uint64_t addr)
{
  uint64_t value = 0;
  assert(mock_read(addr, &value, 8) == 0);
  return value;
}

static void write64(uint64_t addr, uint64_t value)
{
  uint8_t *p = mapped(addr, 8);
  assert(p);
  memcpy(p, &value, 8);
}

static void reset_memory(void)
{
  memset(cave_bytes, 0, sizeof cave_bytes);
  memset(tss_bytes, 0, sizeof tss_bytes);
  memset(idt_bytes, 0, sizeof idt_bytes);
  gate_writes = ist_writes = gate_first = 0;
  fail_core = fail_read_core = -1;
  gate_encode(KBASE + 0x500, 0x20, 4, KH_GATE_INTERRUPT,
              0, 1, &saved_gate_lo, &saved_gate_hi);
  write64(GATE, saved_gate_lo);
  write64(GATE + 8, saved_gate_hi);
  for (unsigned core = 0; core < KH_1270_NCPU; core++) {
    uint64_t row = TSS + (uint64_t)core * KH_TSS_STRIDE;
    write64(row + 0x04, KBASE + 0x100000 + core * 0x1000);
    write64(row + KH_TSS_IST(4), KBASE + 0x200000 + core * 0x1000);
  }
}

static void init_hook(khook_t *kh)
{
  assert(kh_init(kh, mock_read, mock_write, KBASE, CAVE, 6) == 0);
  kh->tss_stride = KH_TSS_STRIDE;
  kh_set_tables(kh, IDT, TSS);
  kh_set_core(kh, 0);
  kh_set_hook_target(kh, KBASE + 0x3000);
  kh->oneshot = 1;
}

int main(void)
{
  khook_t kh;
  reset_memory();
  init_hook(&kh);
  int rc = kh_install(&kh, NULL);
  if (rc != 0)
    fprintf(stderr, "initial install failed: %d\n", rc);
  assert(rc == 0);
  assert(gate_writes == 1 && gate_first && ist_writes == KH_1270_NCPU);
  assert(read64(CAVE + KH_OFF_BIG_CHAIN + 0x00) ==
         kgadget(KERNEL_GADGET_POP_RCX));
  assert(read64(CAVE + KH_OFF_BIG_CHAIN + 0x08) == GATE);
  assert(read64(CAVE + KH_OFF_BIG_CHAIN + 0x18) == saved_gate_lo);
  assert(read64(CAVE + KH_OFF_BIG_CHAIN + 0x30) == 0);
  assert(read64(CAVE + KH_OFF_BIG_CHAIN + 0x38) ==
         kgadget(KERNEL_GADGET_SET_DR7));
  for (unsigned core = 1; core < KH_1270_NCPU; core++) {
    uint64_t top = CAVE + KH_1270_FALLBACK_OFF +
                   (uint64_t)(core - 1) * KH_1270_FALLBACK_STRIDE + 0x50;
    assert(read64(TSS + (uint64_t)core * KH_TSS_STRIDE + KH_TSS_IST(6)) == top);
    assert(read64(top) == kgadget(KERNEL_GADGET_POP_RSP));
    assert(read64(top + 8) == top - 0x30);
  }
  gate_writes = ist_writes = 0;
  assert(kh_restore(&kh) == 0);
  assert(gate_writes == 1 && ist_writes == KH_1270_NCPU);
  for (unsigned core = 0; core < KH_1270_NCPU; core++)
    assert(read64(TSS + (uint64_t)core * KH_TSS_STRIDE + KH_TSS_IST(6)) == 0);

  reset_memory();
  init_hook(&kh);
  write64(TSS + 7 * KH_TSS_STRIDE + KH_TSS_IST(6), KBASE + 0x7777);
  assert(kh_install(&kh, NULL) == -17);
  assert(gate_writes == 0 && ist_writes == 0);

  reset_memory();
  init_hook(&kh);
  fail_core = 5;
  assert(kh_install(&kh, NULL) == -21);
  assert(kh.installed && gate_writes == 0);
  fail_core = -1;
  assert(kh_restore(&kh) == 0);

  reset_memory();
  init_hook(&kh);
  assert(kh_install(&kh, NULL) == 0);
  fail_read_core = 5;
  assert(kh_restore(&kh) == -3 && kh.installed);
  fail_read_core = -1;
  assert(kh_restore(&kh) == 0);

  puts("12.70 per-CPU hook install and rollback checks passed");
  return 0;
}
