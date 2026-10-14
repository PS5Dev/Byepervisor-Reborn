#ifndef KHOOK_H
#define KHOOK_H

#include <stdint.h>
#include <stddef.h>

#include "kdlsym.h"

typedef int (*kh_read_fn)(uint64_t kaddr, void *dst, size_t len);
typedef int (*kh_write_fn)(uint64_t kaddr, const void *src, size_t len);

#define KH_RC_RBP  0x20
#define KH_RC_RSP  0x28
#define KH_RC_RIP  0x38
#define KH_RC_DR7  0xa0

#define KH_USER_CS        0x43
#define KH_USER_SS        0x3b
#define KH_RFLAGS_USER    0x202ULL
#define KH_RF             0x10000ULL
#define KH_DR7_BP0_EXEC   0x403ULL

#define KH_GATE_INTERRUPT 0xE
#define KH_VEC_DB         1
#define KH_TSS_IST1       0x24
#define KH_TSS_IST(k)     (KH_TSS_IST1 + ((uint64_t)((k)-1) * 8))
#define KH_TSS_STRIDE     0x68
#define KH_KIMG_MAX       0x4000000ULL

#define KH_OFF_CHAIN_ARM   0x040
#define KH_OFF_CHAIN_CONT  0x0a0
#define KH_OFF_RESUME      0x140
#define KH_OFF_CHAIN_DISP  0x240
#define KH_OFF_USER        0x440
#define KH_SCRATCH_MIN     0x500
#define KH_SCRATCH_BIG     0x4000
#define KH_OFF_BIG_CHAIN   0x3a00

typedef struct {
  uint8_t *buf;
  size_t cap;
  size_t len;
  int err;
} kh_chain_t;

void kh_chain_init(kh_chain_t *chain, uint8_t *buf, size_t cap);
int kh_chain_q(kh_chain_t *chain, uint64_t raw);        // push qword
int kh_chain_g(kh_chain_t *chain, kgadget_t gadget);    // push kgadget(gadget)
int kh_chain_store(kh_chain_t *chain, uint64_t kaddr, uint64_t val);
int kh_chain_memcpy(kh_chain_t *chain, uint64_t dst_kaddr, uint64_t src_kaddr, uint64_t n_bytes);
int kh_chain_call(kh_chain_t *chain, uint64_t fn_kaddr, int argc, uint64_t a0, uint64_t a1, uint64_t a2);

typedef struct {
  kh_read_fn  read;
  kh_write_fn write;

  uint64_t kernel_base;
  uint64_t idt_base;
  uint64_t tss_base;
  uint64_t tss_stride;
  int core_id;
  uint64_t scratch_base;
  int ist_index;
  uint64_t hook_kaddr;

  uint16_t kcs;
  uint64_t saved_gate_lo, saved_gate_hi, saved_ist;
  int installed;

  // 1 = fire once - the resume tail clears DR7 before returning
  // 0 = persistent
  int oneshot;

  uint64_t resume_rip;

  int resume_rax_set;
  uint64_t resume_rax;
  int resume_rsi_set;
  uint64_t resume_rsi;
  int resume_rdi_set;
  uint64_t resume_rdi;
  int resume_rdx_set;
  uint64_t resume_rdx;

  uint64_t arm_rip_slot;
  uint64_t arm_rsp_slot;
} khook_t;

int  kh_init(khook_t *kh, kh_read_fn rd, kh_write_fn wr, uint64_t kernel_base, uint64_t scratch_base, int ist_index);

void kh_set_hook_target(khook_t *kh, uint64_t kaddr);
void kh_set_resume_rip(khook_t *kh, uint64_t kaddr);
void kh_set_resume_skip(khook_t *kh, uint64_t skip_bytes);


void kh_set_resume_rax(khook_t *kh, uint64_t rax);
void kh_clear_resume_rax(khook_t *kh);

void kh_set_resume_rsi(khook_t *kh, uint64_t rsi);
void kh_clear_resume_rsi(khook_t *kh);

void kh_set_resume_rdi(khook_t *kh, uint64_t rdi);
void kh_clear_resume_rdi(khook_t *kh);

void kh_set_resume_rdx(khook_t *kh, uint64_t rdx);
void kh_clear_resume_rdx(khook_t *kh);

void kh_set_tables(khook_t *kh, uint64_t idt_base, uint64_t tss_base);
void kh_set_core(khook_t *kh, int core_id);

uint64_t kh_find_cave(khook_t *kh, uint64_t start, uint64_t len, size_t need);
uint64_t kh_user_data_addr(const khook_t *kh);

int  kh_install(khook_t *kh, const kh_chain_t *handler);
int  kh_trigger(khook_t *kh);

int  kh_disarm(khook_t *kh);
int  kh_restore(khook_t *kh);

#endif // KHOOK_H
