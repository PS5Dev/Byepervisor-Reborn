#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <ps5/kernel.h>

#include "kdlsym.h"
#include "khook.h"
#include "util.h"

#define FW_1270 0x12700000U

static int read64(uint64_t address, uint64_t *value)
{
  *value = 0;
  return kernel_copyout(address, value, sizeof *value);
}

int main(void)
{
  uint32_t fw = kernel_get_fw_version();
  int soc = sceKernelGetMainSocId();
  if ((fw & 0xffff0000U) != FW_1270 || soc != 0x840f60) {
    printf("CENSUS1270,stop,fw=0x%08x,soc=0x%x\n", fw, soc);
    return 2;
  }

  uint64_t gate = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16 * KH_VEC_DB;
  uint64_t tss = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t gate_lo, gate_hi;
  if (read64(gate, &gate_lo) != 0 || read64(gate + 8, &gate_hi) != 0)
    return 3;
  uint64_t handler = (gate_lo & 0xffffULL)
                   | (((gate_lo >> 48) & 0xffffULL) << 16)
                   | ((gate_hi & 0xffffffffULL) << 32);
  unsigned ist = (unsigned)((gate_lo >> 32) & 7);
  unsigned present = (unsigned)((gate_lo >> 47) & 1);
  printf("CENSUS1270,gate,lo=0x%016" PRIx64 ",hi=0x%016" PRIx64
         ",handler=0x%016" PRIx64 ",ist=%u,present=%u\n",
         gate_lo, gate_hi, handler, ist, present);

  uint64_t rsp0[KH_1270_NCPU], ist4[KH_1270_NCPU];
  unsigned bad = !present || ist != 4 ||
                 handler < ktext(0) || handler >= ktext(KH_KIMG_MAX);
  for (unsigned core = 0; core < KH_1270_NCPU; core++) {
    uint64_t row = tss + (uint64_t)core * KH_TSS_STRIDE;
    uint64_t ist6;
    if (read64(row + 0x04, &rsp0[core]) != 0 ||
        read64(row + KH_TSS_IST(4), &ist4[core]) != 0 ||
        read64(row + KH_TSS_IST(6), &ist6) != 0) {
      printf("CENSUS1270,stop,stage=tss-read,core=%u\n", core);
      return 4;
    }
    printf("CENSUS1270,tss,core=%u,rsp0=0x%016" PRIx64
           ",ist4=0x%016" PRIx64 ",ist6=0x%016" PRIx64 "\n",
           core, rsp0[core], ist4[core], ist6);
    if ((rsp0[core] >> 47) != 0x1ffffULL || ist4[core] == 0 || ist6 != 0)
      bad++;
    for (unsigned prior = 0; prior < core; prior++)
      if (rsp0[core] == rsp0[prior] || ist4[core] == ist4[prior])
        bad++;
  }

  unsigned occupied = 0;
  uint8_t block[KH_1270_FALLBACK_STRIDE];
  for (unsigned off = 0; off < KH_1270_FALLBACK_SIZE; off += sizeof block) {
    if (kernel_copyout(cave + KH_1270_FALLBACK_OFF + off,
                       block, sizeof block) != 0) {
      printf("CENSUS1270,stop,stage=cave-read,off=0x%x\n", off);
      return 5;
    }
    for (unsigned i = 0; i < sizeof block; i++)
      if (block[i] != 0)
        occupied++;
  }
  printf("CENSUS1270,result,cores=%u,occupied_fallback_bytes=%u,bad=%u\n",
         KH_1270_NCPU, occupied, bad);
  return bad == 0 && occupied == 0 ? 0 : 6;
}
