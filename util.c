#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/cpuset.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "util.h"

int kread(uint64_t kaddr, void *dst, size_t len)
{
  return kernel_copyout(kaddr, dst, len);
}

int kwrite(uint64_t kaddr, const void *src, size_t len)
{
  return kernel_copyin(src, kaddr, len);
}

uint32_t kread32(uint64_t kaddr)
{
  uint32_t v = 0;
  kread(kaddr, &v, sizeof(v));
  return v;
}

uint64_t kread64(uint64_t kaddr)
{
  uint64_t v = 0;
  kread(kaddr, &v, sizeof(v));
  return v;
}

void kwrite32(uint64_t kaddr, uint32_t val)
{
  uint32_t t = val;
  kwrite(kaddr, &t, sizeof(t));
}

void kwrite64(uint64_t kaddr, uint64_t val)
{
  uint64_t t = val;
  kwrite(kaddr, &t, sizeof(t));
}

int pin_to_core(int num)
{
  uint64_t mask[2] = {};
  cpusetid_t new_id;

  if(cpuset(&new_id)) {
    return 1;
  }

  mask[0] = 0xFFFF;
  mask[1] = 0;
  cpuset_setaffinity(3, 3, new_id, 8, (const cpuset_t *) mask);
  
  // Sony affinity bits run in reverse order from per-CPU/TSS array rows.
  mask[0] = 1 << (15 - num);
  mask[1] = 0;
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *) mask);
}

void pin_to_first_available_core()
{
  for (int i = 0; i < 16; i++) {
    if (pin_to_core(i) == 0) {
      break;
    }
  }
}

int get_cpu_core()
{
  return sceKernelGetCurrentCpu();
}

void notifyf(const char *fmt, ...)
{
  notify_request_t req;
  bzero(&req, sizeof req);
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(req.message, sizeof req.message, fmt, ap);
  va_end(ap);
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}

void klog(const char *fmt, ...)
{
  char buffer[512];

  va_list args;
  va_start(args, fmt);
  vsprintf(buffer, fmt, args);
  va_end(args);

  sceKernelDebugOutText(0, buffer);
}

void kHexDump(uint64_t kaddr, uint64_t len) {
  char hexdump[0x1000] = {};
  uint64_t size = len;
  char *data = (char *) &hexdump;

  kread(kaddr, data, len);

	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
		klog("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
			klog(" ");
			if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
				klog("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
          klog(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
					klog("   ");
				}
        printf("|  %s \n", ascii);
				klog("|  %s \n", ascii);
			}
		}
	}
}
