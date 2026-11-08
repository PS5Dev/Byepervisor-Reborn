#ifndef DUMP_H
#define DUMP_H

#include <stdint.h>

/* Offset from HV loader base to the HV ELF image */
#define HV_ELF_OFF 0x32000

int dump_kernel_text(const char *path);
int dump_hv_image(const char *path);

#endif // DUMP_H
