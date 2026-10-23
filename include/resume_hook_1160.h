#ifndef RESUME_HOOK_1160_H
#define RESUME_HOOK_1160_H

#include <stddef.h>
#include <stdint.h>

#define RESUME_1160_FW_RAW     0x11600005U
#define RESUME_1160_RESULT_OFF 0x3600ULL

int resume_hook_1160_is_armed(uint64_t cave);
int resume_hook_1160_arm(uint64_t cave, uint64_t cr3,
                         uint64_t scan_lo, uint64_t scan_hi,
                         const uint8_t *payload, size_t payload_len);
int resume_hook_1160_cleanup(uint64_t cave);

#endif
