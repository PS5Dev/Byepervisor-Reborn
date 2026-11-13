#ifndef RESUME_HOOK_1140_H
#define RESUME_HOOK_1140_H

#include <stddef.h>
#include <stdint.h>

#define RESUME_1140_FW_MASK    0xFFFF0000U
#define RESUME_1140_FW_MATCH   0x11400000U
#define RESUME_1140_STASH_OFF  0x3400ULL
#define RESUME_1140_ORACLE_OFF 0x440ULL

#define RESUME_1140_MARK_ENTERED 0x454E544552454431ULL /* "ENTERED1" */
#define RESUME_1140_MARK_DONE    0x444F4E452D415031ULL /* "DONE-AP1" */

int resume_hook_1140_is_armed(uint64_t cave);
int resume_hook_1140_arm(uint64_t cave, uint64_t cr3,
                         uint64_t hv_base_pa,
                         const uint8_t *payload, size_t payload_len);
int resume_hook_1140_cleanup(uint64_t cave);

#endif
