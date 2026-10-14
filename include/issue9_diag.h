#ifndef ISSUE9_DIAG_H
#define ISSUE9_DIAG_H

#include <stddef.h>
#include <stdint.h>

int issue9_diag_run(uint64_t cave);
int issue9_dr0_diag_run(uint64_t cave);
int issue9_resume_diag_run(uint64_t cave);
int issue9_resume_abort_run(uint64_t cave);

#define ISSUE9_PROD_STASH_OFF 0x3400ULL

int issue9_production_is_armed(uint64_t cave);
int issue9_production_arm(uint64_t cave, uint64_t cr3,
                          uint64_t hv_loader_pa,
                          const uint8_t *payload, size_t payload_len);
int issue9_production_cleanup(uint64_t cave);

#endif
