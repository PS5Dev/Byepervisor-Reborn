#ifndef FW_1001_TEXTMAP_H
#define FW_1001_TEXTMAP_H

#include <stdint.h>

#define FW_1001_TEXT_SIZE 0x00cc0000ULL
#define FW_1001_TEXT_PAGES (FW_1001_TEXT_SIZE / 0x1000ULL)
#define FW_1001_TEXTMAP_MAX_LEAVES FW_1001_TEXT_PAGES

typedef uint64_t (*fw_1001_read64_fn)(uint64_t address, void *opaque);
typedef void (*fw_1001_write64_fn)(uint64_t address, uint64_t value,
                                    void *opaque);

typedef struct {
  uint64_t address[FW_1001_TEXTMAP_MAX_LEAVES];
  uint64_t original[FW_1001_TEXTMAP_MAX_LEAVES];
  uint64_t count;
  uint64_t pages;
  uint64_t leaves_1g;
  uint64_t leaves_2m;
  uint64_t leaves_4k;
  uint64_t applied;
  uint64_t changed_verified;
  uint64_t restored_verified;
} fw_1001_textmap_plan_t;

int fw_1001_textmap_build(fw_1001_textmap_plan_t *plan, uint64_t pml4,
                          uint64_t dmap, uint64_t begin, uint64_t end,
                          fw_1001_read64_fn read64, void *opaque);
int fw_1001_textmap_apply(fw_1001_textmap_plan_t *plan,
                          fw_1001_read64_fn read64,
                          fw_1001_write64_fn write64, void *opaque);
uint64_t fw_1001_textmap_verify_updated(
    const fw_1001_textmap_plan_t *plan, fw_1001_read64_fn read64,
    void *opaque);
uint64_t fw_1001_textmap_restore_guarded(
    fw_1001_textmap_plan_t *plan, fw_1001_read64_fn read64,
    fw_1001_write64_fn write64, void *opaque);

#endif
