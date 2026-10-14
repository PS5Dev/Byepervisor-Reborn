#include <stdint.h>
#include <string.h>

#include "fw_1001_textmap.h"
#include "paging.h"

/* paging.h's historical mask includes bit 11; page-table pointers do not. */
#define PAGE_TABLE_ADDR_MASK 0x000ffffffffff000ULL

static uint64_t next_boundary(uint64_t va, uint64_t size, uint64_t end)
{
  uint64_t next = (va & ~(size - 1)) + size;
  return next < end ? next : end;
}

static uint64_t updated_entry(uint64_t original)
{
  CLEAR_PDE_BIT(original, XOTEXT);
  SET_PDE_BIT(original, RW);
  return original;
}

static int matches_with_hw_drift(uint64_t live, uint64_t expected)
{
  const uint64_t hw_mask = (1ULL << PDE_ACCESSED) | (1ULL << PDE_DIRTY);
  return (live & ~hw_mask) == (expected & ~hw_mask);
}

static int append_leaf(fw_1001_textmap_plan_t *plan, uint64_t va,
                       uint64_t next, uint64_t level, uint64_t address,
                       uint64_t original)
{
  if (plan->count >= FW_1001_TEXTMAP_MAX_LEAVES ||
      !PDE_FIELD(original, PRESENT) || !PDE_FIELD(original, XOTEXT) ||
      PDE_FIELD(original, RW))
    return -1;
  for (uint64_t i = 0; i < plan->count; ++i)
    if (plan->address[i] == address)
      return -2;

  plan->address[plan->count] = address;
  plan->original[plan->count++] = original;
  plan->pages += (next - va) >> 12;
  if (level == 3)
    plan->leaves_1g++;
  else if (level == 2)
    plan->leaves_2m++;
  else
    plan->leaves_4k++;
  return 0;
}

int fw_1001_textmap_build(fw_1001_textmap_plan_t *plan, uint64_t pml4,
                          uint64_t dmap, uint64_t begin, uint64_t end,
                          fw_1001_read64_fn read64, void *opaque)
{
  uint64_t va;

  if (!plan || !pml4 || !read64 || end <= begin ||
      ((begin | end) & 0xfff) != 0 || end - begin != FW_1001_TEXT_SIZE)
    return -1;
  memset(plan, 0, sizeof(*plan));

  for (va = begin; va < end;) {
    uint64_t address;
    uint64_t entry;
    uint64_t next;
    uint64_t level;

    address = pml4 + (((va >> 39) & 0x1ff) * 8);
    entry = read64(address, opaque);
    if (!PDE_FIELD(entry, PRESENT))
      return -2;
    address = dmap + (entry & PAGE_TABLE_ADDR_MASK) +
              (((va >> 30) & 0x1ff) * 8);
    entry = read64(address, opaque);
    if (!PDE_FIELD(entry, PRESENT))
      return -3;
    if (PDE_FIELD(entry, PS))
      return -4;

    address = dmap + (entry & PAGE_TABLE_ADDR_MASK) +
              (((va >> 21) & 0x1ff) * 8);
    entry = read64(address, opaque);
    if (!PDE_FIELD(entry, PRESENT))
      return -5;
    if (PDE_FIELD(entry, PS)) {
      next = next_boundary(va, 1ULL << 21, end);
      level = 2;
    } else {
      address = dmap + (entry & PAGE_TABLE_ADDR_MASK) +
                (((va >> 12) & 0x1ff) * 8);
      entry = read64(address, opaque);
      if (!PDE_FIELD(entry, PRESENT))
        return -6;
      next = next_boundary(va, 1ULL << 12, end);
      level = 1;
    }
    if (append_leaf(plan, va, next, level, address, entry) != 0)
      return -7;
    va = next;
  }

  if (plan->count == 0 || plan->pages != FW_1001_TEXT_PAGES ||
      plan->leaves_1g != 0 ||
      plan->leaves_2m + plan->leaves_4k != plan->count)
    return -8;
  return 0;
}

static uint64_t restore_exact(fw_1001_textmap_plan_t *plan,
                              fw_1001_read64_fn read64,
                              fw_1001_write64_fn write64, void *opaque)
{
  uint64_t restored = 0;

  for (uint64_t i = plan->applied; i != 0; --i)
    write64(plan->address[i - 1], plan->original[i - 1], opaque);
  for (uint64_t i = 0; i < plan->count; ++i)
    if (read64(plan->address[i], opaque) == plan->original[i])
      restored++;
  plan->restored_verified = restored;
  return restored;
}

int fw_1001_textmap_apply(fw_1001_textmap_plan_t *plan,
                          fw_1001_read64_fn read64,
                          fw_1001_write64_fn write64, void *opaque)
{
  int error = 0;

  if (!plan || !read64 || !write64 || plan->count == 0 ||
      plan->pages != FW_1001_TEXT_PAGES || plan->leaves_1g != 0 ||
      plan->leaves_2m + plan->leaves_4k != plan->count)
    return -1;
  plan->applied = 0;
  plan->changed_verified = 0;
  plan->restored_verified = 0;

  /* Revalidate the complete immutable plan before the first store. */
  for (uint64_t i = 0; i < plan->count; ++i)
    if (read64(plan->address[i], opaque) != plan->original[i])
      return -2;

  for (uint64_t i = 0; i < plan->count; ++i) {
    if (read64(plan->address[i], opaque) != plan->original[i]) {
      error = -3;
      break;
    }
    plan->applied = i + 1;
    write64(plan->address[i], updated_entry(plan->original[i]), opaque);
    if (read64(plan->address[i], opaque) != updated_entry(plan->original[i])) {
      error = -4;
      break;
    }
  }
  if (!error) {
    for (uint64_t i = 0; i < plan->count; ++i)
      if (read64(plan->address[i], opaque) == updated_entry(plan->original[i]))
        plan->changed_verified++;
    if (plan->changed_verified != plan->count)
      error = -5;
  }
  if (error && restore_exact(plan, read64, write64, opaque) != plan->count)
    return -6;
  return error;
}

uint64_t fw_1001_textmap_verify_updated(
    const fw_1001_textmap_plan_t *plan, fw_1001_read64_fn read64,
    void *opaque)
{
  uint64_t verified = 0;

  if (!plan || !read64)
    return 0;
  for (uint64_t i = 0; i < plan->count; ++i)
    if (matches_with_hw_drift(read64(plan->address[i], opaque),
                              updated_entry(plan->original[i])))
      verified++;
  return verified;
}

uint64_t fw_1001_textmap_restore_guarded(
    fw_1001_textmap_plan_t *plan, fw_1001_read64_fn read64,
    fw_1001_write64_fn write64, void *opaque)
{
  if (!plan || !read64 || !write64)
    return 0;
  for (uint64_t i = 0; i < plan->count; ++i) {
    uint64_t live = read64(plan->address[i], opaque);
    if (!matches_with_hw_drift(live, plan->original[i]) &&
        !matches_with_hw_drift(live, updated_entry(plan->original[i])))
      return 0;
  }
  plan->applied = plan->count;
  return restore_exact(plan, read64, write64, opaque);
}
