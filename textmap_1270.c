#include <stdint.h>
#include <string.h>

#include <ps5/kernel.h>

#include "kdlsym.h"
#include "textmap_1270.h"

#define TEXT_BYTES    0xd50000ULL
#define PAGE_BYTES    0x1000ULL
#define LARGE_BYTES   0x200000ULL
#define PRESENT       (1ULL << 0)
#define RW            (1ULL << 1)
#define LARGE_PAGE    (1ULL << 7)
#define XOTEXT        (1ULL << 58)
#define NX            (1ULL << 63)
#define A_D_BITS      ((1ULL << 5) | (1ULL << 6))
#define FRAME_4K      0x000ffffffffff000ULL
#define FRAME_2M      0x000fffffffe00000ULL
#define RAM_LIMIT     0x1000000000ULL
#define MAX_CHANGES   (TEXT_BYTES / PAGE_BYTES + 16)

typedef struct {
  uint64_t address;
  uint64_t original;
} text_entry_t;

static text_entry_t entries[MAX_CHANGES];
static unsigned entry_count, applied_count;
static unsigned small_count, large_count;

static int read64(uint64_t address, uint64_t *value)
{
  *value = 0;
  return kernel_copyout((intptr_t)address, value, sizeof(*value));
}

static int write64(uint64_t address, uint64_t value)
{
  return kernel_copyin(&value, (intptr_t)address, sizeof(value));
}

static uint64_t updated(uint64_t original)
{
  return (original & ~XOTEXT) | RW;
}

static int matches(uint64_t live, uint64_t expected)
{
  return ((live ^ expected) & ~A_D_BITS) == 0;
}

static int next_table(uint64_t dmap, uint64_t entry, uint64_t *table)
{
  uint64_t frame = entry & FRAME_4K;
  if (!(entry & PRESENT) || (entry & LARGE_PAGE) || !frame ||
      frame >= RAM_LIMIT)
    return -1;
  *table = dmap + frame;
  return 0;
}

static int record(uint64_t address, uint64_t value)
{
  if (entry_count >= MAX_CHANGES || !(value & PRESENT) || (value & NX) ||
      !(value & XOTEXT) || (value & RW))
    return -1;
  for (unsigned i = 0; i < entry_count; ++i)
    if (entries[i].address == address)
      return -1;
  entries[entry_count++] = (text_entry_t){address, value};
  return 0;
}

static int restore_written(void)
{
  int failed = 0;
  for (unsigned i = applied_count; i != 0; --i) {
    text_entry_t *entry = &entries[i - 1];
    uint64_t current = 0, observed = 0;
    if (read64(entry->address, &current) != 0) {
      failed = 1;
      continue;
    }
    if (matches(current, entry->original))
      continue;
    if (!matches(current, updated(entry->original))) {
      failed = 1;
      continue;
    }
    uint64_t restored = (current & ~(XOTEXT | RW)) |
                        (entry->original & (XOTEXT | RW));
    if (write64(entry->address, restored) != 0 ||
        read64(entry->address, &observed) != 0 ||
        !matches(observed, entry->original))
      failed = 1;
  }
  if (!failed)
    applied_count = 0;
  return failed ? -1 : 0;
}

int textmap_1270_prepare(textmap_1270_status_t *status,
                         textmap_1270_progress_fn progress)
{
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  uint64_t dmap = kdldmap(0);
  uint64_t pml4 = 0, cr3 = 0;
  if (!status || !progress || entry_count || applied_count ||
      data <= text || data - text != TEXT_BYTES || !pmap || !dmap ||
      read64(pmap + 0x20, &pml4) != 0 ||
      read64(pmap + 0x28, &cr3) != 0 || !cr3 || (cr3 & 0xfff) ||
      pml4 != dmap + (cr3 & FRAME_4K))
    return -1;
  memset(status, 0, sizeof(*status));

  uint64_t last_pde = UINT64_MAX;
  for (uint64_t off = 0; off < TEXT_BYTES;) {
    uint64_t va = text + off, table = pml4, value = 0, address = 0;
    const unsigned shifts[3] = {39, 30, 21};
    for (unsigned level = 0; level < 3; ++level) {
      address = table + 8 * ((va >> shifts[level]) & 0x1ffULL);
      if (read64(address, &value) != 0 || !(value & PRESENT) ||
          (value & NX))
        return -2;
      if (level < 2 && (!(value & RW) || (value & XOTEXT) ||
                        next_table(dmap, value, &table) != 0))
        return -3;
    }
    if (value & LARGE_PAGE) {
      uint64_t frame = value & FRAME_2M;
      if (!frame || frame >= RAM_LIMIT || record(address, value) != 0)
        return -4;
      ++large_count;
      uint64_t step = LARGE_BYTES - (va & (LARGE_BYTES - 1));
      off += step < TEXT_BYTES - off ? step : TEXT_BYTES - off;
      continue;
    }
    if (address != last_pde) {
      if (next_table(dmap, value, &table) != 0)
        return -5;
      last_pde = address;
    } else if (next_table(dmap, value, &table) != 0) {
      return -5;
    }
    uint64_t pte_address = table + 8 * ((va >> 12) & 0x1ffULL);
    uint64_t pte = 0;
    if (read64(pte_address, &pte) != 0 || !(pte & FRAME_4K) ||
        (pte & FRAME_4K) >= RAM_LIMIT || record(pte_address, pte) != 0)
      return -6;
    ++small_count;
    off += PAGE_BYTES;
  }
  status->entries = entry_count;
  status->pages_4k = small_count;
  status->leaves_2m = large_count;
  /* KASLR changes alignment: observed valid layouts use either five or six
   * 2 MiB leaves. Both must cover exactly the same 3408 text pages. */
  if (entry_count != small_count + large_count ||
      small_count + 512U * large_count != TEXT_BYTES / PAGE_BYTES ||
      (large_count != 5 && large_count != 6))
    return -7;
  if (progress("planned", entry_count) != 0)
    return -8;

  /* Validate the immutable plan before its first store. */
  for (unsigned i = 0; i < entry_count; ++i) {
    uint64_t current = 0;
    if (read64(entries[i].address, &current) != 0 ||
        !matches(current, entries[i].original))
      return -9;
  }
  for (unsigned i = 0; i < entry_count; ++i) {
    uint64_t current = 0, observed = 0;
    if (read64(entries[i].address, &current) != 0 ||
        !matches(current, entries[i].original))
      goto failed;
    entries[i].original = current;
    applied_count = i + 1;
    if (write64(entries[i].address, updated(current)) != 0 ||
        read64(entries[i].address, &observed) != 0 ||
        !matches(observed, updated(current)))
      goto failed;
    if ((applied_count % 32) == 0 &&
        progress("applied", applied_count) != 0)
      goto failed;
  }
  if (textmap_1270_verify() != (int)entry_count)
    goto failed;
  status->applied = applied_count;
  if (progress("verified", applied_count) != 0)
    goto failed;
  return 0;

failed:
  return restore_written() == 0 ? -10 : -11;
}

int textmap_1270_verify(void)
{
  unsigned verified = 0;
  if (!entry_count || applied_count != entry_count)
    return -1;
  for (unsigned i = 0; i < entry_count; ++i) {
    uint64_t current = 0;
    if (read64(entries[i].address, &current) == 0 &&
        matches(current, updated(entries[i].original)))
      ++verified;
  }
  return (int)verified;
}

int textmap_1270_restore(void)
{
  if (!entry_count || applied_count != entry_count)
    return -1;
  for (unsigned i = 0; i < entry_count; ++i) {
    uint64_t current = 0;
    if (read64(entries[i].address, &current) != 0 ||
        !matches(current, updated(entries[i].original)))
      return -2;
  }
  return restore_written();
}
