#ifndef TEXTMAP_1270_H
#define TEXTMAP_1270_H

#include <stdint.h>

typedef int (*textmap_1270_progress_fn)(const char *stage, unsigned count);

typedef struct {
  unsigned entries;
  unsigned pages_4k;
  unsigned leaves_2m;
  unsigned applied;
} textmap_1270_status_t;

/* Requires a pristine 12.70 text map. A successful prepare remains active
 * until reboot or an explicit guarded restore. */
int textmap_1270_prepare(textmap_1270_status_t *status,
                         textmap_1270_progress_fn progress);
int textmap_1270_verify(void);
int textmap_1270_restore(void);

#endif
