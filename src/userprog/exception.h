#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H
#include "threads/vaddr.h"
/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

void exception_init (void);
void exception_print_stats (void);

#define NUM_OF_STACK_PAGE 0x40
#define STACK_SIZE (NUM_OF_STACK_PAGE*PGSIZE)
#define LOWEST_STACK_TOP (PHYS_BASE-STACK_SIZE)
#define NUM_OF_GEN_REG 8
#define ESP_BOUNDARY (NUM_OF_GEN_REG * sizeof(uintptr_t))


static inline bool
is_stack_access(const void* cr2)
{
  return LOWEST_STACK_TOP <= cr2 && cr2 < PHYS_BASE - PGSIZE;
}

#endif /* userprog/exception.h */
