#include <lib/debug.h>
#include "threads/thread.h"
#include "devices/timer.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "threads/interrupt.h"
#include "vm/swap.h"

frame_table_info g_frame_table;

void update_freshness(struct thread* t)
{
  ASSERT(intr_get_level() == INTR_OFF);
  if (t != NULL && t->status != THREAD_DYING) {
    uint32_t* pd = t->pagedir;

    if (pd == NULL) {
      return;
    }
    int64_t newFreshness = timer_ticks();
    uint32_t* pde;
    for (pde = pd; pde < pd + pd_no(PHYS_BASE); pde++) {
      if (*pde & PTE_P) {
        uint32_t* pt = pde_get_pt(*pde);
        uint32_t* pte;

        for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++) {
          if (*pte & PTE_P) {
            void* p = pte_get_page(*pte);
            if (pagedir_is_dirty(pd, p) || pagedir_is_accessed(pd, p)) {
              enum intr_level old = intr_disable();
              frame_table_entry* frame = find_frame_entry(p);
              frame->freshness = newFreshness;
              intr_set_level(old);
              pagedir_set_dirty(pd, p, 0);
              pagedir_set_accessed(pd, p, 0);
            }
          }
        }
      }
    }
  }
}

static
void is_src_in_mem(sup_pt_elem* spte, uint32_t aux UNUSED)
{
  ASSERT(spte->src == SRC_RAM
        || spte->src == SRC_M_FILE);
}

frame_table_entry* find_page_to_evict(void)
{
  ASSERT(intr_get_level() == INTR_OFF);
  frame_table_entry* ret = NULL;
  do
  {
    int64_t oldest = timer_ticks();
    for (size_t i = 0; i < g_frame_table.num_of_frame; ++i)
    {
      frame_table_entry* cur = g_frame_table.frame_tab + i;
      if (cur->is_allocated && !list_empty(&cur->u_page_sup) && !cur->is_pinned)
      {//traverse all allocated, installed, unpinned frame
        process_sptes(&cur->u_page_sup, is_src_in_mem, 0);
        //assertion purpose
        int64_t cur_time = cur->freshness;
        if (oldest >= cur_time)
        {
          ret = cur;
          oldest = cur_time;
        }
      }
    }
  }while(ret == NULL);
  return ret;
}

frame_table_entry* find_frame_entry(void *kpage_user)
{
  ASSERT(((uintptr_t)kpage_user & 0xfff) == 0);
  ASSERT(g_frame_table.user_page_start != NULL);

  size_t ft_idx = ((uint8_t*)kpage_user -
      g_frame_table.user_page_start) / PGSIZE;
  return g_frame_table.frame_tab + ft_idx;
}


void* find_page_given_frame(frame_table_entry* entry)
{
  ASSERT(((uintptr_t)entry -
    (uintptr_t)g_frame_table.frame_tab) %
    sizeof(frame_table_entry) == 0);
  ASSERT(entry - g_frame_table.frame_tab < (int32_t)g_frame_table.num_of_frame)
  return (void*)g_frame_table.user_page_start +
    (entry - g_frame_table.frame_tab) * PAGE_SIZE;
}
