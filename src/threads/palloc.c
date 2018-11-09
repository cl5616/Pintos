#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/pte.h"
#include "devices/timer.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "threads/interrupt.h"
/* Page allocator.  Hands out memory in page-size (or
   page-multiple) chunks.  See malloc.h for an allocator that
   hands out smaller chunks.

   System memory is divided into two "pools" called the kernel
   and user pools.  The user pool is for user (virtual) memory
   pages, the kernel pool for everything else.  The idea here is
   that the kernel needs to have memory for its own operations
   even if user processes are swapping like mad.

   By default, half of system RAM is given to the kernel pool and
   half to the user pool.  That should be huge overkill for the
   kernel pool, but that's just fine for demonstration purposes. */

/* A memory pool. */
struct pool
  {
    struct lock lock;                   /* Mutual exclusion. */
    struct bitmap *used_map;            /* Bitmap of free pages. */
    uint8_t *base;                      /* Base of pool. */
  };

/* Two pools: one for kernel data, one for user pages. */
static struct pool kernel_pool, user_pool;

static void init_pool (struct pool *, void *base, size_t page_cnt,
                       const char *name);
static bool page_from_pool (const struct pool *, void *page);

/* Initializes the page allocator.  At most USER_PAGE_LIMIT
   pages are put into the user pool. */
void
palloc_init (size_t user_page_limit)
{
  /* Free memory starts at 1 MB and runs to the end of RAM. */
  uint8_t *free_start = ptov (1024 * 1024);
  uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
  uint8_t *real_free_start;
  size_t free_pages = (free_end - free_start) / PGSIZE;
  size_t user_pages = free_pages / 2;
  size_t kernel_pages;
  if (user_pages > user_page_limit)
    user_pages = user_page_limit;
  kernel_pages = free_pages - user_pages;

  real_free_start = pg_round_up(free_start + user_pages * sizeof(frame_table_entry));
  //so memory between real_free_start and free start is frame table
  size_t kernel_page_consumed = (real_free_start - free_start) / PGSIZE;
  g_frame_table.frame_tab = (frame_table_entry*)free_start;
  g_frame_table.num_of_frame = user_pages;

  /* Give half of memory to kernel, half to user. */
  init_pool (&kernel_pool, real_free_start,
    kernel_pages - kernel_page_consumed, "kernel pool");
  init_pool (&user_pool, free_start + kernel_pages * PGSIZE,
             user_pages, "user pool");
  g_frame_table.user_page_start = user_pool.base;
  //thread system not started yet, so do not need lock
  for (size_t i = 0; i < g_frame_table.num_of_frame; ++i)
  {
    list_init(&g_frame_table.frame_tab[i].u_page_sup);
  }
}

/* Obtains and returns a group of PAGE_CNT contiguous free pages.
   If PAL_USER is set, the pages are obtained from the user pool,
   otherwise from the kernel pool.  If PAL_ZERO is set in FLAGS,
   then the pages are filled with zeros.  If too few pages are
   available, returns a null pointer, unless PAL_ASSERT is set in
   FLAGS, in which case the kernel panics. */
void *
palloc_get_multiple (enum palloc_flags flags, size_t page_cnt)
{
  struct pool *pool = flags & PAL_USER ? &user_pool : &kernel_pool;
  void *pages;
  size_t page_idx;

  if (page_cnt == 0)
    return NULL;

  lock_acquire (&pool->lock);
  page_idx = bitmap_scan_and_flip (pool->used_map, 0, page_cnt, false);
  lock_release (&pool->lock);


  if (page_idx != BITMAP_ERROR)
    pages = pool->base + PGSIZE * page_idx;
  else
    pages = NULL;


  if (pages != NULL)
    {
      if (flags & PAL_ZERO)
        memset (pages, 0, PGSIZE * page_cnt);
      if (flags & PAL_USER)
      {
        void* i_page = pages;
        for (size_t i = 0; i < page_cnt; ++i)
        {
          lock_acquire(&ft_spt_lock);
          frame_table_entry* user_frame = find_frame_entry(i_page);
          ASSERT(!user_frame->is_allocated);
          ASSERT(!user_frame->is_pinned);
          ASSERT(list_empty(&user_frame->u_page_sup));
          enum intr_level old = intr_disable();
          user_frame->freshness = timer_ticks();
          intr_set_level(old);
          user_frame->is_allocated = true;
          user_frame->rom_id = 0;
          lock_release(&ft_spt_lock);
          i_page += PAGE_SIZE;
        }
      }
    }
  else
    {
      if (flags & PAL_ASSERT)
      {
        PANIC ("palloc_get: out of pages");
      }
      else
      {
        if (flags & PAL_USER)
        {
          if (page_cnt > 1)
            PANIC("cannot evict multiple pages");
          struct list* sup_ent;
          lock_acquire(&ft_spt_lock);
          enum intr_level old = intr_disable();
          frame_table_entry*
              frame_to_be_swapped = find_page_to_evict();
          intr_set_level(old);
          ASSERT (!list_empty(&frame_to_be_swapped->u_page_sup));
          ASSERT (frame_to_be_swapped->is_allocated);
          ASSERT (!frame_to_be_swapped->is_pinned);

          //must be mapped into user space
          pages = find_page_given_frame(frame_to_be_swapped);
          sup_ent = &frame_to_be_swapped->u_page_sup;
          old = intr_disable();
          frame_to_be_swapped->freshness = timer_ticks();
          intr_set_level(old);

          store_page(sup_ent);
          list_init(&frame_to_be_swapped->u_page_sup);
          frame_to_be_swapped->rom_id = 0;
          //empty the list
          lock_release(&ft_spt_lock);
          if (flags & PAL_ZERO)
          {
            memset(pages, 0, PGSIZE);
          }
        }
        else
        {
          pages = NULL;
        }
      }
    }
  return pages;
}

/* Obtains a single free page and returns its kernel virtual
   address.
   If PAL_USER is set, the page is obtained from the user pool,
   otherwise from the kernel pool.  If PAL_ZERO is set in FLAGS,
   then the page is filled with zeros.  If no pages are
   available, returns a null pointer, unless PAL_ASSERT is set in
   FLAGS, in which case the kernel panics. */
void *
palloc_get_page (enum palloc_flags flags)
{
  void* ret = palloc_get_multiple (flags, 1);
  return ret;
}

/* Frees the PAGE_CNT pages starting at PAGES. */
void
palloc_free_multiple (void *pages, size_t page_cnt)
{
  struct pool *pool;
  size_t page_idx;

  ASSERT (pg_ofs (pages) == 0);
  if (pages == NULL || page_cnt == 0)
    return;

  if (page_from_pool (&kernel_pool, pages))
    pool = &kernel_pool;
  else if (page_from_pool (&user_pool, pages))
    {
      pool = &user_pool;
      void* i_pages = pages;
      for (size_t i = 0; i < page_cnt; ++i)
      {
        lock_acquire(&ft_spt_lock);
        falloc_free_frame(i_pages);
        lock_release(&ft_spt_lock);
        i_pages += PAGE_SIZE;
      }
    }
  else
    NOT_REACHED ();

  page_idx = pg_no (pages) - pg_no (pool->base);

#ifndef NDEBUG
  memset (pages, 0xcc, PGSIZE * page_cnt);
#endif

  ASSERT (bitmap_all (pool->used_map, page_idx, page_cnt));
  bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
}

/* Frees the page at PAGE. */
void
palloc_free_page (void *page)
{
  palloc_free_multiple (page, 1);
}

/* Initializes pool P as starting at START and ending at END,
   naming it NAME for debugging purposes. */
static void
init_pool (struct pool *p, void *base, size_t page_cnt, const char *name)
{
  /* We'll put the pool's used_map at its base.
     Calculate the space needed for the bitmap
     and subtract it from the pool's size. */
  size_t bm_pages = DIV_ROUND_UP (bitmap_buf_size (page_cnt), PGSIZE);
  if (bm_pages > page_cnt)
    PANIC ("Not enough memory in %s for bitmap.", name);
  page_cnt -= bm_pages;

  printf ("%zu pages available in %s.\n", page_cnt, name);

  /* Initialize the pool. */
  lock_init (&p->lock);
  p->used_map = bitmap_create_in_buf (page_cnt, base, bm_pages * PGSIZE);
  p->base = base + bm_pages * PGSIZE;
}

/* Returns true if PAGE was allocated from POOL,
   false otherwise. */
static bool
page_from_pool (const struct pool *pool, void *page)
{
  size_t page_no = pg_no (page);
  size_t start_page = pg_no (pool->base);
  size_t end_page = start_page + bitmap_size (pool->used_map);

  return page_no >= start_page && page_no < end_page;
}
