#include "vm/swap.h"
#include "devices/block.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "threads/pte.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "vm/frame.h"
#include <debug.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "devices/timer.h"
#include "vm/executables.h"


swap_idx_t swap_size;
struct block* swap_device;
struct bitmap* used_map;

void swap_slot_init(void) {
  swap_device = block_get_role(BLOCK_SWAP);
  swap_size = block_size(swap_device) / SECTORS_PER_PAGE;
  used_map = bitmap_create(swap_size);
  if (used_map == NULL) {
    PANIC("fail to allocate memory for used_map");
  }
}

void load_page(sup_pt_elem* spte, void* kpage) {
  ASSERT(spte != NULL);

  ASSERT(spte->src == SRC_SWAP);

  swap_idx_t page_idx = spte->u.swap_info.swap_idx;
  bool exist = bitmap_test(used_map, page_idx);
  if (!exist) {
    PANIC("missing page");
  }
  bitmap_reset(used_map, page_idx);
  //todo, load rom id into frame table
  spte->src = SRC_RAM;
  spte->u.kpage = kpage;

  set_addr(spte->pt_entry, vtop(kpage));
  enum intr_level old = intr_disable();
  frame_table_entry* frame = find_frame_entry(kpage);
  frame->freshness = timer_ticks();
  intr_set_level(old);
  frame->rom_id = spte->u.swap_info.rom_id;

  for (size_t i = 0; i < SECTORS_PER_PAGE; ++i)
  {
    block_read(swap_device, page_idx * SECTORS_PER_PAGE + i,
                              kpage + BLOCK_SECTOR_SIZE * i);
  }

  set_p(spte->pt_entry);
}

//for debug assertion purpose
static
bool is_src_same(struct list* sptes)
{
  sup_pt_elem* first = list_entry(
        list_begin(sptes), sup_pt_elem, shared_elem);
  enum page_src src = first->src;

  struct list_elem *e;

  for (e = list_begin (sptes); e != list_end (sptes);
       e = list_next (e))
    {
      sup_pt_elem *spte = list_entry (e, sup_pt_elem, shared_elem);
      if (spte->src != src)
        return false;
    }
    return true;
}

inline static
bool is_valid_store_list(struct list* sptes)
{
  return sptes != NULL && !list_empty(sptes) && is_src_same(sptes);
}

void process_sptes(struct list* sptes, sptes_proc_t func, uint32_t aux)
{
  struct list_elem *e;

  for (e = list_begin (sptes); e != list_end (sptes);
       e = list_next (e))
    {//clear all P
      sup_pt_elem *spte = list_entry (e, sup_pt_elem, shared_elem);
      func(spte, aux);
    }
}

void set_swap_info(struct list* sptes, swap_idx_t idx, rom_id_t rom_id)
{
  struct list_elem *e;

  for (e = list_begin (sptes); e != list_end (sptes);
       e = list_next (e))
    {//clear all P
      sup_pt_elem *spte = list_entry (e, sup_pt_elem, shared_elem);
      spte->src = SRC_SWAP;
      spte->u.swap_info.swap_idx = idx;
      spte->u.swap_info.rom_id = rom_id;
    }
}

static
void clear_p_spte(sup_pt_elem* spte, uint32_t aux UNUSED)
{
  *spte->pt_entry &= (~(uint32_t)(PTE_P));
}


static
void clear_all_p_in_pt(struct list* sptes)
{
  process_sptes(sptes, clear_p_spte, 0);
}

void store_page(struct list* sptes) {

  sup_pt_elem* first = list_entry(
        list_begin(sptes), sup_pt_elem, shared_elem);
  enum page_src src = first->src;

  ASSERT(is_valid_store_list(sptes));

  clear_all_p_in_pt(sptes);

  if (src == SRC_RAM)
  {
    for(swap_idx_t idx = 0; idx < swap_size; ++idx)
    {
      if (!bitmap_test(used_map, idx))
      {
        bitmap_mark(used_map, idx);
        void* kpage = first->u.kpage;
        set_swap_info(sptes, idx, find_frame_entry(kpage)->rom_id);
        for (size_t i = 0; i < SECTORS_PER_PAGE; ++i)
        {
          block_write(swap_device, idx * SECTORS_PER_PAGE + i,
                                kpage + BLOCK_SECTOR_SIZE * i);
        }
        goto store_page_return;
      }
    }
    PANIC("out of swap space");
  }
  else if (src == SRC_M_FILE)
  {
    ASSERT(list_size(sptes) == 1);
    //no shared memory for file memory mapping case
    mapped_page* mapped_p = &first->u.m_page;
    file_write_at(mapped_p->f, first->userpage_addr, mapped_p->ofs, PGSIZE);
    first->u.m_page.kpage = NULL;
    first->src = SRC_FILE;
    // SRC_M_FILE and SRC_FILE uses the same union ATM,
    // so not changing the union for now.
    goto store_page_return;
  }
  else NOT_REACHED();

store_page_return:
  list_init(sptes);
  //clear the list without freeing sup table elem
  return;
}

void* swap_page(sup_pt_elem* spt_to_swap)
{
  ASSERT(spt_to_swap->src == SRC_SWAP);
  frame_table_entry* frame =
      find_frame_given_rom_id(spt_to_swap->u.swap_info.rom_id);

  void* page_available;

  if (frame == NULL)
  {//need swapping
    enum intr_level old = intr_disable();
    frame_table_entry*
        frame_to_be_swapped = find_page_to_evict();
    intr_set_level(old);

    ASSERT (!list_empty(&frame_to_be_swapped->u_page_sup));
    page_available = find_page_given_frame(frame_to_be_swapped);
    ASSERT (page_available > PHYS_BASE);
    //must be mapped into user space

    store_page(&frame_to_be_swapped->u_page_sup);
    load_page(spt_to_swap, page_available);
    list_push_back(&frame_to_be_swapped->u_page_sup, &spt_to_swap->shared_elem);
  }
  else
  {//just install that page
    page_available = find_page_given_frame(frame);
    bitmap_reset(used_map, spt_to_swap->u.swap_info.swap_idx);
    install_page(spt_to_swap->userpage_addr, page_available, false);
    //install ROM page
  }

  return page_available;
}
