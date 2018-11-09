#ifndef SWAP_H
#define SWAP_H
#include <inttypes.h>
#include <list.h>
#include "userprog/process.h"
#include "vm/types.h"

#define SECTORS_PER_PAGE 8

typedef void (*sptes_proc_t)(sup_pt_elem*, uint32_t);

void load_page(sup_pt_elem* spte, void* kpage);
void store_page(struct list* sptes);
void swap_slot_init(void);
void* swap_page(sup_pt_elem* supt_to_swap);
void process_sptes(struct list* sptes, sptes_proc_t func, uint32_t aux);

#endif
