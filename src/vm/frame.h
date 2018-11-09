
#ifndef FRAME_H
#define FRAME_H
#include <stdint.h>
#include <list.h>
#include "vm/sup_pt.h"
#include "vm/types.h"

struct thread;
void update_freshness(struct thread* t);

typedef struct _frame_table_entry {
	//void* page;
	int64_t freshness;
	//0 if no user page being mapped
	struct list u_page_sup;
	bool is_allocated;
	bool is_pinned;
	rom_id_t rom_id;				//0 if not ROM, positive if ROM
}frame_table_entry;


typedef struct _frame_table
{
	frame_table_entry* frame_tab;
	size_t num_of_frame;
	uint8_t* user_page_start;
}frame_table_info;

void falloc_free_frame(void* page);
frame_table_entry* find_page_to_evict(void);
frame_table_entry* find_frame_entry(void* kpage_user);
void* find_page_given_frame(frame_table_entry* entry);

extern frame_table_info g_frame_table;

#endif
