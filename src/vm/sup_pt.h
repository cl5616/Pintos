#ifndef SUP_PT_H
#define SUP_PT_H

#include "vm/types.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "vm/types.h"
#include <hash.h>
#include <list.h>

#define MAPPINGS_NUM ((PGSIZE - sizeof(struct bitmap*)) \
						/ sizeof(mapping_elem))

enum page_src
{
	SRC_SWAP,
	SRC_RAM,
	SRC_FILE,
	SRC_M_FILE,
	SRC_LOAD
};

typedef struct _mapped_page
{
	void* kpage;			//for SRC_M_FILE
	struct file* f;
	int size;
	size_t ofs;
	size_t page_read_bytes;
}mapped_page;

struct load_info
{
	struct file* file;
	rom_id_t rom_id;
	off_t start_read;
	size_t page_read_bytes;
};

typedef struct _swap_info
{
	swap_idx_t swap_idx;
	rom_id_t rom_id;
}swap_info;

union sup_page_info
{
	swap_info swap_info;	// for SRC_SWAP.
	void* kpage;			// for SRC_RAM, cannot be used by SRC_M_FILE.
	mapped_page m_page;		// for SRC_FILE/SRC_M_FILE.
	struct load_info load_info;	// for SRC_LOAD.
	/*information for loading elf*/
};


typedef struct _sup_pt_elem
{
	const void* userpage_addr;
	struct hash_elem elem;
	enum page_src src;
	union sup_page_info u;
	uint32_t* pt_entry;
	struct list_elem shared_elem;
}sup_pt_elem;

typedef struct _mapping_elem
{
	struct file* f;
	int size;
	int mapping_idx;
	const void* upage;
	struct list_elem elem;
}mapping_elem;

// total size of a page.
typedef struct _mappings
{
	struct bitmap* free_map;
	mapping_elem mappings[MAPPINGS_NUM];
}mappings;

#endif
