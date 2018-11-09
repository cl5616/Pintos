#ifndef EXECUTABLES_H
#define EXECUTABLES_H
#include <list.h>
#include <hash.h>
#include "vm/frame.h"
extern struct list executables;
#define FILE_NAME_BUF_LEN 16
//max file name len is 14, take 16 as buf len

typedef struct _ofs_to_rom_id
{
	void* upage;			// user page.
	rom_id_t rom_id; 	// id of read-only page.
	struct hash_elem hash_elem;
}ofs_to_rom_id;

typedef struct _executable
{
	uint32_t counter;
	struct list_elem elem;
	//rom_id_t* off_to_rom_id;
	char name[FILE_NAME_BUF_LEN];
	struct hash rom_id_info;
}executable;

executable* add_executable(const char* name);
void remove_executable(const char* name);

//upage is user page virtual address, map to rom_id_t
//return 0 if it is not a rom
rom_id_t get_rom_id(executable* exec, void* upage);
frame_table_entry* find_frame_given_rom_id(rom_id_t rom_id);
bool insert_shared_rom(executable* exec, void* upage, rom_id_t rom_id);

extern struct lock exes_lock;

#endif
