#include "executables.h"
#include <string.h>
#include "threads/malloc.h"
struct list executables;
struct lock exes_lock;

static
bool page_less (const struct hash_elem *a_,
	const struct hash_elem *b_, void *aux UNUSED)
{
  const ofs_to_rom_id* a = hash_entry (a_, ofs_to_rom_id, hash_elem);
  const ofs_to_rom_id* b = hash_entry (b_, ofs_to_rom_id, hash_elem);
  return a->upage < b->upage;
}


static
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const ofs_to_rom_id* ofs_to_id = hash_entry(p_,
																		ofs_to_rom_id, hash_elem);
	return hash_bytes(&ofs_to_id->upage,
											sizeof(ofs_to_id->upage));
}


executable* add_executable(const char* name)
{
	struct list_elem* e;
	executable* ret_exec;

	lock_acquire(&exes_lock);
	for (e = list_begin (&executables); e != list_end (&executables);
		e = list_next (e))
	{
		executable* exec = list_entry (e, executable, elem);
		// if the exec has already been opened before.
		if (strcmp(name, exec->name) == 0)
		{
			exec->counter++;
			ASSERT(exec->counter > 0);
			ret_exec = exec;
			goto add_exec_return;
		}
	}
	// if not been opened.
	ret_exec = malloc(sizeof(executable));
	ASSERT(ret_exec != NULL);
	ret_exec->counter = 1;
	strlcpy(ret_exec->name, name, FILE_NAME_BUF_LEN);
	bool success = hash_init(&ret_exec->rom_id_info, page_hash, page_less, NULL);
	ASSERT(success);
	list_push_back(&executables, &ret_exec->elem);

	add_exec_return:
	lock_release(&exes_lock);
	return ret_exec;
}

void remove_executable(const char* name)
{
	struct list_elem* e;
	lock_acquire(&exes_lock);

	for (e = list_begin (&executables); e != list_end (&executables);
		e = list_next (e))
	{
		executable* exec = list_entry (e, executable, elem);
		if (strcmp(name, exec->name) == 0)
		{
			ASSERT(exec->counter > 0);
			exec->counter--;
			if (exec->counter == 0)
			{
				list_remove(e);
				hash_destroy(&exec->rom_id_info, NULL);
				free(exec);
				lock_release(&exes_lock);
				return;
			}
		}
	}
	NOT_REACHED();
}

rom_id_t get_rom_id(executable* exec, void* upage)
{
	ASSERT(exec != NULL);
	lock_acquire(&exes_lock);

	ofs_to_rom_id ofs_to_id;
	ofs_to_id.upage = upage;
	struct hash_elem* e = hash_find(&exec->rom_id_info, &ofs_to_id.hash_elem);
	rom_id_t found_id = e != NULL
						? hash_entry(e, ofs_to_rom_id, hash_elem)->rom_id : 0;

	lock_release(&exes_lock);
	return found_id;
}

frame_table_entry* find_frame_given_rom_id(rom_id_t rom_id)
{
	if (rom_id == 0)
		return NULL;
	for (size_t i = 0; i < g_frame_table.num_of_frame; ++i)
	{
		frame_table_entry* entry = g_frame_table.frame_tab + i;
		if (entry->rom_id == rom_id)
			return entry;
	}
	return NULL;
}

bool insert_shared_rom(executable* exec, void* upage, rom_id_t rom_id)
{
	lock_acquire(&exes_lock);
	ofs_to_rom_id* new_shared_rom = malloc(sizeof(ofs_to_rom_id));
	new_shared_rom->upage = upage;
	new_shared_rom->rom_id = rom_id;
	struct hash_elem* elem = hash_insert(&exec->rom_id_info,
								&new_shared_rom->hash_elem);
  lock_release(&exes_lock);
  if (elem == NULL)
  {
  	return true;
  }
  else
  {
  	free(new_shared_rom);
  	return false;
  }
}
