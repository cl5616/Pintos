#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <list.h>
#include <hash.h>
#include "vm/types.h"
#include "vm/sup_pt.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
#define MAX_LEN_OF_BUFFER (128*31)
#define MAX_NUM_OF_ARGS 31
typedef struct _proc_arg
{
	int argc;
	char* arr_to_args[MAX_NUM_OF_ARGS];
	char args[MAX_LEN_OF_BUFFER];
}proc_arg;
//sizeof (proc_arg) == 4096, which occupies excacly one page

typedef struct _start_stack_frame
{
	void (*eip) (void);
	int argc;
	char **argv;
}start_stack_frame;
#define START_STACK_FRAME_LEN (sizeof(start_stack_frame))
#define PAGE_SIZE 0x1000

#define STDIN_FILE_NO 0
#define STDOUT_FILE_NO 1

#define EXEC_IF_PARENT_IS_WAITING(INSTRUCTIONS) \
	if (cur->parent->status == THREAD_BLOCKED &&/*prevent the main case*/\
	cur->parent->child_waiting == cur->tid)/*your parents are waiting for you*/\
	{\
    	ASSERT(cur->parent != cur);\
    	ASSERT(cur->status == THREAD_RUNNING);\
		INSTRUCTIONS\
	}

typedef struct _exit_info
{
	struct list_elem elem;
	struct thread* parent;
	tid_t tid;
	int exit_code;
	bool is_done;
}exit_info;

void vm_init(void);


extern struct list exit_info_list;
extern struct lock ft_spt_lock;
extern struct hash frame_table;

struct frame_table_entry* page_lookup(void* page);
sup_pt_elem* sup_page_lookup(const void* page);
bool install_page (const void *upage, void *kpage, bool writable);
uint32_t* find_entry(uint32_t* pd, const void* upage);
bool update_page_after_load (const void *upage, void *kpage, bool writable,
	sup_pt_elem* supt);
bool lazy_load(sup_pt_elem* supt);
void sup_action_free(struct hash_elem *e, void *aux);


#endif /* userprog/process.h */
