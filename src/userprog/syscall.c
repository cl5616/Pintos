#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/exception.h"
#include "threads/malloc.h"
#include <bitmap.h>
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

static bool
examine_user_addr (const void* i)
{
	lock_acquire(&ft_spt_lock);
	const void* round_down = pg_round_down(i);
	frame_table_entry* ft;
	sup_pt_elem* supt = sup_page_lookup(round_down);
	if (supt == NULL)
	{
		lock_release(&ft_spt_lock);
		void* stack_kpage;
		if (is_stack_access(i))
		{
			void* user_esp = thread_current()->saved_esp;
			if (pg_round_down(user_esp - ESP_BOUNDARY) <= i)
			{//then it is indeed nessasery to grow stack
				stack_kpage = palloc_get_page(PAL_USER);
				ASSERT(stack_kpage != NULL);
				bool ret = install_page(round_down, stack_kpage, true);
				ASSERT(ret);
				ft = find_frame_entry(stack_kpage);
				lock_acquire(&ft_spt_lock);
				ASSERT(!ft->is_pinned);
				ft->is_pinned = true;
				lock_release(&ft_spt_lock);
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	else
	{
		switch (supt->src)
		{
			case SRC_RAM:
			ft = find_frame_entry(supt->u.kpage);
			ASSERT(!ft->is_pinned);
			ft->is_pinned = true;
			break;
			case SRC_SWAP:
			ft = find_frame_entry(swap_page(supt));
			ASSERT(!ft->is_pinned);
			ft->is_pinned = true;
			break;
			case SRC_LOAD:
			if (!lazy_load(supt))
			{
				lock_release(&ft_spt_lock);
				return false;
			}
			ft = find_frame_entry(supt->u.kpage);
			ASSERT(!ft->is_pinned);
			ft->is_pinned = true;
			break;
			case SRC_FILE:
			if (!lazy_load(supt))
			{
				lock_release(&ft_spt_lock);
				return false;
			}
			ft = find_frame_entry(supt->u.m_page.kpage);
			ASSERT(!ft->is_pinned);
			ft->is_pinned = true;
			break;
			case SRC_M_FILE:
			ft = find_frame_entry(supt->u.m_page.kpage);
			ASSERT(!ft->is_pinned);
			ft->is_pinned = true;
			break;
		}
	}
	lock_release(&ft_spt_lock);
	return true;
}


#define EXAMINE_BUF_READ \
if (!is_user_pointer_mapped_pin(buffer, length))\
{\
		exit(EXIT_ERROR);\
		NOT_REACHED();\
}

#define EXAMINE_BUF_WRITE \
if (!is_user_pointer_writable(buffer, length))\
{\
		exit(EXIT_ERROR);\
		NOT_REACHED();\
}

#define VM_DISPL_MASK 0xfff
#define FILE_NOT_EXIST (-1)   /* File not exist*/
#define INVALID_MMAP (-1)			/* Memory Mapping failed */
#define NOT_MAPPABLE (-3)
#define DEFAULT_FD (-2)		/* File created yet to be opened */
#define GET_PAGE_ADDR(p) ((void*)((uint32_t)(p)&(~(uint32_t)(VM_DISPL_MASK))))
//static struct file_info file_info[FILE_NUM];

struct lock file_sys_lock;

inline bool is_range_valid(const void* beg, const void* last_byte)
{
	if (last_byte < beg)
	{//overflow
		return false;
	}
	if (last_byte >= PHYS_BASE || beg >= PHYS_BASE)
	{
		return false;
	}
	return true;
}

static bool is_user_pointer_mapped_pin(const void* ptr, unsigned size)
{
	const char* last_byte = ptr + size - 1;
	if (!is_range_valid(ptr, last_byte))
		return false;
	if (!examine_user_addr(ptr))
	{
		return false;
	}
	ptr = ((uintptr_t)ptr & VM_DISPL_MASK) ? pg_round_up(ptr) : ptr + PGSIZE;
	last_byte = GET_PAGE_ADDR(last_byte);
	for (const char* i = ptr; i <= last_byte; i += PAGE_SIZE)
	{
		if (!examine_user_addr(i))
		{
			return false;
		}
	}
	return true;
}

static void unpin_pages(const void* ptr, unsigned size)
{
	const char* last_byte = ptr + size - 1;
	ASSERT(is_range_valid(ptr, last_byte));
	ptr = GET_PAGE_ADDR(ptr);
	last_byte = GET_PAGE_ADDR(last_byte);
	lock_acquire(&ft_spt_lock);
	for (const char* i = ptr; i <= last_byte; i += PAGE_SIZE)
	{
		sup_pt_elem* supt = sup_page_lookup(i);
		ASSERT(supt != NULL);
		void* kpage;
		switch(supt->src)
		{
			case SRC_RAM:
			kpage = supt->u.kpage;
			break;
			case SRC_M_FILE:
			kpage = supt->u.m_page.kpage;
			break;
			default:
			NOT_REACHED();
		}
		frame_table_entry* ft = find_frame_entry(kpage);
		ASSERT(ft->is_pinned);
		ft->is_pinned = false;
	}
	lock_release(&ft_spt_lock);
}

static bool
is_user_pointer_writable(void* ptr, unsigned size)
{
	const char* last_byte = ptr + size - 1;
	if (!is_range_valid(ptr, last_byte))
		return false;
	ptr = GET_PAGE_ADDR(ptr);
	last_byte = GET_PAGE_ADDR(last_byte);
	for (const char* i = ptr; i <= last_byte; i += PAGE_SIZE)
	{//utilize MMU to find unmapped page, if unmapped, fail
		asm volatile ("push %%ecx; movzbl %0, %%ecx;\
			movb %%cl,%0; pop %%ecx" : : "m" (*i));
	}
	return true;
}

static bool is_user_str_valid(const char* str)
{
	if (str == NULL)
		return false;
	size_t len = strlen(str);
	return is_range_valid((const void*)str, str + len);
}


static void syscall_handler (struct intr_frame *);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);//todo, pin down string
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
mapid_t mmap (int fd, void *addr);
void munmap(mapid_t );

static struct file_info*
getInfo (int fd)
{
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
		return NULL;
	struct file_info* file_info = thread_current()->fd_info;
	ASSERT(file_info != NULL);
	int file_info_index = thread_current()->file_info_index;
	for (int i = 0; i < file_info_index; i++)
	{
		if (file_info[i].file_descriptor == fd)
		{
			return &file_info[i];
		}
	}
	return NULL;
}

static int
insertFile (const char* name, struct file* f)
{
	struct thread* cur =  thread_current();
	struct file_info* file_info = cur->fd_info;
	ASSERT(file_info != NULL);
	for (int i = 0; i < cur->file_info_index; i++)
	{
		if (strcmp(file_info[i].name, name) == 0)
		{
			if (file_info[i].file_descriptor == DEFAULT_FD)
			{
				/* File not have been opened */
				file_info[i].file = f;
				file_info[i].file_descriptor = cur->descriptor_index++;
				return file_info[i].file_descriptor;
			}
			else
			{
				/* Reopen file */
				if (cur->file_info_index >= MAX_NUM_OF_FILES - 1)
					return -1;
				file_info[cur->file_info_index].size = file_info[i].size;
				strlcpy(file_info[cur->file_info_index].name, name, MAX_FILE_NAME_LEN);
				file_info[cur->file_info_index].file = f;
				file_info[cur->file_info_index].file_descriptor = cur->descriptor_index++;
				return file_info[cur->file_info_index++].file_descriptor;
			}
		}
	}
	cur->file_info_index++;
	if (cur->file_info_index >= MAX_NUM_OF_FILES)
		return -1;
	strlcpy(file_info[cur->file_info_index - 1].name, name, MAX_FILE_NAME_LEN);
	file_info[cur->file_info_index - 1].file_descriptor = cur->descriptor_index++;
	file_info[cur->file_info_index - 1].file = f;
	file_info[cur->file_info_index - 1].size = inode_length(file_get_inode(f));

	return file_info[cur->file_info_index - 1].file_descriptor;
}

static int
removeFD (int fd)
{
	struct thread* cur = thread_current();
	struct file_info* file_info = cur->fd_info;
	ASSERT(file_info != NULL);
	for (int i = 0; i < cur->file_info_index; i++)
	{
		if (file_info[i].file_descriptor == fd)
		{
			file_close(file_info[i].file);
			for (int j = i; j < cur->file_info_index - 1; j++)
			{
				file_info[j] = file_info[j + 1];
			}
			cur->file_info_index--;
			return 0;
		}
	}
	return FILE_NOT_EXIST;
}

//free all the resources when exit the process
static void
clear_all_fds(void)
{
	struct thread* cur = thread_current();
	struct file_info* file_info = cur->fd_info;
	for (int i = 0; i < cur->file_info_index; i++)
	{
		file_close(file_info[i].file);
	}
}

static int
removeFile (const char* name)
{
	struct thread* cur = thread_current();
	struct file_info* file_info = cur->fd_info;
	ASSERT(file_info != NULL);
	for (int i = 0; i < cur->file_info_index; i++)
	{
		if (strcmp(file_info[i].name, name) == 0)
		{
			file_info[i].name[0] = '\0';
			return 0;
		}
	}
	return FILE_NOT_EXIST;
}

inline arg_t access_user_arg_t(arg_t* addr)
{
	if ((void*)addr > PHYS_BASE - sizeof(arg_t))
	{//if addr will access anything in kernel, terminate with -1
		exit(EXIT_ERROR);
	}
	return *addr;//if unmapped, this will interrupt to page_fault
}

inline arg_t syscall_num(struct intr_frame* f)
{
	return access_user_arg_t((arg_t*)f->esp);
}

#define GET_USER_STACK(FRAME,TYPE,IDX) 		\
	((TYPE)									\
	(access_user_arg_t					\
			(((arg_t*)(FRAME)->esp)+1+(IDX))	\
	))

void
syscall_init (void)
{
  intr_register_int (SYSCALL_VEC, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&file_sys_lock);

  //intr_register_int ();
  //todo, register interrupt, and terminate user program when appropriate
}

static void
syscall_handler (struct intr_frame *f)
{
	ASSERT(intr_get_level() == INTR_ON);
	thread_current()->saved_esp = f->esp;
	switch (syscall_num(f))
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(GET_USER_STACK(f, int, 0));
		break;
	case SYS_EXEC:
		f->eax = exec(GET_USER_STACK(f, const char*, 0));
		break;
	case SYS_WAIT:
		f->eax = wait(GET_USER_STACK(f, pid_t, 0));
		break;
	case SYS_CREATE:
		f->eax = create(GET_USER_STACK(f, const char*, 0),
			GET_USER_STACK(f, unsigned, 1));
		break;
	case SYS_REMOVE:
		f->eax = remove(GET_USER_STACK(f, const char*, 0));
		break;
	case SYS_OPEN:
		f->eax = open(GET_USER_STACK(f, const char *, 0));
		break;
	case SYS_FILESIZE:
		f->eax = filesize(GET_USER_STACK(f, int, 0));
		break;
	case SYS_READ:
		f->eax = read(GET_USER_STACK(f, int, 0),
			GET_USER_STACK(f, void*, 1),
			GET_USER_STACK(f, unsigned, 2));
		break;
	case SYS_WRITE:
		f->eax = write(GET_USER_STACK(f, int, 0),
			GET_USER_STACK(f, const void*, 1),
			GET_USER_STACK(f, unsigned, 2));
		break;
	case SYS_SEEK:
		seek(GET_USER_STACK(f, int, 0),
			GET_USER_STACK(f, unsigned, 1));
		break;
	case SYS_TELL:
		f->eax = tell(GET_USER_STACK(f, int, 0));
		break;
	case SYS_CLOSE:
		close(GET_USER_STACK(f, int, 0));
		break;
	case SYS_MMAP:
		f->eax = mmap(GET_USER_STACK(f, int, 0),
					GET_USER_STACK(f, void*, 1));
		break;
	case SYS_MUNMAP:
		munmap(GET_USER_STACK(f, mapid_t, 0));
		break;
	default:
		NOT_REACHED();
		break;
	}
}

//todo
void halt (void)
{
	shutdown_power_off();
	NOT_REACHED ();
}
void exit (int status)
{
	ASSERT(intr_get_level() == INTR_ON);
	struct thread* cur = thread_current();
	mappings* map_info = cur->map_info;

	for (size_t i = 0; i < bitmap_size(map_info->free_map); ++i)
	{
		if (bitmap_test(map_info->free_map, i))
		{
			munmap(i);
			file_close(map_info->mappings[i].f);
		}
	}
	bitmap_destroy(map_info->free_map);

	//exit will only be called after entering r3
	//so read will not cause race cond
	proc_arg* args = cur->argPage;
	printf ("%s: exit(%d)\n", args->arr_to_args[0], status);
	hash_clear (&cur->sup_page_table, sup_action_free);
	clear_all_fds();
	palloc_free_page(cur->fd_info);
	palloc_free_page(cur->map_info);
	//trust the address in args, so it can not be modified by user program
	enum intr_level old = intr_disable();
	struct list_elem *e;
	for (e = list_begin (&exit_info_list); e != list_end (&exit_info_list);
			 e = list_next (e))
	{
		exit_info *f = list_entry (e, exit_info, elem);
		if (f->tid == cur->tid)
		{
			f->exit_code = status;
		}
	}
	//no race cond, since this must execute before accessing exit_code
	intr_set_level(old);
	thread_exit();
	NOT_REACHED ();
}

pid_t exec (const char *file)
{
	return (pid_t)process_execute(file);
}
int wait (pid_t pid)
{
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
	if (file == NULL || file[0] == '\0') {
		exit(EXIT_ERROR);
		NOT_REACHED();
		return false;
	}

	lock_acquire(&file_sys_lock);

	bool ret = filesys_create(file, initial_size);
	lock_release(&file_sys_lock);

	return ret;
}

bool remove (const char *file)
{
	lock_acquire(&file_sys_lock);
	removeFile(file);
	bool ret = filesys_remove(file);
	lock_release(&file_sys_lock);

	return ret;
}
int open (const char *file)
{
	if (!is_user_str_valid(file))
	{
		exit(EXIT_ERROR);
		NOT_REACHED();
	}
	if (file == NULL || file[0] == '\0')
		return FILE_NOT_EXIST;
	lock_acquire(&file_sys_lock);
	struct file* open_file = filesys_open(file);
	if (open_file == NULL)
	{
		lock_release(&file_sys_lock);
		return FILE_NOT_EXIST;
	}
	int ret = insertFile(file, open_file);
	lock_release(&file_sys_lock);
	return ret;
}

int filesize (int fd)
{
	return getInfo(fd) == NULL ? FILE_NOT_EXIST : getInfo(fd) -> size;
}

int read (int fd, void *buffer, unsigned length)
{
	if (length == 0)
		return 0;

	EXAMINE_BUF_READ;
	EXAMINE_BUF_WRITE;


	if (fd == STDIN_FILE_NO)
	{
		for (unsigned i = 0; i < length; ++i)
		{
			((uint8_t*)buffer)[i] = input_getc();
		}
		unpin_pages(buffer, length);
		return length;
	}

	lock_acquire(&file_sys_lock);
	struct file_info* fi = getInfo(fd);
	if (fi == NULL)
	{
		lock_release(&file_sys_lock);
		exit(EXIT_ERROR);
		NOT_REACHED();
	}
	struct file* file = fi -> file;
	if (file == NULL)
	{
		lock_release(&file_sys_lock);
		exit(EXIT_ERROR);
		NOT_REACHED();
	}//todo integer overflow
	size_t remain_size = fi->size - file_tell(file);
	length = remain_size > length ? length : remain_size;

	int read_b = file_read(file, buffer, length);

	lock_release(&file_sys_lock);
	unpin_pages(buffer, length);
	return read_b;
}

#define MAX_WRITE_SIZE 256

int write (int fd, const void *buffer, unsigned length)
{
	if (length == 0)
		return 0;

	EXAMINE_BUF_READ;

	int write_b = 0;

	if (fd == STDOUT_FILE_NO) {
		if (length < MAX_WRITE_SIZE) {
			putbuf(buffer, length);
			write_b = length;
		}
		goto ret;
	}
	if (fd == STDIN_FILE_NO) {
		goto ret;
	}

	lock_acquire(&file_sys_lock);

	struct file_info* fi = getInfo(fd);
	if (fi == NULL)
	{
		lock_release(&file_sys_lock);
		exit(EXIT_ERROR);
		NOT_REACHED();
	}
	struct file* f = fi -> file;
	if (f == NULL) {
		lock_release(&file_sys_lock);
		exit(EXIT_ERROR);
		NOT_REACHED();
	}
	size_t remain_size = fi->size - file_tell(f);
	length = remain_size > length ? length : remain_size;

	write_b = file_write(f, buffer, length);
	/*switch (fd)
	{
		case STDIN_FILE_NO:
		break;
		case STDOUT_FILE_NO:
		if (length < MAX_WRITE_SIZE) {
			putbuf(buffer, length);
			write_b = length;
		}
		break;
		case STDERR_FILE_NO:
		break;
		default:
		break;
	}*/
	lock_release(&file_sys_lock);

	ret:
	unpin_pages(buffer, length);

	return write_b;
}

void seek (int fd, unsigned position)
{
	struct file_info* fi = getInfo(fd);
	if (fi == NULL)
	{
		exit(EXIT_ERROR);
		NOT_REACHED();
	}
	ASSERT(fi->size >= 0);
	size_t size = (size_t)fi->size;
	//todo integer overflow
	file_seek(fi->file, (size > position) ? position : size);
}
unsigned tell (int fd)
{
	return file_tell(getInfo(fd)->file);
}
void close (int fd)
{
	removeFD(fd);
}

mapid_t mmap (int fd, void *addr)
{
	if (addr == 0)
		return INVALID_MMAP;

	// I/O console, unmapped.
	if (fd == 0 || fd == 1)
		return NOT_MAPPABLE;

	struct file_info* fi = getInfo(fd);
	if (fi == NULL)
	{
		exit(EXIT_ERROR);
		NOT_REACHED();
	}

	ASSERT(fi->size >= 0);
	size_t f_size = (size_t)fi->size;
	if (f_size == 0)
		return INVALID_MMAP;

	// if the 'addr' is not page-aligned
	if (((uintptr_t) addr & VM_DISPL_MASK) != 0)
		return INVALID_MMAP;

	int m_page_num = f_size / PGSIZE;
	// if file's length is not a multiple of PGSIZE.
	if (f_size % PGSIZE != 0)
		m_page_num++;

	lock_acquire(&ft_spt_lock);
	for (int i = 0; i < m_page_num; ++i)
	{
		if (sup_page_lookup(addr + i * PGSIZE) != NULL || 
			(addr + i * PGSIZE) >= LOWEST_STACK_TOP)
		{
			lock_release(&ft_spt_lock);
			return INVALID_MMAP;
		}
	}

	struct thread* t = thread_current();
	struct file* reopened = file_reopen(fi->file);

	for (int i = 0; i < m_page_num; ++i)
	{
		void* upage = addr + i * PGSIZE;
		sup_pt_elem* new_spt = malloc(sizeof(sup_pt_elem));
		if (new_spt == NULL)
		{
			lock_release(&ft_spt_lock);
			return INVALID_MMAP;
		}
		new_spt->userpage_addr = upage;
		new_spt->src = SRC_FILE;
		// one page of possibly many pages in mmap of the file.
		// struct consists of 'file_info' and 'offset' to the position in file.
		mapped_page* map = &new_spt->u.m_page;
		map->f = reopened;
		map->size = f_size;
		map->ofs = i * PGSIZE;
		map->page_read_bytes = map->ofs + PGSIZE > f_size ?
									f_size - map->ofs : PGSIZE;
		//new_spt->pt_entry = find_entry(t->pagedir, upage);
		hash_insert(&t->sup_page_table, &new_spt->elem);
	}
	lock_release(&ft_spt_lock);

	mapid_t idx_tmp = bitmap_scan_and_flip(t->map_info->free_map, 0, 1, false);
	ASSERT(idx_tmp >= 0);
	// get the mapping_elem at the pre_allocated index 'idx_tmp'.
	mapping_elem* new_mapping = t->map_info->mappings + idx_tmp;
	new_mapping->f = reopened;
	new_mapping->size = f_size;
	new_mapping->upage = addr;

	// ^^					 ^^
	// ** REMEMBER **
	//		zero out the 'stick-out' bytes if the size is not multiple of PGSIZE.
	// **          **
	return idx_tmp;
}

void munmap (mapid_t id)
{
	struct thread* t = thread_current();
	mappings* map_info = t->map_info;
	// testing 'id' was a valid mapping in current thread.
	ASSERT(bitmap_test(map_info->free_map, id));

	mapping_elem* mapping = map_info->mappings + id;
	int f_size = mapping->size;
	int m_page_num = f_size / PGSIZE;
	// if file's length is not a multiple of PGSIZE.
	if (f_size % PGSIZE != 0)
		m_page_num++;

	const void* addr = mapping->upage;
	lock_acquire(&ft_spt_lock);

	for (int i = 0; i < m_page_num; ++i)
	{
		const void* unmap_page = addr + i * PGSIZE;
		sup_pt_elem* new_spt = sup_page_lookup(unmap_page);
		ASSERT(new_spt != NULL);

		// file written, needs to be written back.
		if (pagedir_is_dirty(t->pagedir, unmap_page))
		{
			size_t offset = new_spt->u.m_page.ofs;
			file_write_at(mapping->f, unmap_page, PGSIZE, offset);
		}

		if (new_spt->src == SRC_M_FILE)
		{
			lock_release(&ft_spt_lock);
			palloc_free_page(new_spt->u.m_page.kpage);
			lock_acquire(&ft_spt_lock);
		}

		pagedir_clear_page(t->pagedir, unmap_page);
		hash_delete(&t->sup_page_table, &new_spt->elem);

		free(new_spt);
	}
	lock_release(&ft_spt_lock);
	// reset the free_map of that mappings.
	bitmap_reset(map_info->free_map, id);
}
