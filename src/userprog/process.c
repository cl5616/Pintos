#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "threads/pte.h"
#include "vm/swap.h"
#include "vm/sup_pt.h"
#include "vm/frame.h"
#include "vm/sup_pt.h"
#include <bitmap.h>
#include <limits.h>
#include "vm/executables.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

unsigned page_hash(const struct hash_elem* elem, void* aux UNUSED);
bool page_less(const struct hash_elem* a_, const struct hash_elem* b_,
                void *aux UNUSED);

#define ROM_ID_LIMIT UINT_MAX
static rom_id_t next_rom_id;
static struct lock rom_id_lock;
static inline
rom_id_t allocate_rom_id(void)
{
  lock_acquire(&rom_id_lock);
  if (next_rom_id == ROM_ID_LIMIT)
  {
    PANIC("running out of rom id");
  }
  rom_id_t ret = next_rom_id++;
  lock_release(&rom_id_lock);
  return ret;
}

struct list exit_info_list;
struct lock ft_spt_lock;
struct hash frame_table;

void vm_init(void)
{
  lock_init(&ft_spt_lock);
  list_init(&executables);
  lock_init(&exes_lock);
  lock_init(&rom_id_lock);
  next_rom_id = 1;
}


#define GOTO_FINISH_FOR_FAIL \
  if (!success)\
    {goto finish;}


static unsigned
sup_page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const sup_pt_elem *p = hash_entry (p_, sup_pt_elem, elem);
  return hash_bytes(&p->userpage_addr, sizeof(p->userpage_addr));
}

static bool
sup_page_less (const struct hash_elem *a_, const struct hash_elem *b_,
          void *aux UNUSED)
{
  const sup_pt_elem *a = hash_entry (a_, sup_pt_elem, elem);
  const sup_pt_elem *b = hash_entry (b_, sup_pt_elem, elem);
  return a->userpage_addr < b->userpage_addr;
}

void
sup_action_free(struct hash_elem *e, void *aux UNUSED)
{
  sup_pt_elem* elem = hash_entry (e, sup_pt_elem, elem);
  switch (elem->src)
  {
    case SRC_M_FILE:
    case SRC_RAM:
      list_remove(&elem->shared_elem);
      break;
    case SRC_LOAD:
      file_close(elem->u.load_info.file);
      break;
    default:
      break;
  }
  free(elem);
}

sup_pt_elem* sup_page_lookup(const void* page) {
  struct thread* cur = thread_current();
  struct hash sup_hash = cur->sup_page_table;
  sup_pt_elem p;
  struct hash_elem* e;
  p.userpage_addr = page;
  e = hash_find(&sup_hash, &p.elem);
  return e != NULL ? hash_entry(e, sup_pt_elem, elem) : NULL;
}

static bool
parse_args(proc_arg* page, const char* file_name)
{
  ASSERT(sizeof(proc_arg) == PAGE_SIZE);
  ASSERT((((uint32_t)(page)) & 0xfff) == 0);
  //must be aligned

  proc_arg* args = page;

  size_t len = strlcpy(args->args, file_name, sizeof(args->args));
  if (len >= sizeof(args->args))
    return false;
  int argIdx;
  if (args->args[0] != ' ')
  {//prevent begin with space
    args->arr_to_args[0] = args->args;
    argIdx = 1;
  }
  else
  {
    argIdx = 0;
  }
  for (char* p = args->args; *p; p++)
  {
    if (*p == ' ')
    {
      do
      {
        *p = '\0';
        p++;
      }while(*p == ' ');
      //prevent multiple args
      if (*p)
      {//prevent ending with space
        args->arr_to_args[argIdx] = p;
        argIdx++;
      }
      else
      {
        break;
      }
    }
  }
  args->argc = argIdx;
  return true;
}

/*
pre: args_u and args_k must be mapped to same physical address
change argv from kernel address to user address
*/
static void
validate_argv(proc_arg* args_u, proc_arg* args_k)
{
  for (int i = 0; i < args_u->argc; ++i)
  {
    args_k->arr_to_args[i] = args_u->args +
      (args_u->arr_to_args[i] - args_k->args);
  }
}



/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created.

   This function is called when initializing OS, which is r0
   */

tid_t
process_execute (const char *file_name)
{
  proc_arg *fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (PAL_USER);
  //fn_copy = falloc();
  if (fn_copy == NULL)
    return TID_ERROR;
  if (!parse_args(fn_copy, file_name))
  {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_copy->arr_to_args[0], //idx 0 is file name
    PRI_DEFAULT, start_process, fn_copy);
  enum intr_level old = intr_disable();
  if (tid == TID_ERROR)
  {
    intr_set_level(old);
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  thread_block();
  intr_set_level(old);
  if (thread_current()->exit_code == EXIT_ERROR)
  //this access must be after assignment of exit_code
  //so no race cond
  {
    tid = TID_ERROR;
    thread_current()->exit_code = EXIT_SUCCESS;
  }
  return tid;
}
/*
find VA of the page that has not been mapped to any PA
put addr of VA into page_ret
return false if there is no VA available
*/
#define USER_PAGE_START ((void*)0x00001000)
static bool
find_free_user_page(void** page_ret)
{
  for (void* p = USER_PAGE_START; is_user_vaddr(p); p += PAGE_SIZE)
  {
    if (pagedir_get_page(thread_current()->pagedir, p) == NULL)
    {
      *page_ret = p;
      return true;
    }
  }
  return false;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  thread_yield();
  bool if_map_to_user_success = false;
  proc_arg* args = args_;
  struct thread* cur = thread_current();

  cur->descriptor_index = 2;
  char *file_name = args->arr_to_args[0];
  struct intr_frame if_;
  bool success;

  success = hash_init (&cur->sup_page_table,
        sup_page_hash, sup_page_less, NULL);
  GOTO_FINISH_FOR_FAIL;

  cur->map_info = palloc_get_page(0);
  ASSERT(sizeof(mappings) <= PGSIZE);

  cur->map_info->free_map = bitmap_create(MAPPINGS_NUM);

  lock_acquire(&file_sys_lock);
  cur->this_file = filesys_open(args->arr_to_args[0]);
  if (cur->this_file == NULL)
  {
    lock_release(&file_sys_lock);
    success = false;
    goto finish;
  }
  file_deny_write(cur->this_file);
  lock_release(&file_sys_lock);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  //r3 selector
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  //load ELF into memory
  GOTO_FINISH_FOR_FAIL;

  void* free_user_page;
  success = find_free_user_page(&free_user_page);
  GOTO_FINISH_FOR_FAIL;

  success = install_page(free_user_page, args, false);
  if (success) if_map_to_user_success = true;
  GOTO_FINISH_FOR_FAIL;
  cur->argPage = free_user_page;

  start_stack_frame* ssf = if_.esp;
  ssf->argc = args->argc;
  proc_arg* args_user = free_user_page;
  validate_argv(args_user, args);
  ssf->argv = args_user->arr_to_args;

  cur->fd_info = palloc_get_page(0);
  //cur->fd_info = falloc();
  if (cur->fd_info == NULL)
  {
    success = false;
    goto finish;
  }
finish:
  if (!success)
  {
    cur->parent->exit_code = EXIT_ERROR;
    if (!if_map_to_user_success)
      palloc_free_page (args);
      //if not installed to user, we need to free this manually
    thread_unblock(cur->parent);
    thread_exit ();
  }
  thread_unblock(cur->parent);
  //assigned in thread_create, so will not be executed untill being assigned
  //in future this will not be modified, so no race cond
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  //mock a return to switch from r0 to r3
  NOT_REACHED ();
}

static exit_info*
tid_to_exit_info(tid_t tid)
{
  ASSERT (intr_get_level() == INTR_OFF);
  exit_info* ret = NULL;
  struct list_elem* e;
  for (e = list_begin (&exit_info_list); e != list_end (&exit_info_list);
     e = list_next (e))
  {
    exit_info *t = list_entry (e, exit_info, elem);
    if (t->tid == tid)
    {
      ret = t;
      break;
    }
  }
  return ret;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */



int
process_wait (tid_t child_tid)
{
  int ret;
  enum intr_level old = intr_disable();
  struct thread* cur = thread_current();
  exit_info* child = tid_to_exit_info(child_tid);
  if (child == NULL || child->parent != cur)
  {
    intr_set_level(old);
    return -1;//when call 2nd time or invalid tid, child is NULL
  }
  if (!child->is_done)
  {
    cur->child_waiting = child_tid;
    thread_block();
  }

  ret = child->exit_code;
  list_remove(&child->elem);
  //this access must be after assignment of exit_code in thread_exit() too
  //so no race cond
  cur->child_waiting = TID_ERROR;
  intr_set_level(old);
  free(child);//free child out of interrupt disable
  return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */

      /* All mappings are implicitly unmapped when a process exits. */


      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  if (cur->this_file != NULL)
  {
    lock_acquire(&file_sys_lock);
    file_allow_write(cur->this_file);
    file_close(cur->this_file);
    lock_release(&file_sys_lock);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();



  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (executable* exe, struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  executable* exe = add_executable(file_name);
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (exe, file, file_page,
                                (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  if (!success)
    remove_executable(file_name);
  return success;
}

/* load() helpers. */


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

static inline
sup_pt_elem* new_load_supt_elem(const void* upage, struct file* file,
          rom_id_t rom_id, off_t read_cursor, size_t page_read_bytes)
{
  sup_pt_elem* new_spt = malloc(sizeof(sup_pt_elem));
  new_spt->userpage_addr = upage;
  struct load_info* load_info = &new_spt->u.load_info;
  load_info->file = file_reopen(file);
  load_info->rom_id = rom_id;
  load_info->start_read = read_cursor;
  load_info->page_read_bytes = page_read_bytes;
  new_spt->src = SRC_LOAD;
  return new_spt;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (executable* exe, struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread *t = thread_current ();


  file_seek (file, ofs);
  off_t read_cursor = ofs;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      rom_id_t rom_id = get_rom_id(exe, upage);
      lock_acquire(&ft_spt_lock);
      if (rom_id > 0)
      {//the rom is already loaded/inswap/lazy, must be a ROM
        ASSERT(!writable);
        frame_table_entry* fte = find_frame_given_rom_id(rom_id);
        if (fte == NULL)
        {//rom in swap or lazy load
           sup_pt_elem* new_spt = new_load_supt_elem(upage,
            file, rom_id, read_cursor, page_read_bytes);
           struct hash_elem* tmp = hash_insert(&t->sup_page_table, &new_spt->elem);
           ASSERT(tmp == NULL);
        }
        else
        {//rom loaded
          install_page(upage, find_page_given_frame(fte), false);
        }
      }
      else
      {
        rom_id_t rom_id;
        if (writable)
        {
          rom_id = 0;
        }
        else
        {
          rom_id = allocate_rom_id();
          insert_shared_rom(exe, upage, rom_id);
        }
        sup_pt_elem* new_spt = new_load_supt_elem(upage,
            file, rom_id, read_cursor, page_read_bytes);
        struct hash_elem* tmp = hash_insert(&t->sup_page_table, &new_spt->elem);
        ASSERT(tmp == NULL);
      }
      lock_release(&ft_spt_lock);


      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      read_cursor += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
//called in load(), which load ELF
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE - START_STACK_FRAME_LEN;
      else
        palloc_free_page (kpage);
    }
  return success;
}

uint32_t* find_entry(uint32_t* pd, const void* upage)
{
  ASSERT(((uint32_t)upage & 0xfff) == 0);
  ASSERT(upage < PHYS_BASE);

  uint32_t pte = pd[pd_no(upage)];
  ASSERT(pte & PTE_P);
  uint32_t* pt = ptov(entry_to_addr(pte));

  uint32_t* ret = &pt[pt_no(upage)];
  ASSERT(*ret & PTE_P);
  return ret;
}


/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (const void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  bool if_lock = !lock_held_by_current_thread(&ft_spt_lock);


  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool ret = (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
  if (ret)
  {
    if (if_lock) lock_acquire(&ft_spt_lock);
    sup_pt_elem* new_spt = sup_page_lookup(upage);
    if (new_spt == NULL)
    {
      // if not shared
      new_spt = malloc(sizeof(sup_pt_elem));
      new_spt->userpage_addr = upage;
      new_spt->pt_entry = find_entry(t->pagedir, upage);
      struct hash_elem* tmp = hash_insert(&t->sup_page_table, &new_spt->elem);
      ASSERT(tmp == NULL);
    }
    new_spt->src = SRC_RAM;
    new_spt->u.kpage = kpage;


    //update sup table recorded in frame
    frame_table_entry* frame = find_frame_entry(kpage);
    ASSERT(frame->is_allocated);
    //is can already be installed, but allocated

    list_push_back(&frame->u_page_sup, &new_spt->shared_elem);

    frame->is_pinned = false;
    if (if_lock) lock_release(&ft_spt_lock);
  }
  return ret;
}

bool
update_page_after_load (const void *upage, void *kpage, bool writable,
  sup_pt_elem* supt)
{
  ASSERT(supt->src == SRC_LOAD || supt->src == SRC_FILE);
  struct thread *cur = thread_current ();

  bool ret = (pagedir_get_page (cur->pagedir, upage) == NULL
          && pagedir_set_page (cur->pagedir, upage, kpage, writable));
  if (ret)
  {
    if (supt->src == SRC_LOAD)
    {
      supt->src = SRC_RAM;
      supt->u.kpage = kpage;
    }
    else if (supt->src == SRC_FILE)
    {
      supt->src = SRC_M_FILE;
      supt->u.m_page.kpage = kpage;
    }
    else
      NOT_REACHED();
    supt->pt_entry = find_entry(cur->pagedir, upage);
    frame_table_entry* frame = find_frame_entry(kpage);
    ASSERT(list_empty(&frame->u_page_sup));
    ASSERT(frame->is_allocated);
    list_push_back(&frame->u_page_sup, &supt->shared_elem);
  }
  return ret;
}

static bool
load_memory_mapping(const void *upage, void* kpage, bool writable,
  sup_pt_elem* supt)
{
  ASSERT(supt->src == SRC_FILE);

  struct thread *cur = thread_current ();

  bool ret = (pagedir_get_page (cur->pagedir, upage) == NULL
          && pagedir_set_page (cur->pagedir, upage, kpage, writable));
  if (ret)
  {
    supt->src = SRC_M_FILE;
    supt->u.m_page.kpage = kpage;
    frame_table_entry* frame = find_frame_entry(kpage);
    ASSERT(list_empty(&frame->u_page_sup));
    ASSERT(frame->is_allocated);
    list_push_back(&frame->u_page_sup, &supt->shared_elem);
  }
  return ret;
}

bool lazy_load(sup_pt_elem* supt)
{
  ASSERT(lock_held_by_current_thread(&ft_spt_lock));

  struct file* file;
  size_t bytes_read;
  size_t ofs;
  bool writable;
  enum palloc_flags flag;
  switch (supt->src)
  {
    case SRC_LOAD:
      file = supt->u.load_info.file;
      bytes_read = supt->u.load_info.page_read_bytes;
      ofs = supt->u.load_info.start_read;
      writable = supt->u.load_info.rom_id == 0;
      flag = PAL_USER;
      break;
    case SRC_FILE:
      file = supt->u.m_page.f;
      bytes_read = supt->u.m_page.page_read_bytes;
      ofs = supt->u.m_page.ofs;
      writable = true;
      flag = PAL_ZERO | PAL_USER;
      break;
    default:
      NOT_REACHED();
  }
  const uint8_t* upage = supt->userpage_addr;
  size_t bytes_zero = PGSIZE - bytes_read;

  /* Get a page of memory. */
  lock_release(&ft_spt_lock);
  uint8_t *kpage = palloc_get_page(flag);
  if (kpage == NULL)
    return false;

  lock_acquire(&ft_spt_lock);

  if (supt->src == SRC_LOAD)
  {
    rom_id_t id = supt->u.load_info.rom_id;
    if (find_frame_given_rom_id(id) != NULL)
    {
      install_page(supt->userpage_addr, kpage, writable);
      return true;
    }
  }

  if (file_read_at(
        file, kpage, bytes_read, ofs) != (int) bytes_read)
  {
    lock_release(&ft_spt_lock);
    palloc_free_page(kpage);
    return false;
  }

  memset(kpage + bytes_read, 0, bytes_zero);

  // install the page.
  switch (supt->src)
  {
    case SRC_LOAD:
      file_close(file);
      if (!update_page_after_load(upage, kpage, writable, supt))
      {
        lock_release(&ft_spt_lock);
        palloc_free_page(kpage);
        return false;
      }
      break;
    case SRC_FILE:
      if (!load_memory_mapping(upage, kpage, writable, supt))
      {
        lock_release(&ft_spt_lock);
        palloc_free_page(kpage);
        return false;
      }
      break;
    default:
      NOT_REACHED();
  }

  return true;
}

void falloc_free_frame(void* page) {
  enum intr_level old = intr_disable();
  frame_table_entry* f_entry = find_frame_entry(page);
  memset(f_entry, 0, sizeof(frame_table_entry));
  list_init(&f_entry->u_page_sup);
  //clear everything
  intr_set_level(old);
}
