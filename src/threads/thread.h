#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <hash.h>
#include "devices/float.h"
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

#define PRI_NUM (PRI_MAX+1)             /* Number of priorities*/
#define PRIORITY_INVALID (-1)
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mreturn idle_thread;utually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

typedef struct _proc_arg proc_arg;
typedef struct _mappings mappings;
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /*used for timer_sleep, only useful when thread is sleeping*/

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    proc_arg* argPage;    /* Kernel page to store argument, only used for process thread*/
    struct thread* parent;     /* The thread that creates it, can be itself for main*/
    tid_t child_waiting;
    /*when thread is waiting in process_wait, it is the thread it is waiting for
      or else it is TID_ERROR*/
    int exit_code; /*when the thread it waits terminates, put exit code here*/
    /*or when creating process, recieve error code if initialization fails*/
    struct file_info* fd_info; /*page to store array of fd_info(file descriptor it opened*/
    struct file* this_file; /*the file file struct of file of current process*/
    int descriptor_index; /* Used to manage fd system, next fd to be allocated*/
    int file_info_index; /* number of current fds*/
#endif

#ifdef VM
    struct hash sup_page_table; /*only useful for process*/
    void* stack_top;  /*r3 stack top, must be page aligned*/
    void* saved_esp; /*save esp for invalid access in kernel*/
    mappings* map_info; /* store all memory mapping files */
#endif

    struct list_elem sleep_elem; /*all threads called timer_sleep*/
    int64_t end_time; /*The time when the thread needs unblocked*/

    /* For Priority donation. */
    int base_priority;

    /* For Advanced scheduling. */
    float_t recent_cpu;                 /* For Advanced schedule*/
    int nice;                           /* Nice value*/
    struct list locks;
    struct thread* lock_holder;         /*used when being blocked*/

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;
/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
extern struct list ready_lists[PRI_NUM];

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

/*list of sleeping process*/
extern struct list sleep_list;
extern struct list all_list;
void show_lists (void);

bool thread_less_in_priority (const struct list_elem *thread_a,
                             const struct list_elem *thread_b,
                             void *aux UNUSED);

void restore_priority (struct thread* t);
void save_priority (struct thread* t);
size_t get_ready_threads_num (void);
void thread_set_priority_force (int new_priority);

extern float_t load_avg;
#define NICE_MAX_VAL 20
#define NICE_MIN_VAL (-20)
#define NICE_DEFAULT 0

#endif /* threads/thread.h */
