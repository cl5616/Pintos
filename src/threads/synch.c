/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */

struct list ready_lists[PRI_NUM];

void
sema_init (struct semaphore *sema, unsigned value)
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema)
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0)
  {
      list_insert_ordered(&sema->waiters, &thread_current()->elem,
				        thread_less_in_priority, 0);
      thread_block ();
  }
  sema->value--;
  intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema)
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0)
    {
      sema->value--;
      success = true;
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/*
do not disable interrupt and yield thread
*/
void
sema_up_nointr(struct semaphore *sema)
{
  if (!list_empty (&sema->waiters))//pop_back to get the max priority thread
    thread_unblock (list_entry (list_pop_back (&sema->waiters),
                                struct thread, elem));

  sema->value++;
}
/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema)
{
  enum intr_level old_level;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  sema_up_nointr(sema);
  intr_set_level (old_level);
#ifndef VM
  thread_yield();
#endif
}

void sema_up_in_ext_intr(struct semaphore *sema)
{
  ASSERT (sema != NULL);
  ASSERT (intr_context());
  ASSERT (intr_get_level() == INTR_OFF);

  sema_up_nointr(sema);
  intr_yield_on_return();
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void)
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++)
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_)
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++)
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
  lock -> priority = PRI_MIN;
}

static void update_lock_priority(struct lock* lock, int new_pri);
static void update_holder_priority(struct thread* thread, int new_pri);
static void update_queue_by_priority(struct thread* thread, enum thread_status status);

static bool lock_less_in_priority (const struct list_elem *lock_a,
                             const struct list_elem *lock_b,
                             void *aux UNUSED)
{
  return list_entry (lock_a, struct lock, lock_elem)->priority
    < list_entry (lock_b, struct lock, lock_elem)->priority;
}
/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));
  enum intr_level old_level = intr_disable ();

    if (!thread_mlfqs)
    {
      if (lock -> holder != NULL) {
        thread_current() -> lock_holder = lock -> holder;
        int cur_pri = thread_current() -> priority;
        update_lock_priority(lock, cur_pri);
      }
    }
  intr_set_level (old_level);
  sema_down (&lock->semaphore);
  if (!thread_mlfqs)
    list_insert_ordered(&thread_current() -> locks, &lock -> lock_elem,
                        lock_less_in_priority, 0);

  thread_current() -> lock_holder = NULL;
  lock->holder = thread_current ();
}

void update_lock_priority(struct lock* lock, int new_pri) {
  ASSERT(lock != NULL);
  ASSERT(new_pri >= PRI_MIN && new_pri <= PRI_MAX);
  if (lock -> priority >= new_pri) {
    return;
  }

  lock -> priority = new_pri;
  update_holder_priority(lock -> holder, new_pri);
}

void update_holder_priority(struct thread* thread, int new_pri) {
  if (thread -> priority >= new_pri){
    return;
  }

  thread -> priority = new_pri;

  enum thread_status status = thread -> status;
  update_queue_by_priority(thread, status);

  if (thread -> lock_holder != NULL)
    update_holder_priority(thread -> lock_holder, new_pri);
}

static void priority_sort(struct list_elem* e,
                           list_less_func* priority_less, void* aux) {

   ASSERT(e != NULL);
   struct list_elem* cursor = e;

   if (cursor->prev->prev != NULL
      &&
     list_entry(cursor, struct thread, elem)->priority
       < list_entry(cursor->prev, struct thread, elem)->priority) {
     while (cursor->prev->prev != NULL
            && priority_less(e, cursor->prev, aux)) {
       cursor = cursor->prev;
     }
     list_remove(e);
     list_insert(cursor, e);
   } else if (cursor->next->next != NULL
                &&
              list_entry(cursor, struct thread, elem)->priority
                > list_entry(cursor->next, struct thread, elem)->priority) {
         while (cursor->next->next != NULL
                && priority_less(cursor->next, e, aux)) {
           cursor = cursor->next;
         }
         list_remove(e);
         list_insert(cursor->next, e);
   }

}

void update_queue_by_priority(struct thread* thread, enum thread_status status) {
  int new_pri = thread -> priority;
  if (status == THREAD_READY) {
    list_remove(&thread -> elem);
    list_push_back(&ready_lists[new_pri], &thread -> elem);
  } else if (status == THREAD_BLOCKED){
    priority_sort(&thread -> elem, thread_less_in_priority, 0);
  }
}
/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
  {
		struct thread* cur = thread_current ();
    lock->holder = cur;
	}
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */

void
lock_release (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));
  enum intr_level old = intr_disable();
  struct thread* cur = thread_current();
  if (!thread_mlfqs)
  {
    if (cur -> priority > lock -> priority) {
      list_remove(&lock -> lock_elem);
      if (list_empty(&cur->locks)) {
        cur->priority = cur->base_priority;
      }
    } else {
      list_remove(&lock -> lock_elem);
      struct list* lock_list = &(cur -> locks);
      int thread_new_pri = list_empty(lock_list) ? cur -> base_priority :
                                            (list_entry(
                                              list_back(lock_list),
                                              struct lock, lock_elem) -> priority);

      if (thread_new_pri < cur->base_priority) {
        thread_new_pri = cur->base_priority;
      }
      cur -> priority = thread_new_pri;

      struct list* waiters = &(lock -> semaphore).waiters;
      int lock_new_pri;
      if (list_size(waiters) < 2) {
        lock_new_pri = PRI_MIN;
      } else {
        struct list_elem* fstWaiter = list_pop_back(waiters);
        lock_new_pri = list_entry(list_back(waiters), struct thread, elem)
                                                                    -> priority;
        list_push_back(waiters, fstWaiter);
      }
      lock -> priority = lock_new_pri;
    }
  }
  lock->holder = NULL;
  sema_up_nointr (&lock->semaphore);
  intr_set_level(old);
#ifndef VM
  thread_yield();
#endif
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock)
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem
  {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
    int priority;
  };

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

static bool waiter_less_in_priority (const struct list_elem *waiter_a,
                             const struct list_elem *waiter_b,
                             void *aux UNUSED)
{
  return list_entry (waiter_a, struct semaphore_elem, elem)->priority
    < list_entry (waiter_b, struct semaphore_elem, elem)->priority;
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock)
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);//  list_push_back (&cond->waiters, &waiter.elem);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  sema_init (&waiter.semaphore, 0);
  waiter.priority = thread_get_priority();
  list_insert_ordered(&cond->waiters, &waiter.elem, waiter_less_in_priority, 0);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED)
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters))
    sema_up (&list_entry (list_pop_back (&cond->waiters),
                          struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock)
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
