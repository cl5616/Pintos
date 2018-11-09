#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <inttypes.h>
void syscall_init (void);

#define SYSCALL_VEC 0x30
#define FD_SIZE 1024            /* File Descriptors size. */
#define FILE_NUM 1024           /* File Number*/
#define MAX_FILE_NAME_LEN 14
struct file_info {
  int size;
  struct file* file;
  int file_descriptor;
  char name[MAX_FILE_NAME_LEN];
};

/* Process identifier. */
typedef int pid_t;
typedef uint32_t arg_t;
typedef int mapid_t;
extern struct lock file_sys_lock;
void exit (int status);
#define EXIT_ERROR (-1)
#define EXIT_SUCCESS 0

#define MAX_NUM_OF_FILES 146

#endif /* userprog/syscall.h */
