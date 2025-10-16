#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/synch.h"


#include <string.h>

static void syscall_handler (struct intr_frame *);
struct lock file_lock;

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void *addr_to_page (const void *addr) {
  if (addr == NULL || !is_user_vaddr(addr)) return NULL;
  void *page = pg_round_down((void *)addr);

  return pagedir_get_page (thread_current()->pagedir, page);
}

static void copy_data (void *dst, const void *src, size_t size) {
  uint8_t *dest = dst;
  const uint8_t *source = src;

  while (size > 0) {
    void *page = addr_to_page(source);
    if (page == NULL) return NULL;

    size_t offset  = (size_t)((uintptr_t)source & (PGSIZE - 1));
    size_t remainder     = PGSIZE - offset;
    if (remainder > size) remainder = size; // to prevent problems when data is between 2 pages
    uint8_t *kptr = (uint8_t *)page + offset;
    memcpy(dest, kptr, remainder);

    dest  += remainder;
    source  += remainder;
    size -= remainder;
  }
}

static char *copy_string (char *str) {
  char *s = palloc_get_page(0);
  if (s == NULL) return NULL;
  size_t i = 0;
  while (true) {
    void *page = addr_to_page((uint8_t *) str + i);
    if (page == NULL) {
      palloc_free_page(s);
      return NULL;
    }
    size_t offset = ((uintptr_t)str + i) & (PGSIZE - 1);
    size_t remainder = PGSIZE - offset;
    char *src = (char *)page + offset;

    for (size_t bytes = 0; bytes < remainder; bytes++) {
      s[i++] = src[bytes];
      if (src[bytes] == '\0') {
        return s; // end of string
      }
    }
  }
}

static void system_exit (int status)
{
  struct thread *t = thread_current();
  t->exit_code = status;
  if(t->child_record != NULL) {
    t->child_record->exit_code = status;
    t->child_record->exited = true;
    sema_up(&t->child_record->exit_sema);
  }
  thread_exit();
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  // get the syscall number from the stack
  uint8_t *sp = f->esp;

  if(sp == NULL || !is_user_vaddr((const void *)sp)) {
    // invalid pointer
    thread_exit();
  }

  int syscall_num;
  copy_data(&syscall_num, sp, sizeof(int));

  // int a0=0,a1=0,a2=0;
  // copy_data(&a0, sp+4, 4);
  // copy_data(&a1, sp+8, 4);
  // copy_data(&a2, sp+12, 4);

  // printf("sysno=%d a0=%d a1=0x%x a2=%d\n", syscall_num, a0, (unsigned)a1, a2);

  switch(syscall_num) {
    case SYS_HALT: { // void halt (void)
      shutdown_power_off();
      break;
    }
      
    case SYS_EXIT: { // void exit (int status)
      int status;
      copy_data(&status, sp+4, sizeof(int));
      system_exit(status);
      break;
    }
    case SYS_EXEC: { // pid_t exec (const char *cmd_line)
        char *cmd_linePtr;
        copy_data(&cmd_linePtr, sp+4, sizeof(const char *));
        if(cmd_linePtr == NULL) {
          system_exit(-1);
        }
        char *cmd_line = copy_string(cmd_linePtr);
        if (cmd_line == NULL) {
          system_exit(-1);
        }
        f->eax = process_execute(cmd_line);
        palloc_free_page(cmd_line);
        break;
      }
    case SYS_WAIT: { // int wait (pid_t pid)
      tid_t tid;
      copy_data(&tid, sp+4, sizeof(tid_t));
      f->eax = process_wait(tid);
      break;
      }
    case SYS_CREATE: { // bool create (const char *file, unsigned initial_size)
      char *filePtr;
      unsigned initial_size;
      copy_data(&filePtr, sp+4, sizeof(const char *));
      if(filePtr == NULL) {
        system_exit(-1);
      }
      copy_data(&initial_size, sp+8, sizeof(unsigned));
      char *file = copy_string(filePtr);
      if(file == NULL || file == '\0') {
        palloc_free_page(file);
        f->eax = false;
        return;
      }
      lock_acquire(&file_lock);
      f->eax = filesys_create(file, initial_size);
      lock_release(&file_lock);
      palloc_free_page(file);
      break;
    }
    case SYS_REMOVE: { // bool remove (const char *file)
      char *filePtr;
      copy_data(&filePtr, sp+4, sizeof(const char *));
      if(filePtr == NULL) {
        system_exit(-1);
      }
      char *file = copy_string(filePtr);
      if(file == NULL || file == '\0') {
        palloc_free_page(file);
        f->eax = false;
        return;
      }
      lock_acquire(&file_lock);
      f->eax = filesys_remove(file);
      lock_release(&file_lock);
      palloc_free_page(file);
      break;

    }
    case SYS_OPEN: { // int open (const char *file)
      const char *file;
      copy_data(&file, sp+4, sizeof(const char *));
      lock_acquire(&file_lock);
      struct file *filePtr = filesys_open(file);
      lock_release(&file_lock);
      f->eax = (int) filePtr;
      // TODO need to somehow return a file descriptor instead of a file pointer
      break;
    }
    case SYS_FILESIZE: { // int filesize (int fd)
      break;
    }
    case SYS_READ: { // int read (int fd, void *buffer, unsigned size)
      // read from a file
      // (not implemented)
      break;
    }
    case SYS_WRITE:
      // write to a file
      // (not implemented)
      break;
    case SYS_SEEK:
      // change position in a file
      // (not implemented)
      break;
    case SYS_TELL:
      // report current position in a file
      // (not implemented)
      break;
    case SYS_CLOSE:
      // close a file
      // (not implemented)
      break;
    default:
      // unknown syscall number
      thread_exit();
    

  }

}


