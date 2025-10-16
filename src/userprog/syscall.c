#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#include <string.h>

static void syscall_handler (struct intr_frame *);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
    if (page == NULL) thread_exit();

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
    case SYS_HALT:
      // halt the system
      // (not implemented)
      break;
    case SYS_EXIT:
      int status;
      copy_data(&status, sp+4, sizeof(int));
      system_exit(status);
      break;
    case SYS_EXEC:
      // run a new executable
      // (not implemented)
      break;
    case SYS_WAIT:
      // wait for a child process to die
      // (not implemented)
      break;
    case SYS_CREATE:
      // create a file
      // (not implemented)
      break;
    case SYS_REMOVE:
      // delete a file
      // (not implemented)
      break;
    case SYS_OPEN:
      // open a file
      // (not implemented)
      break;
    case SYS_FILESIZE:
      // obtain a file's size
      // (not implemented)
      break;
    case SYS_READ:
      // read from a file
      // (not implemented)
      break;
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


