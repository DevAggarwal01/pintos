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
#include "filesys/file.h"


#include <string.h>

static void syscall_handler (struct intr_frame *);
struct lock file_lock;

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

void system_exit (int status)
{
  struct thread *t = thread_current();
  t->exit_code = status;
  if(t->child_record != NULL) {
    t->child_record->exit_code = status;
    t->child_record->exited = true;
    sema_up(&t->child_record->exit_sema);
  }
  printf("%s: exit(%d)\n", t->name, status);
  process_exit();
  thread_exit();
}

static uint8_t *addr_to_page(const void *useraddr) {
  if (useraddr == NULL || !is_user_vaddr(useraddr)) {
    return NULL;
  }
  return pagedir_get_page(thread_current()->pagedir, useraddr);
}

static bool copy_data(void *kernel_dst, const void *user_src_, size_t size) {
  const uint8_t *user_src = user_src_;
  uint8_t *kernel_ptr = kernel_dst;

  for (size_t i = 0; i < size; i++) {
    uint8_t *page = addr_to_page(user_src + i);
    if (page == NULL) {
      return false;
    }
    kernel_ptr[i] = *(user_src + i);
  }
  return true;
}


static char *copy_string(const char *user_str) {
  if (user_str == NULL || !is_user_vaddr(user_str)) {
    return NULL;
  }

  char *buffer = palloc_get_page(0);
  if (buffer == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < PGSIZE; i++) {
    uint8_t *page = addr_to_page(user_str + i);
    if (page == NULL) {
      palloc_free_page(buffer);
      return NULL;
    }
    buffer[i] = *(user_str + i);
    if (buffer[i] == '\0') {
      return buffer;
    }
  }

  // Unterminated string or too long
  palloc_free_page(buffer);
  return NULL;
}


/* creates file descriptors and adds to fds list */
static struct fd_entry *create_fd(struct file *file) {
  struct thread *t = thread_current();
  struct fd_entry *fd_entry = palloc_get_page(0);
  if (fd_entry == NULL) {
    return NULL;
  }
  fd_entry->fd = t->next_fd++;
  fd_entry->f = file;
  list_push_back(&t->fds, &fd_entry->elem);
  return fd_entry;
}

static struct fd_entry *find_fd(int fd) {
  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin(&t->fds); e != list_end(&t->fds); e = list_next(e)) {
    struct fd_entry *fd_entry = list_entry(e, struct fd_entry, elem);
    if (fd_entry->fd == fd) {
      return fd_entry;
    }
  }
  return NULL;
}

void remove_fd(int fd) {
  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin(&t->fds); e != list_end(&t->fds); e = list_next(e)) {
    struct fd_entry *fd_entry = list_entry(e, struct fd_entry, elem);
    if (fd_entry->fd == fd) {
      list_remove(e);
      palloc_free_page(fd_entry);
      return;
    }
  }
}



static void syscall_handler (struct intr_frame *f UNUSED)
{
  // get the syscall number from the stack
  uint8_t *sp = f->esp;

  if (sp == NULL || !is_user_vaddr((const void *)sp)) {
    // invalid stack pointer
    system_exit(-1);
  }

  int syscall_num;
  if (!copy_data(&syscall_num, sp, sizeof(int))) {
    system_exit(-1);
  }

  switch (syscall_num) {
    case SYS_HALT: { // void halt (void)
      shutdown_power_off();
      break;
    }

    case SYS_EXIT: { // void exit (int status)
      int status;
      if (!copy_data(&status, sp + 4, sizeof(int))) {
        system_exit(-1);
      }
      system_exit(status);
      break;
    }

    case SYS_EXEC: { // pid_t exec (const char *cmd_line)
      const char *cmd_linePtr;
      if (!copy_data(&cmd_linePtr, sp + 4, sizeof(const char *))) {
        system_exit(-1);
      }
      if (cmd_linePtr == NULL) {
        system_exit(-1);
      }
      char *cmd_line = copy_string((char *)cmd_linePtr);
      if (cmd_line == NULL) {
        system_exit(-1);
      }
      f->eax = process_execute(cmd_line);
      palloc_free_page(cmd_line);
      break;
    }

    case SYS_WAIT: { // int wait (pid_t pid)
      tid_t tid;
      if (!copy_data(&tid, sp + 4, sizeof(tid_t))) {
        f->eax = -1;
        break;
      }
      f->eax = process_wait(tid);
      break;
    }

    case SYS_CREATE: { // bool create (const char *file, unsigned initial_size)
      const char *filePtr;
      unsigned initial_size;
      if (!copy_data(&filePtr, sp + 4, sizeof(const char *))) {
        system_exit(-1);
      }
      if (filePtr == NULL) {
        system_exit(-1);
      }
      if (!copy_data(&initial_size, sp + 8, sizeof(unsigned))) {
        system_exit(-1);
      }
      char *file = copy_string((char *)filePtr);
      if (file == NULL) {
        system_exit(-1);
      }
      if (file[0] == '\0') {
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
      const char *filePtr;
      if (!copy_data(&filePtr, sp + 4, sizeof(const char *))) {
        system_exit(-1);
      }
      if (filePtr == NULL) {
        system_exit(-1);
      }
      char *file = copy_string((char *)filePtr);
      if (file == NULL) {
        system_exit(-1);
      }
      if (file[0] == '\0') {
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
      const char *fileNamePtr;
      if (!copy_data(&fileNamePtr, sp + 4, sizeof(const char *))) {
        system_exit(-1);
      }
      if (fileNamePtr == NULL) {
        system_exit(-1);
      }
      char *fileName = copy_string((char *)fileNamePtr);
      if (fileName == NULL) {
        system_exit(-1);
      }
      if (fileName[0] == '\0') {
        palloc_free_page(fileName);
        f->eax = -1;
        return;
      }
      lock_acquire(&file_lock);
      struct file *file = filesys_open(fileName);
      lock_release(&file_lock);
      if (file == NULL) {
        palloc_free_page(fileName);
        f->eax = -1;
        break;
      }
      struct fd_entry *fd = create_fd(file);
      if (fd == NULL) {
        f->eax = -1;
        file_close(file);
        palloc_free_page(fileName);
        break;
      }
      f->eax = fd->fd;
      palloc_free_page(fileName);
      break;
    }

    case SYS_FILESIZE: { // int filesize (int fd)
      int fd;
      if (!copy_data(&fd, sp + 4, sizeof(int))) {
        system_exit(-1);
      }
      struct fd_entry *fd_entry = find_fd(fd);
      if (fd_entry == NULL) {
        f->eax = -1;
        break;
      }
      lock_acquire(&file_lock);
      f->eax = file_length(fd_entry->f);
      lock_release(&file_lock);
      break;
    }

    case SYS_READ: { // int read (int fd, void *buffer, unsigned size)
      int fd;
      void *buffer;
      unsigned size;
      if (!copy_data(&fd, sp + 4, sizeof(int)) ||
          !copy_data(&buffer, sp + 8, sizeof(void *)) ||
          !copy_data(&size, sp + 12, sizeof(unsigned))) {
        system_exit(-1);
      }
      if (size == 0) {
        f->eax = 0;
        break;
      }
      if (buffer == NULL) {
        system_exit(-1);
      }
      // validate each page of buffer
      char *buf = (char *)buffer;
      unsigned remaining = size;
      while (remaining > 0) {
        if (addr_to_page(buf) == NULL) {
          system_exit(-1);
        }
        size_t offset = (uintptr_t)buf & (PGSIZE - 1);
        size_t chunk = PGSIZE - offset;
        if (chunk > remaining)
          chunk = remaining;
        buf += chunk;
        remaining -= chunk;
      }
      if (fd == 0) { // read from keyboard
        for (unsigned i = 0; i < size; i++) {
          ((char *)buffer)[i] = input_getc();
        }
        f->eax = size;
        break;
      }
      struct fd_entry *fd_entry = find_fd(fd);
      if (fd_entry == NULL) {
        f->eax = -1;
        break;
      }
      lock_acquire(&file_lock);
      f->eax = file_read(fd_entry->f, buffer, size);
      lock_release(&file_lock);
      break;
    }

    case SYS_WRITE: { // int write (int fd, const void *buffer, unsigned size)
      int fd;
      const void *buffer;
      unsigned size;
      if (!copy_data(&fd, sp + 4, sizeof(int)) ||
          !copy_data(&buffer, sp + 8, sizeof(const void *)) ||
          !copy_data(&size, sp + 12, sizeof(unsigned))) {
        system_exit(-1);
      }
      if (size == 0) {
        f->eax = 0;
        break;
      }
      if (buffer == NULL) {
        system_exit(-1);
      }
      // validate each page of buffer
      const char *bufw = (const char *)buffer;
      unsigned remainingw = size;
      while (remainingw > 0) {
        if (addr_to_page(bufw) == NULL) {
          system_exit(-1);
        }
        size_t offset = (uintptr_t)bufw & (PGSIZE - 1);
        size_t chunk = PGSIZE - offset;
        if (chunk > remainingw)
          chunk = remainingw;
        bufw += chunk;
        remainingw -= chunk;
      }
      if (fd == 1) { // write to console
        putbuf(buffer, size);
        f->eax = size;
        break;
      } else if (fd == 0) { // write to keyboard not allowed
        f->eax = -1;
        break;
      } else {
        struct fd_entry *fd_entry = find_fd(fd);
        if (fd_entry == NULL) {
          f->eax = -1;
          break;
        }
        lock_acquire(&file_lock);
        int written = 0;
        while (written < (int)size) {
          int needWrite = size - written;
          int wrote = file_write(fd_entry->f, (const uint8_t *)buffer + written, needWrite);
          if (wrote <= 0) {
            break;
          }
          written += wrote;
        }
        lock_release(&file_lock);
        f->eax = written;
        break;
      }
    }

    case SYS_SEEK: { // void seek (int fd, unsigned position)
      int fd;
      unsigned position;
      if (!copy_data(&fd, sp + 4, sizeof(int))) {
        system_exit(-1);
      }
      if (!copy_data(&position, sp + 8, sizeof(unsigned))) {
        system_exit(-1);
      }
      struct fd_entry *fd_entry = find_fd(fd);
      if (fd_entry == NULL) {
        system_exit(-1);
      }
      lock_acquire(&file_lock);
      file_seek(fd_entry->f, position);
      lock_release(&file_lock);
      break;
    }

    case SYS_TELL: { // unsigned tell (int fd)
      int fd;
      if (!copy_data(&fd, sp + 4, sizeof(int))) {
        system_exit(-1);
      }
      struct fd_entry *fd_entry = find_fd(fd);
      if (fd_entry == NULL) {
        f->eax = -1;
        break;
      }
      lock_acquire(&file_lock);
      f->eax = file_tell(fd_entry->f);
      lock_release(&file_lock);
      break;
    }

    case SYS_CLOSE: { // void close (int fd)
      int fd;
      if (!copy_data(&fd, sp + 4, sizeof(int))) {
        system_exit(-1);
      }
      struct fd_entry *fd_entry = find_fd(fd);
      if (fd_entry == NULL) {
        f->eax = -1;
        break;
      }
      lock_acquire(&file_lock);
      file_close(fd_entry->f);
      lock_release(&file_lock);
      remove_fd(fd);
      break;
    }

    default:
      // unknown syscall number
      system_exit(-1);
  }
}