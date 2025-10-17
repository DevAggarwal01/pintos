#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void remove_fd(int fd);

extern struct lock file_lock;


#endif /* userprog/syscall.h */
