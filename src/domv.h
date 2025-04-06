#ifndef __DOMV_H
#define __DOMV_H

#include <stdbool.h>

#define DEFAULT_DOMV_DEV "/dev/domv"
#define DOMV_API_VERSION 1

#define DOMV_MEM_READONLY	(1UL << 1)

#define DOMVIO  0xF3

#define DOMV_CREATE_DOMVM      _IO(DOMVIO, 0x01)
#define DOMV_DEST_DOMVM        _IO(DOMVIO, 0x02)

#define DOMV_MMAP       _IOW(DOMVIO, 0x05,	\
				struct	domv_memory_region)
#define DOMV_MUNMAP	_IO(DOMVIO, 0x06)

#define DOMV_ENTER          _IO(DOMVIO, 0x09)
#define DOMV_EXIT           _IO(DOMVIO, 0x0a)

#define DOMV_READ  _IOW(DOMVIO, 0x10, struct domv_memory_region)
#define DOMV_WRITE _IOW(DOMVIO, 0x11, struct domv_memory_region)

#ifndef PROT_NONE
#define PROT_NONE 0x00
#endif

#ifndef PROT_READ
#define PROT_READ 0x01
#endif

#ifndef PROT_WRITE
#define PROT_WRITE 0x02
#endif

#ifndef PROT_EXEC
#define PROT_EXEC 0x04
#endif




typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long size_t;

struct domv_memory_region {
  __u64 gpa;
  __u64 hva;
  __u64 size;
  __u32 prot;
};

int domv_create(int vid);
int domv_destroy(int vid);

int domv_enter(int vid);
void domv_exit();

void *domv_mmap(__u64 base, void *userspace_addr, size_t size, int prot);
void domv_munmap(void *base);
//void *verse_mprotect(__u64 base, __u64 user_start, size_t size, int prot);

int domv_write(void *base, void *src, size_t size, bool del);
int domv_read(void *base, void *src, size_t size, bool del);
//int verse_read(__u64 base, void *dst, size_t size);

#endif //__DOMV_HOST_H
