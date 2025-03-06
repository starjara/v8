#ifndef __DOMV_H
#define __DOMV_H

#define DEFAULT_DOMV_DEV "/dev/domv"
#define DOMV_API_VERSION 1

#define DOMV_MEM_READONLY	(1UL << 1)

#define DOMVIO  0xF3

#define DOMV_GET_API_VERSION_      _IO(DOMVIO, 0x00)
#define DOMV_CREATE_DOMVM      _IO(DOMVIO, 0x01)
#define DOMV_DEST_DOMVM        _IO(DOMVIO, 0x02)

#define DOMV_GET_VCPU_MMAP_SIZE    _IO(DOMVIO,   0x04) /* in bytes */

#define DOMV_MMAP       _IOW(DOMVIO, 0x05,	\
				struct	domv_memory_region)
#define DOMV_MUNMAP	_IO(DOMVIO, 0x06)

#define DOMV_ENTER          _IO(DOMVIO, 0x09)
#define DOMV_EXIT           _IO(DOMVIO, 0x0a)

#define DOMV_MAP_EXECUTABLE         _IOW(DOMVIO, 0x0b, struct domv_memory_region)
#define DOMV_UNMAP_EXECUTABLE         _IO(DOMVIO, 0x0c)

#define DOMV_CREATE_VCPU           _IO(DOMVIO,   0x41)

#define DOMV_SET_USER_MEMORY_REGION _IOW(DOMVIO, 0x46, \
					 struct domv_memory_region)

#define DOMV_MEM_LOG_DIRTY_PAGES	(1UL << 0)
#define DOMV_MEM_READONLY	(1UL << 1)

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

int verse_create(int vid);
int verse_destroy(int vid);

int verse_enter(int vid);
int verse_exit();

__u64 verse_mmap(__u64 base, __u64 userspace_addr, size_t size, int prot);
void verse_munmap(__u64 base, size_t size);
void *verse_mprotect(__u64 base, __u64 user_start, size_t size, int prot);

int verse_write(void *base, void *src, size_t size);
//int verse_read(__u64 base, void *dst, size_t size);
unsigned long long verse_read(void *base, size_t size);

int verse_bulk_write(void *base, void *src, size_t size);
int verse_bulk_read(void *base, void *dest, size_t size);

      

#endif //__DOMV_HOST_H
