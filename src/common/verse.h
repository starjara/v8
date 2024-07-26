#ifndef __VERSE_LIB__
#define __VERSE_LIB__

#define DEFAULT_VERSE_DEV    "/dev/verse"

#define VERSEIO  0xF3

#define VERSE_CREATE  _IO(VERSEIO, 0x01)
#define VERSE_DEST  _IO(VERSEIO, 0x02)

#define VERSE_ENTER  _IO(VERSEIO, 0x11)
#define VERSE_EXIT   _IO(VERSEIO, 0x12)

#define VERSE_MMAP  _IOW(VERSEIO, 0x21, struct verse_memory_region)
#define VERSE_MUNMAP   _IO(VERSEIO, 0x22)
#define VERSE_MPROTECT _IO(VERSEIO, 0x23)

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

struct verse_memory_region {
  __u64 guest_phys_addr;
  __u64 memory_size;
  __u64 userspace_addr;
  __u32 prot;
};

int verse_create(int vid);
int verse_destroy(int vid);

int verse_enter(int vid);
int verse_exit(int isFast);

__u64 verse_mmap(__u64 base, __u64 userspace_addr, size_t size, int prot);
void verse_munmap(__u64 base, size_t size);
void *verse_mprotect(__u64 base, __u64 user_start, size_t size, int prot);

int verse_write(__u64 base, void *src, size_t size);
int verse_read(__u64 base, void *dst, size_t size);

#endif
