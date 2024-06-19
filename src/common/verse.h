#ifndef __VERSE_LIB__
#define __VERSE_LIB__

//#include <linux/ioctl.h>
#include <sys/mman.h>

#define DEFAULT_MINI_DEV    "/dev/mini"

#define MINIIO  0xF3

#define MINI_CREATE_VM  _IO(MINIIO, 0x1)
#define MINI_DEST_VM  _IO(MINIIO, 0x2)

#define MINI_ALLOC  _IO(MINIIO, 0x5)
#define MINI_FREE   _IO(MINIIO, 0x6)

#define MINI_ENTER  _IO(MINIIO, 0x9)
#define MINI_EXIT   _IO(MINIIO, 0xa)

#define VERSE_ATTACH _IO(MINIIO, 0xb)
#define VERSE_DETACH _IO(MINIIO, 0xc)

#define MINI_CREATE_VCPU  _IO(MINIIO, 0x41)

#define MINI_SET_USER_MEMORY_REGION     _IOW(MINIIO, 0x46, struct userspace_memory_region)

static int verse_fd;

typedef unsigned int __u32;
typedef unsigned long __u64;

struct userspace_memory_region {
    __u32 slots;
    __u32 flags;
    __u64 guest_phys_addr;
    __u64 memory_size;
    __u64 userspace_addr;
};

int create_verse(int vid);
int destroy_verse(int vid);

int enter_verse(int vid);
int exit_verse();

int mmap_verse(__u64 base, __u64 size, int prot, int flags);
void munmap_verse();

int verse_mmap(struct verse *v);
int verse_munmap(struct verse *v);
int verse_mprotect(struct verse *v);
#endif
