#include "verse.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
//#include <sys/mman.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


int create_verse(int vid)
{
    verse_fd = open(DEFAULT_MINI_DEV, O_RDWR);
    int ret;

    printf("[libverse] create_verse\n");

    // Init verse struct 
    if(verse_fd == -1) {
        fprintf(stderr, "[ERROR] kernel module not exist\n");
        close(verse_fd);
        return -1;
    }

    printf("%d\n", O_TRUNC);

    // create vm
    ret = ioctl(verse_fd, MINI_CREATE_VM, vid);

    return ret;
}

int destroy_verse(int vid)
{
    int ret = -1;

    printf("[libverse] destroy_verse\n");

    ret = ioctl(verse_fd, MINI_DEST_VM, vid);

    return ret;
}

int enter_verse(int vid)
{
    ioctl(verse_fd, MINI_ENTER, vid);

    return 0;
}

int exit_verse()
{
    ioctl(verse_fd, MINI_EXIT);

    return 0;
}

int mmap_verse(__u64 base, __u64 size, int prot, int flags)
{
    struct userspace_memory_region mm = {
        0,
        0,
        base,
        size,
        //(unsigned long)mmap(NULL, size, prot, flags , -1, 0)
        0
    };
    //int ret = ioctl(v->vm_fd, MINI_ALLOC, 0);

    int verse_fd = open(DEFAULT_MINI_DEV, O_RDWR);

    void *start_addr = (void *)mm.userspace_addr;
    //memset(start_addr, 0xAB, 4);

    //int ret = ioctl(v->vm_fd, MINI_SET_USER_MEMORY_REGION, &mm);
    int ret = ioctl(verse_fd, MINI_SET_USER_MEMORY_REGION, &mm);
    
    close(verse_fd);

    //munmap(v->ram_alloc_start, size);
    //v->ram_alloc_size = size;

    //munmap(start_addr, mm.memory_size);

    return ret;
}

void munmap_verse()
{
    printf("[libverse] munmap_verse\n");

    ioctl(verse_fd, MINI_FREE, 0);
}
