#ifndef __DOMV_H
#define __DOMV_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "domv_types.h"
#include "domvm.h"
#include "domv_mmu.h"

#define domv_err(fmt, ...) \
    pr_err("[DOMV] [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define domv_info(fmt, ...) \
    pr_info("[DOMV] [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

#define DOMV_API_VERSION 1

#define DOMV_MEM_READONLY	(1UL << 1)

#define DOMVIO  0xF3

#define DOMV_GET_API_VERSION_      _IO(DOMVIO, 0x00)
#define DOMV_CREATE_DOMVM      _IO(DOMVIO, 0x01)
#define DOMV_DEST_DOMVM        _IO(DOMVIO, 0x02)

#define DOMV_GET_VCPU_MMAP_SIZE    _IO(DOMVIO,   0x04) /* in bytes */

#define DOMV_MMAP          _IOW(DOMVIO, 0x05, \
				struct domv_memory_region)
#define DOMV_MUNMAP           _IO(DOMVIO, 0x06)

#define DOMV_ENTER          _IO(DOMVIO, 0x09)
#define DOMV_EXIT           _IO(DOMVIO, 0x0a)

#define DOMV_MAP_EXECUTABLE         _IOW(DOMVIO, 0x0b, struct domv_memory_region)
#define DOMV_UNMAP_EXECUTABLE         _IO(DOMVIO, 0x0c)

#define DOMV_CREATE_VCPU           _IO(DOMVIO,   0x41)

#define DOMV_SET_USER_MEMORY_REGION _IOW(DOMVIO, 0x46, \
					 struct domv_memory_region)

#define DOMV_MEM_LOG_DIRTY_PAGES	(1UL << 0)
#define DOMV_MEM_READONLY	(1UL << 1)

#define MAX_VMID 4096
#define MAX_REGIONS 10


struct domv_memory_region {
  u64 gpa;
  u64 hva;
  u64 size;
  u32 prot;
};

struct domv_vma {
  u64 gpa_start;
  u64 gpa_end;
  u64 hva;
  u64 kva;
  u64 prot;
};

struct domvm {
  void *pgd;
  u64 vmid;        // User declared VID
  struct domv_vma vma_array[MAX_REGIONS];
};

#endif //__DOMV_HOST_H
