#ifndef __MINI_TYPES_H__
#define __MINI_TYPES_H__

struct domvm;
struct domv_memory_region;


typedef unsigned long long u64;
typedef unsigned int u32;

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

#define INVALID_GPA	(~(gpa_t)0)

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

#endif
