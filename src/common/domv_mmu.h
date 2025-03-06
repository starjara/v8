#ifndef __DOMV_MMU_H__
#define __DOMV_MMU_H__

#include "domv.h"

int domv_gstage_alloc_pgd(struct domvm *domvm);
void domv_gstage_free_pgd(struct domvm *domvm);
void domv_gstage_update_hgatp(struct domvm *domvm);
/*
int domv_gstage_map(struct domvm *domvm,
		    gpa_t gpa, unsigned long hva, bool is_write);
*/
int domv_gstage_map(struct domvm *domvm, struct domv_memory_region *requested_region);
int domv_gstage_munmap(struct domvm *domvm, struct domv_memory_region *target);

#endif /* __DOMV_MMU_H__ */
