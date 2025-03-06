#ifndef __DOMVM_H__
#define __DOMVM_H__

#include "domv.h"

int domv_init_vm(struct domvm *domvm);
void domv_destroy_vm(struct domvm *domvm);
int domv_enter(struct domvm *domvm);
int domv_exit(struct domvm *domvm);

#endif /* __DOMVM_H__ */
