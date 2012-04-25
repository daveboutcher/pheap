#ifndef __PHEAP_H__
#define __PHEAP_H__
#include <stddef.h>

struct pheap;

struct pheap *pheap_init(void *mgmt, size_t mgmt_size,
			 void *heap, size_t heapsize,
			 int shared);

void *pmalloc(struct pheap *ph, size_t size);

void pfree(struct pheap *ph, void *ptr);

size_t pheap_mgmt_size(size_t heapsize);

size_t pmalloc_usable_size(struct pheap *ph, void *ptr);
#endif /* __PHEAP_H__ */
