#ifndef __PHEAP_H__
#define __PHEAP_H__
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct pheap;

size_t __attribute__((pure)) pheap_mgmt_size(size_t heapsize);

struct pheap *pheap_init(void *mgmt, size_t mgmt_size,
			 void *heap, size_t heapsize,
			 bool shared);

void *pmalloc(struct pheap *ph, size_t size);

void pfree(struct pheap *ph, void *ptr);

size_t pmalloc_usable_size(struct pheap *ph, void *ptr);

void *pmmheap(size_t prefix, size_t len, struct pheap **ph);
#endif /* __PHEAP_H__ */
