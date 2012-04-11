/********************************************************************* 
 * pheap - Private heap Library
 ********************************************************************* 
 * Copyright (C) 2012 Dave Boutcher
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING3.  If not see
 * <http://www.gnu.org/licenses/>. 
 ********************************************************************* 
 * Couple of todos:
 *  1) handle non-power-of-two sizes. To do that, just don't
 *     actually hand out blocks that fall past the end (though we
 *     will otherwise act like they exist)
 *  2) Don't write "far end" free list entries, to prevent
 *     pushing past the end of touched memory.  Keep some kind
 *     of "farthest touched" index, and only push that out if 
 *     we run out of free blocks
 *  3) Make MIN_ORDER a paramter?
 *********************************************************************/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>

#include "pheap.h"

#define BLOCK_INVALID (0x00)
#define BLOCK_FREE    (0x01)
#define BLOCK_ALLOC   (0x02)
#define BLOCK_SPLIT   (0x03)

#define PHEAP_MIN_ORDER (6U)
#define PHEAP_MIN_SIZE (1U<<PHEAP_MIN_ORDER)

#define PHEAP_MAGIC (0xDB014EA9LU)
#define PHEAP_FREE_MAGIC (0xDB024EA9LU)

/* Double linked list put at the beginning of every freed block */
struct pheap_free {
	uint64_t free_magic;
	struct pheap_free *next;
	struct pheap_free **prevp;
};

/* Heap block at the beginning of the management area */
struct pheap {
	uint64_t magic;             /* Magic value */
	pthread_spinlock_t lock;    /* Single lock */
	void *heap;                 /* pointer to heap memory */
	size_t heapsize;            /* size of heap */
	uint32_t max_order;         /* highest order allocation */
	uint32_t max_tree;          /* max byte in tree array */
	uint8_t *tree;              /* pointer to tree array */
	struct pheap_free *frees[]; /* per-order free list */ 
};

/* Our tree structure has two bits per node, packed into a heap (classic
 * heap datastructure, that is, not "heap" as in malloc.)  This routine
 * extracts the two bit value given the linear index into the map.  
 * tagMax is redundant, but included just for safety
 */
static uint8_t getTag(uint8_t *tagMap, uint64_t tagNo, uint64_t tagMax)
{
	/* There are four tags per byte */
	uint64_t tagByte = tagNo >> 2UL;

	assert(tagByte < tagMax);

	uint64_t tagShift = (tagNo & 0x03LU) << 1UL;

	return (tagMap[tagByte] >> tagShift) & 0x03U;
}

/* Set a two bit tag value */
static void setTag(uint8_t *tagMap, uint64_t tagNo, uint64_t tagMax, uint8_t tagVal)
{
	/* There are four tags per byte */
	uint64_t tagByte = tagNo >> 2UL;

	assert(tagByte < tagMax);
	assert(tagVal < 4U);

	uint64_t tagShift = (tagNo & 0x03LU) << 1UL;

	uint8_t tagMask = (((0xFC << tagShift) & 0xFF) |
			   (0xFF >> (8U - tagShift)));

	tagMap[tagByte] = ((tagMap[tagByte] & tagMask) | (tagVal << tagShift));
}

/* Remove an entry from a doubly linked free list.  O(1) for any entry
 * in the list 
 */
static struct pheap_free *
flist_remove(struct pheap_free *e)
{
	assert(e->free_magic == PHEAP_FREE_MAGIC);
	if (e->next)
		e->next->prevp = e->prevp;
	*e->prevp = e->next;
	e->free_magic = 0;
	e->next = NULL;
	e->prevp = NULL;
	return e;
}

/* Push an entry onto the double linked free list. O(1) */
static void flist_push(struct pheap_free **head, void *ptr)
{
	struct pheap_free *e = ptr;
	e->next = *head;
	e->prevp = head;
	if (e->next)
		e->next->prevp = &e->next;
	*head = e;
	e->free_magic = PHEAP_FREE_MAGIC;
}

/* Pop the first entry off the double linked free list O(1) */
static void *flist_pop(struct pheap_free **head)
{
	if (*head == NULL)
		return NULL;

	return flist_remove(*head);
}

/* We break this out into an ugly macro just because we need it in
 * a couple of places
 */
#define PHEAP_SIZES							\
	int order = __builtin_ffsl(heapsize) - 1;			\
									\
        order = order - PHEAP_MIN_ORDER;                                \
									\
        size_t treesize = heapsize >> (PHEAP_MIN_ORDER-1);	        \
        size_t treebytes = (treesize + 3U) / 4U

size_t __attribute__((pure)) pheap_mgmt_size(size_t heapsize)
{
	if (__builtin_popcountl(heapsize) != 1) {
		fprintf(stderr,"Heap size must be a power of 2\n");
		return 0;
	}

	PHEAP_SIZES;

	size_t mgmt_size = (sizeof(struct pheap) +
			    sizeof(struct pheap_free *) * order +
			    treebytes);

	if (order < PHEAP_MIN_ORDER) {
		fprintf(stderr,"Heap size must be minimum of %u bytes\n", PHEAP_MIN_SIZE);
		return 0;
	}

	return mgmt_size;
}

struct pheap *pheap_init(void *mgmt, size_t mgmt_size,
			 void *heap, size_t heapsize,
			 bool shared)
{
	if (__builtin_popcountl(heapsize) != 1) {
		fprintf(stderr,"Heap size must be a power of 2\n");
		return NULL;
	}

	if (mgmt_size < pheap_mgmt_size(heapsize)) {
		fprintf(stderr, "pheap mgmt size too small\n");
		return NULL;
	}

	PHEAP_SIZES;

	struct pheap *ph = mgmt;

	memset(mgmt, 0x00, mgmt_size);

	ph->magic = PHEAP_MAGIC;
	pthread_spin_init(&ph->lock,
			  shared ?
			  PTHREAD_PROCESS_SHARED : PTHREAD_PROCESS_PRIVATE);

	ph->heap = heap;
	ph->heapsize = heapsize;
	ph->max_order = order;
	ph->max_tree = treebytes;
	ph->tree = (uint8_t *)(ph->frees + order + 1);

	flist_push(&ph->frees[order], heap);
	ph->tree[0] = BLOCK_FREE;

	return ph;
}

static uint32_t
size_to_order(size_t size)
{
	if (size <= 1) /* __builtin_clzl(0) is undefined */
		return size;
	return ((int)sizeof(size_t) * 8) - __builtin_clzl(size - 1);
}

static uint64_t ptr_to_tag(struct pheap *ph, void *ptr, uint32_t order)
{
	assert(ptr >= ph->heap);

	uint64_t addr = (uint64_t)ptr - (uint64_t)ph->heap;
	addr = addr >> (order + PHEAP_MIN_ORDER);

	uint64_t tstart = (1U<<(ph->max_order - order))-1U;

	return tstart + addr;
}

/* This returns the buddy of a tag */
static uint64_t pair_tag(uint64_t tag)
{
	if (tag & 0x01)
		return tag + 1;
	else
		return tag - 1;
}

void *pmalloc(struct pheap *ph, size_t size)
{
	void *ret = NULL;
	assert(ph->magic == PHEAP_MAGIC);
	
	if (size < PHEAP_MIN_SIZE)
		size = PHEAP_MIN_SIZE;

	uint32_t order = size_to_order(size) - PHEAP_MIN_ORDER;
	if (order > ph->max_order) {
		fprintf(stderr, "debug: pmalloc too big! %lu\n", size);
		return NULL;
	}

	pthread_spin_lock(&ph->lock);
	ret = flist_pop(&ph->frees[order]);
	if (ret) {
		uint64_t tag = ptr_to_tag(ph, ret, order);
		if (getTag(ph->tree, tag, ph->max_tree) != BLOCK_FREE) {
			fprintf(stderr,"Error: free block tag %lu val %u ptr %p!\n",
				tag,
				getTag(ph->tree, tag, ph->max_tree),
				ret);
			pthread_spin_unlock(&ph->lock);
			return NULL;
		}
		setTag(ph->tree, tag, ph->max_tree, BLOCK_ALLOC);
		pthread_spin_unlock(&ph->lock);
		return ret;
	}

	pthread_spin_unlock(&ph->lock);

	/* Ok, no luck, drop the lock and try to get the next larger size
	 * block
	 */
	size_t nextsize = 1U << (order + 1U + PHEAP_MIN_ORDER);
	void *nextblock = pmalloc(ph, nextsize);

	/* If we are totally out, return NULL */
	if (nextblock == NULL) {
		return NULL;
	}

	/* Calculate the block 1/2 way through this one */
	void *free_entry = ((uint8_t *)nextblock + (nextsize >> 1));

	uint64_t split_tagNo = ptr_to_tag(ph, nextblock, order+1);
	uint64_t tag1No = ptr_to_tag(ph, nextblock, order);
	uint64_t tag2No = ptr_to_tag(ph, free_entry, order);

	pthread_spin_lock(&ph->lock);
	if (getTag(ph->tree, split_tagNo, ph->max_tree) != BLOCK_ALLOC) {
		fprintf(stderr,"Error: nextblock was not BLOCK_ALLOC\n");
		return NULL;
	}
	if (getTag(ph->tree, tag1No, ph->max_tree) != BLOCK_INVALID) {
		fprintf(stderr,"Error: tag1 was not BLOCK_INVALID\n");
		return NULL;
	}
	if (getTag(ph->tree, tag2No, ph->max_tree) != BLOCK_INVALID) {
		fprintf(stderr,"Error: tag1 was not BLOCK_INVALID\n");
		return NULL;
	}
	setTag(ph->tree, split_tagNo, ph->max_tree, BLOCK_SPLIT);
	setTag(ph->tree, tag1No, ph->max_tree, BLOCK_ALLOC);
	setTag(ph->tree, tag2No, ph->max_tree, BLOCK_FREE);

	flist_push(&ph->frees[order], free_entry);
	pthread_spin_unlock(&ph->lock);

	return nextblock;
}

static uint64_t findorder(struct pheap *ph, void *ptr, uint64_t max_order)
{
	uint64_t order;
	uint64_t tagNo = 0;

	/* Don't need to do this under a lock, since we own this memory */
	for (order = 0; order <= max_order; order++) {
		tagNo = ptr_to_tag(ph, ptr, order);
		uint8_t tag = getTag(ph->tree, tagNo, ph->max_tree);

		if (tag == BLOCK_FREE) {
			fprintf(stderr,"Invalid freed address!\n");
			return (size_t)-1;
		} else if (tag == BLOCK_SPLIT) {
			fprintf(stderr,"Wierd, found split tag first!\n");
			return (size_t)-1;
		} else if (tag == BLOCK_ALLOC) {
			break;
		}
	}

	if (order > max_order) {
		fprintf(stderr, "bad free!\n");
		return (size_t)-1;
	}
	
	return order;
}

void pfree(struct pheap *ph, void *ptr)
{
	uint64_t order;
	uint64_t max_order = ph->max_order; /* make a local copy */

	assert(ph->magic == PHEAP_MAGIC);

	assert(ptr >= ph->heap);

	uint64_t addr = (uint64_t)ptr - (uint64_t)ph->heap;

	/* check for non-round address */
	if (addr & (PHEAP_MIN_SIZE-1)) {
		fprintf(stderr,"Invalid address in free\n");
		return;
	}
	
	order = findorder(ph, ptr, max_order);

	if (order == (size_t)-1)
	    return;

	uint64_t tagNo = ptr_to_tag(ph, ptr, order);
	uint64_t pairTagNo = pair_tag(tagNo);

	pthread_spin_lock(&ph->lock);
	/* Now see if we can pair up */
	while ((order < max_order) &&
	       (getTag(ph->tree, pairTagNo, ph->max_tree) == BLOCK_FREE)) {
		
		/* We can pair this up!  Mark both halves as invalid */
		setTag(ph->tree, tagNo, ph->max_tree, BLOCK_INVALID);
		setTag(ph->tree, pairTagNo, ph->max_tree, BLOCK_INVALID);

		/* Work out the other half's address */
		uint64_t pairaddr = addr ^ (1U << (order + PHEAP_MIN_ORDER));
		void *pairptr = (void *)((uint64_t)ph->heap + pairaddr);

		flist_remove((struct pheap_free *)pairptr);
		
		/* Move to the next order */
		order++;
		
		addr = addr & (~((1LU << ((uint64_t)order + PHEAP_MIN_ORDER)) - 1LU));
		ptr = (void *)((uint64_t)ph->heap + addr);
		
		/* Now get the tag for the higher pointer and his brother */
		tagNo = ptr_to_tag(ph, ptr, order);
		pairTagNo = pair_tag(tagNo);
	
		/* Sanity check...this block should be marked "split" */
		if (getTag(ph->tree, tagNo, ph->max_tree) != BLOCK_SPLIT)
			fprintf(stderr,
				"Wierd! expected BLOCK_SPLIT for tag %lu, got %u\n",
				tagNo, getTag(ph->tree, tagNo, ph->max_tree));
	}
	
	setTag(ph->tree, tagNo, ph->max_tree, BLOCK_FREE);
	flist_push(&ph->frees[order], ptr);
	pthread_spin_unlock(&ph->lock);
	return;
}

size_t pmalloc_usable_size(struct pheap *ph, void *ptr)
{
	uint64_t order;
	uint64_t max_order = ph->max_order; /* make a local copy */

	assert(ph->magic == PHEAP_MAGIC);

	assert(ptr >= ph->heap);

	uint64_t addr = (uint64_t)ptr - (uint64_t)ph->heap;

	/* check for non-round address */
	if (addr & (PHEAP_MIN_SIZE-1)) {
		fprintf(stderr,"Invalid address in free\n");
		return 0;
	}
	
	order = findorder(ph, ptr, max_order);

	if (order == (size_t)-1)
	    return 0;
	
	return (1U << (order + PHEAP_MIN_ORDER));
}
