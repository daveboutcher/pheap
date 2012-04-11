/*
 * With thanks to Scott Parish
 */

#include "pheap.h"
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

struct fib {
	struct fib	*next;
	uint64_t	n;
};

static inline size_t
rand_sz(size_t min_sz)
{
	return ((size_t)rand() & ((1 << 12) - 1)) + min_sz;
}

static void *
fib(void *vph)
{
	struct fib *f, *lf;
	int i, j;
	uint64_t n1, n2, n3;
	struct pheap *ph = vph;

        for (j = 0; j < 200; j++) {
                f = pmalloc(ph, rand_sz(sizeof(struct fib)));
                f->n = 1;
                f->next = pmalloc(ph, rand_sz(sizeof(struct fib)));
                f->next->n = 1;
                f->next->next = NULL;

                n1 = n2 = 1;

                for (i = 2; i < 90; i++) {
                        f->next->next =
                                pmalloc(ph, rand_sz(sizeof(struct fib)));
			assert(f->next->next != NULL);
                        f->next->next->n = f->n + f->next->n;
                        f->next->next->next = NULL;

                        n3 = n2 + n1;
			assert(n3 == f->next->next->n);
                        n1 = n2;
                        n2 = n3;

                        lf = f;
                        f = f->next;
                        pfree(ph, lf);
                }

                lf = f;
                f = f->next;
                pfree(ph, lf);
                lf = f;
                f = f->next;
                pfree(ph, lf);
                assert(f == NULL);
        }

	return NULL;
}

#define MAX_THREADS 8
#define HEAP_SZ (1 << 20) /* 32Mib */

static void
fib_test(int threads)
{
	pthread_t th[MAX_THREADS];
	void *heap = calloc(HEAP_SZ, 1);
	struct pheap *ph;;
	int i;

	assert(threads <= MAX_THREADS);
	
	size_t mgmt_size = pheap_mgmt_size(HEAP_SZ);
	ph = pheap_init(malloc(mgmt_size),
			mgmt_size,
			heap,
			HEAP_SZ,
			false);

	for (i = 0; i < threads; i++)
		pthread_create(&th[i], 0, fib, ph);

	for (i = 0; i < threads; i++)
		pthread_join(th[i], NULL);

	free(heap);
	free(ph);
}

int main(int argc, char **argv)
{
    fib_test(1);
    fib_test(2);
    fib_test(4);
    fib_test(8);
    return 0;
}
