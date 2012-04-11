#include <sys/mman.h>
#include "pheap.h"

struct pheap *pmmheap(void *start, size_t len)
{
	size_t mgmt_len = pheap_mgmt_size(len);
	
	void *result = mmap(start, 
			    len + mgmt_len, 
			    PROT_EXEC | PROT_WRITE | PROT_EXEC, 
			    MAP_PRIVATE | MAP_ANONYMOUS,
			    -1, 0);
	if (result == MAP_FAILED)
		return NULL;

	return result + len;
}
