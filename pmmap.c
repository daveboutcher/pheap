#include <sys/mman.h>
#include "pheap.h"

void *pmmheap(size_t prefix, size_t len, struct pheap **ph)
{
	size_t mgmt_len = pheap_mgmt_size(len);

	/* Round up to a page boundary 
	 * TODO: use proper page size getter 
	 */
	mgmt_len = (mgmt_len + 4095UL) & (~4095UL);
	prefix   = (prefix   + 4095UL) & (~4095UL);
	len      = (len      + 4095UL) & (~4095UL);

	void *result = mmap(NULL, 
			    prefix + mgmt_len + len + 4096,
			    PROT_EXEC | PROT_WRITE | PROT_EXEC, 
			    MAP_PRIVATE | MAP_ANONYMOUS,
			    -1, 0);
	if (result == MAP_FAILED) {
		perror("pmmheap initialization mmap");
		return NULL;
	}

	/* Mprotect the page following the prefix */
	if (mprotect(result + prefix,
		     4096, PROT_NONE)) {
		perror("mprotecting the guard page following the prefix");
	}

	*ph = pheap_init(result + prefix + 4096,
			 mgmt_len,
			 result + prefix + mgmt_len,
			 len,
			 false);
	
	return result;
}
