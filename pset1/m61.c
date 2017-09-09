#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <limits.h>

struct m61_statistics global = {0, 0, 0, 0, 0, 0, NULL, NULL};

struct metadata {
    size_t size;
};

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    if (sz == 0) return NULL;

    void* ptr;
    if (sz < 0 || sz + sizeof(struct metadata) <= sz || !(ptr = (base_malloc(sz + sizeof(struct metadata))))) {
        global.nfail++;
        global.fail_size += sz;
        return NULL;
    }

    ((struct metadata*) ptr)->size = sz;
    global.nactive++;
    global.active_size += sz;
    global.ntotal++;
    global.total_size += sz;
    if (global.heap_min == NULL || ptr + sizeof(struct metadata) < global.heap_min)
        global.heap_min = ptr + sizeof(struct metadata);
    if (global.heap_max == NULL || ptr + sizeof(struct metadata) + sz > global.heap_max)
        global.heap_max = ptr + sizeof(struct metadata) + sz;

    return ptr + sizeof(struct metadata);
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    if (ptr) { 
        global.nactive--;
        global.active_size -= ((struct metadata*) (ptr - sizeof(struct metadata)))->size;
        base_free(ptr - sizeof(struct metadata));
    }
}


/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void* ptr, size_t sz, const char* file, int line) {
    void* new_ptr = NULL;
    if (ptr == NULL) return m61_malloc(sz, file, line);
    if (sz == 0) {
        m61_free(ptr, file, line);
        return NULL;
    }
    if (sz) {
        new_ptr = m61_malloc(sz, file, line);
    }
    if (ptr && new_ptr) {
        size_t ptr_size = ((struct metadata*) (ptr - sizeof(struct metadata)))->size;
        int size_to_copy = (sz <= ptr_size) ? sz : ptr_size;
        memcpy(new_ptr, ptr, size_to_copy);
    }
    m61_free(ptr, file, line);
    return new_ptr;
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, int line) {
    if (sz == 0) return NULL;
    void* ptr = m61_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    *stats = global;
}


/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void) {
    // Your code here.
}
