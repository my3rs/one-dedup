#ifndef OPEN_DEDUP_DEDUP_H
#define OPEN_DEDUP_DEDUP_H

#include <stdint.h>
#include "rabin.h"

#define SHA_DIGEST_LENGTH 48

#define SIZE ( 18ull * 1024ull * 1024ull * 1024ull)
#define HASH_LOG_BLOCK_SIZE ( 4 * 1024 )
#define VIR_BLOCK_SIZE MAX_BLOCK_SIZE
#define FINGERPRINT_SIZE 20

#define N_BLOCKS (SIZE / (MIN_BLOCK_SIZE + MAX_BLOCK_SIZE) * 2)

/* Main on-disk data structures: block map, hash index, and hash log. */
#define ENTRIES_PER_BUCKET 16
#define NBUCKETS N_BLOCKS
#define HASH_INDEX_SIZE \
    (ENTRIES_PER_BUCKET * NBUCKETS * sizeof(struct hash_index_entry))
#define HASH_LOG_SIZE (N_BLOCKS * sizeof(struct hash_log_entry))
/// Space mode
#define ENTRIES_PER_SPACE ( MAX_BLOCK_SIZE / MIN_BLOCK_SIZE )
#define SPACE_LENGTH MAX_BLOCK_SIZE
#define N_SPACES N_BLOCKS
#define SPACE_SIZE ( SPACE_LENGTH * N_SPACES )

/* The size of the fingerprint cache, described in terms of how many bits are
 * used to determine the location of a cache line. Here, we use the first 20
 * bits of the fingerprint, which allows us to store 1M entries, each 32B, for a
 * total cache that uses 32 MB of memory. */
#define CACHE_SIZE 20

/* We use a free-list and next-fit algorithm to manage free data log */
struct data_log_free_list_node {
    uint64_t    offset;
    uint64_t    next;
    size_t      size;
};


struct hash_index_entry {
    char hash[FINGERPRINT_SIZE];
    uint64_t hash_log_address;
};

struct hash_log_entry {
    char        fingerprint[FINGERPRINT_SIZE];
    uint32_t    ref_count;
    uint64_t    data_log_offset;
    uint32_t    block_size;
};

typedef struct hash_index_entry hash_bucket[ENTRIES_PER_BUCKET];

struct block_map_entry {
    uint64_t    start;
    uint32_t    length;
    char        fingerprit[FINGERPRINT_SIZE];
} block_map_entry;

typedef struct block_map_entry hash_space[ENTRIES_PER_SPACE];

#define BOLD                 "\e[1m"
#define NONE                 "\e[0m"


/* Forward declaration */
static int read_one_block(void *buf, uint32_t len, uint64_t offset);
static int write_cdc_block(void *buf, uint32_t len, uint64_t offset);



#endif //OPEN_DEDUP_DEDUP_H
