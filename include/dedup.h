#ifndef OPEN_DEDUP_DEDUP_H
#define OPEN_DEDUP_DEDUP_H

#include <stdint.h>
#include "rabin.h"


#define SIZE ( 8ull * 1024ull * 1024ull * 1024ull)
#define HASH_LOG_BLOCK_SIZE ( 4 * 1024 )
#define PHY_BLOCK_MAX_SIZE MIN_BLOCK_SIZE       // rabin
#define PHY_BLOCK_MIN_SIZE MIN_BLOCK_SIZE       // rabin
/* Virtual block size should be the EXpectations of the cdc block */
#define EX_CDC_BLOCK_SIZE (30 * 1024)
#define VIR_BLOCK_SIZE EX_CDC_BLOCK_SIZE

#define FINGERPRINT_SIZE 20

/* We advertise twice as many virtual blocks as we have physical blocks. */
#define NPHYS_BLOCKS (SIZE / VIR_BLOCK_SIZE)
#define NVIRT_BLOCKS (2 * NPHYS_BLOCKS)

/* Main on-disk data structures: block map, hash index, and hash log. */
#define ENTRIES_PER_BUCKET 16
#define NBUCKETS NVIRT_BLOCKS
#define HASH_INDEX_SIZE \
    (ENTRIES_PER_BUCKET * NBUCKETS * sizeof(struct hash_index_entry))
#define HASH_LOG_SIZE (NPHYS_BLOCKS * sizeof(struct hash_log_entry))


/* 可用的数据区域大小 */
#define DATA_SIZE_BTREE \
    (SIZE - HASH_INDEX_SIZE - HASH_LOG_SIZE - sizeof(struct data_log_free_list_node))


/** Space Mapping Mode:
 * Space is an array of fingerprint which refers to a fixed range of nbd's field offset */
// space range: max block size
#define SPACE_RANGE MAX_BLOCK_SIZE
// every space contains (max_block_size/min_block_size) fingerprints
#define ENTRIES_PER_SPACE (MAX_BLOCK_SIZE/MIN_BLOCK_SIZE)
// space size
#define SPACE_SIZE (NVIRT_BLOCKS * ENTRIES_PER_SPACE * FINGERPRINT_SIZE)

/* The size of the fingerprint cache, described in terms of how many bits are
 * used to determine the location of a cache line. Here, we use the first 20
 * bits of the fingerprint, which allows us to store 1M entries, each 32B, for a
 * total cache that uses 32 MB of memory. */
#define CACHE_SIZE 20

/* Max length of each log line */
#define LOG_LINE_MAX_SIZE (1024 * 20)



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




//struct hash_log_entry {
//    char fingerprint[FINGERPRINT_SIZE];
//    uint32_t ref_count;
//    uint64_t pbn;
//};

/* 每个数据块对应一个指纹项 */
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



/* 向屏幕打印时的字体 */
#define BOLD                 "\e[1m"
#define NONE                 "\e[0m"


/* Forward declaration */
static int read_one_block(void *buf, uint32_t len, uint64_t offset);
static int write_cdc_block_btree(void *buf, uint32_t len, uint64_t offset);



#endif //OPEN_DEDUP_DEDUP_H
