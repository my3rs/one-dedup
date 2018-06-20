#ifndef OPEN_DEDUP_DEDUP_H
#define OPEN_DEDUP_DEDUP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif



#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlog.h>       // log
#include <time.h>
#include <openssl/sha.h>
#include <stdbool.h>

#include "bplustree.h"
#include "rabin.h"

#include "private/errors.h"
#include "rabin.h"
#include "global_opts.h"

//#define SHA_DIGEST_LENGTH 48

#define SIZE ( 5ull * 1024ull * 1024ull * 1024ull)
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



enum {
    INVALID_PHY_OFFSET = -1,
};

// ===================================================
//               Tool Functions: Seek
// ===================================================

#define SEEK_TO_BUCKET(fd, i) \
    do { \
        if (gArgs()->MAP == BPTREE_MODE ) \
            lseek64((fd), (i)*sizeof(hash_bucket), SEEK_SET); \
        else if (g_args.MAP == SPACE_MODE) \
            lseek64((fd), SPACE_SIZE + (i)*sizeof(hash_bucket), SEEK_SET); \
    } while(0)

#define SEEK_TO_HASH_LOG(fd, i) \
    do { \
        if (gArgs()->MAP == BPTREE_MODE ) \
            lseek64((fd), HASH_INDEX_SIZE + (i) * sizeof(struct hash_log_entry), SEEK_SET); \
        else if (gArgs()->MAP == SPACE_MODE) \
            lseek64((fd), SPACE_SIZE + HASH_INDEX_SIZE + (i) * sizeof(struct hash_log_entry), SEEK_SET); \
    } while (0)

#define SEEK_TO_SPACE(fd, i) \
    do { \
        lseek64((fd), (i) * SPACE_LENGTH, SEEK_SET); \
    } while (0)

#define SEEK_TO_DATA_LOG(fd, offset) \
    do { \
        lseek64((fd), (offset), SEEK_SET); \
    } while(0)


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

struct g_args_t {
    int MAP;
    int hash_table_fd;

    int fd;
    int run_mode;
    zlog_category_t* write_block_category;
    zlog_category_t* log_error;
    struct bplus_tree *tree;
    struct data_log_free_list_node data_log_free_list;
};

struct last_request_t {
    unsigned char buffer[2 * 128 * 1024];
    uint  length;   // if length == 0, last_request is not available
};

#define BOLD                 "\e[1m"
#define NONE                 "\e[0m"


/* Forward declaration */
int read_one_block(void *buf, uint32_t len, uint64_t offset);
int write_cdc_block(void *buf, uint32_t len, uint64_t offset);
int dedup_write(const void *buf, uint32_t len, uint64_t offset);
int dedup_read(void *buf, uint32_t len, uint64_t offset);
void dedup_disc();
int dedup_flush();
int dedup_trim(uint64_t from, uint32_t len);
struct g_args_t* gArgs();
void set_data_log_offset(uint64_t offset);
void set_hash_log_offset(uint64_t index);




#endif //OPEN_DEDUP_DEDUP_H
