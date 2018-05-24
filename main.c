#define _GNU_SOURCE
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <signal.h>
#include <zlog.h>       // log
#include "dedup.h"
#include "private/errors.h"
//#include "buse.h"
#include "buse_single.h"
#include <stdbool.h>
#include <time.h>
#include "bplustree.h"
#include "rabin.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))



// ===================================================
//                  Global Variables
// ===================================================

#define TREE_FILENAME "./tree"
#define HASH_FILENAME "./hash"
#define IMAGE_FILENAME "./image"
#define NBD_DEVICE "/dev/nbd0"

struct g_args_t {
    int MAP;
    int hash_table_fd;

    int fd;
    int run_mode;
    zlog_category_t* write_block_category;
    zlog_category_t* log_error;
    struct bplus_tree *tree;
    struct data_log_free_list_node data_log_free_list;
    bool cmd_debug;
    bool rabin_debug;
    bool read_debug;
    bool write_debug;
};
struct g_args_t g_args;

static void *zeros;
static struct hash_log_entry *cache;
static uint64_t hash_log_free_list;
static uint64_t data_log_free_offset;
static uint64_t skip_len;

enum mode{
    INIT_MODE = 0,
    RUN_MODE  = 1,
    BPTREE_MODE = 2,
    SPACE_MODE =3,
};

struct last_request_t {
    unsigned char buffer[2 * 128 * 1024];
    uint  length;   // if length == 0, last_request is not available
};

struct last_request_t last_request;

clock_t prog_begin, prog_end;
clock_t write_clock = 0, detect_clock = 0;
clock_t bs_read = 0;
clock_t bs_write = 0;


// ===================================================
//               Tool Functions: Seek
// ===================================================

#define SEEK_TO_BUCKET(fd, i) \
    do { \
        if (g_args.MAP == BPTREE_MODE ) \
            lseek64((fd), (i)*sizeof(hash_bucket), SEEK_SET); \
        else if (g_args.MAP == SPACE_MODE) \
            lseek64((fd), SPACE_SIZE + (i)*sizeof(hash_bucket), SEEK_SET); \
    } while(0)

#define SEEK_TO_HASH_LOG(fd, i) \
    do { \
        if (g_args.MAP == BPTREE_MODE ) \
            lseek64((fd), HASH_INDEX_SIZE + (i) * sizeof(struct hash_log_entry), SEEK_SET); \
        else if (g_args.MAP == SPACE_MODE) \
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


static void fingerprint_to_str(char *dest, char *src)
{
    for (int i=0; i<SHA_DIGEST_LENGTH; i++)
        sprintf(&dest[i*2], "%02x", (unsigned int)src[i]);

}

// ===================================================
//                  Function Defines
// ===================================================


static void usage()
{
    fprintf(stderr, "Options:\n\n");
    fprintf(stderr, BOLD"    -h, --help\n" NONE "\tdisplay the help infomation\n\n");
    fprintf(stderr, BOLD"    -i, --init\n" NONE "\tspecify the nbd device and init\n\n");
    fprintf(stderr, BOLD"    -a, --hash-file\n" NONE "\tspecify the hash file\n\n");
    fprintf(stderr, BOLD"    -p, --physical-device\n" NONE "\tspecify the physical device or file\n\n");
    fprintf(stderr, BOLD"    -s, --space\n" NONE "\tspace mapping mode\n\n");
    fprintf(stderr, BOLD"    -b, --btree\n" NONE "\tb+tree mapping mode and specify b+tree db file\n\n");
}

static void print_debug_info()
{
    fprintf(stderr, "SIZE is %lluM\n", SIZE/1024/1024);
    fprintf(stderr, "HASH_INDEX_SIZE is %llu\n", HASH_INDEX_SIZE);
    fprintf(stderr, "HASH_LOG_SIZE is %llu\n", HASH_LOG_SIZE);
}


static int fingerprint_is_zero(const char *fingerprint)
{
    int i;
    for (i = 0; i < FINGERPRINT_SIZE; i++) {
        if (fingerprint[i])
            return 0;
    }
    return 1;
}



static int hash_get_space(uint64_t offset, hash_space *space)
{
    uint64_t space_n = offset / SPACE_LENGTH;
    SEEK_TO_SPACE(g_args.hash_table_fd, space_n);
    ssize_t err = read(g_args.hash_table_fd, space, sizeof(struct block_map_entry) * ENTRIES_PER_SPACE);
    assert(err == sizeof(struct block_map_entry) * ENTRIES_PER_SPACE);

    return 0;
}


static int hash_put_space(uint64_t offset, hash_space *space)
{
    uint64_t space_n = offset / SPACE_LENGTH;
    SEEK_TO_SPACE(g_args.hash_table_fd, space_n);
    ssize_t err = write(g_args.hash_table_fd, space, sizeof(struct block_map_entry) * ENTRIES_PER_SPACE);
    assert(err == sizeof(struct block_map_entry) * ENTRIES_PER_SPACE);

    return 0;
}

static int hash_space_insert(uint64_t offset, struct block_map_entry ble)
{
    hash_space space;

    hash_get_space(offset, &space);

    for (int i = 0; i < ENTRIES_PER_SPACE; i ++) {
        if (space[i].length == 0) {
            /// We have found an empty slot.
            memcpy(space + i, &block_map_entry, sizeof(struct block_map_entry));
            hash_put_space(offset, &space);
            return 0;
        }
    }

    /// Failed to find a slot.
    assert(0);
}


/**
 * Return the bucket which contains the given fingerprint
 */
static int hash_index_get_bucket(char *hash, hash_bucket *bucket)
{
    /* We don't need to look at the entire hash, just the last few bytes. */
    int32_t *hash_tail = (int32_t *)(hash + FINGERPRINT_SIZE - sizeof(int32_t));
    uint64_t bucket_index = *hash_tail % NBUCKETS;
    SEEK_TO_BUCKET(g_args.hash_table_fd, bucket_index);
    ssize_t err = read(g_args.hash_table_fd, bucket,
            sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);
    assert(err == sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);

    return 0;
}

static int hash_index_put_bucket(char *hash, hash_bucket *bucket)
{
    /* We don't need to look at the entire hash, just the last few bytes. */
    int32_t *hash_tail = (int32_t *)(hash + FINGERPRINT_SIZE - sizeof(int32_t));
    uint64_t bucket_index = *hash_tail % NBUCKETS;
    SEEK_TO_BUCKET(g_args.hash_table_fd, bucket_index);
    ssize_t err = write(g_args.hash_table_fd, bucket,
            sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);
    assert(err == sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);

    return 0;
}

static int hash_index_insert(char *hash, uint64_t hash_log_address)
{
    hash_bucket bucket;
    hash_index_get_bucket(hash, &bucket);

    for (int i = 0; i < ENTRIES_PER_BUCKET; i++)
        if (bucket[i].hash_log_address == 0) {
            /* We have found an empty slot. */
            memcpy(bucket[i].hash, hash, FINGERPRINT_SIZE);
            bucket[i].hash_log_address = hash_log_address;
            hash_index_put_bucket(hash, &bucket);
            return 0;
        }

    // Debug info. If we get to here, error occurs.
    char str_fp[SHA_DIGEST_LENGTH*2+1];
    fingerprint_to_str(str_fp, hash);
    printf("[HASH INDEX INSERT] | Debug | Hash: %s\n", str_fp);

    char log_line[1024*1024];
    sprintf(log_line, "[HASH INDEX INSERT] | Debug | Hash: %s", str_fp);
    zlog_info(g_args.log_error, log_line);

    /* We failed to find a slot. In the future it would be nice to have a more
     * sophisticated hash table that resolves collisions better. But for now we
     * just give up. */
    assert(0);
}

/**
 * Search the hash log address of given hash
 */
static uint64_t hash_index_lookup(char *hash)
{
    hash_bucket bucket;
    hash_index_get_bucket(hash, &bucket);

    for (int i = 0; i < ENTRIES_PER_BUCKET; i++)
        if (!memcmp(bucket[i].hash, hash, FINGERPRINT_SIZE))
            return bucket[i].hash_log_address;
    return -1;
}


/**
 * Given a fingerprint, remove the corresponding hash_index_entry in HASH INDEX TABLE
 */
static int hash_index_remove(char *hash)
{
    hash_bucket bucket;
    hash_index_get_bucket(hash, &bucket);

    for (int i = 0; i < ENTRIES_PER_BUCKET; i++)
        if (!memcmp(bucket[i].hash, hash, FINGERPRINT_SIZE)) {
            memset(bucket + i, 0, sizeof(struct hash_index_entry));
            hash_index_put_bucket(hash, &bucket);
            return 0;
        }

    return -1;
}

static uint64_t hash_log_new()
{
    uint64_t new_block = hash_log_free_list;
    SEEK_TO_HASH_LOG(g_args.hash_table_fd, new_block);
    ssize_t err = read(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));
    return new_block;
}

/**
 * Free a hash_log_entry and change hash_log_free_list to it
 */
static int hash_log_free(uint64_t hash_log_address)
{
    SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
    ssize_t err = write(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));
    hash_log_free_list = hash_log_address;

    return 0;
}

/**
 * Get a free data block in term of specified blocksize
 */
static uint64_t physical_block_new(uint64_t blocksize)
{
//    int err;
//    uint64_t offset;
//
//    struct data_log_free_list_node node;
//    node = g_args.data_log_free_list;
//
//
//    while (node.size < blocksize && node.next != INVALID_OFFSET) {
//        seek_to_data_log(fd, node.next);
//        err = read(fd, &node, sizeof(struct data_log_free_list_node));
//        assert(err == sizeof(struct data_log_free_list_node));
//
//        // Next Fit algorithm
//        if (node.size >= blocksize) {
//            break;
//        }
//    }
//
//    // The size of the NODE we get is gt blocksize, so
//    // we just
//    offset = node.offset;
//    node.offset += blocksize;
//    node.size -= blocksize;
//
//    return offset;

    int err;
    uint64_t offset = data_log_free_offset;
    data_log_free_offset += blocksize;
    return offset;
}



static int physical_block_free(uint64_t offest, uint64_t size)
{
    fprintf(stderr, "try to free a block\n");
    ssize_t err;
    SEEK_TO_DATA_LOG(g_args.fd, offest);
    struct data_log_free_list_node prev = g_args.data_log_free_list;
    while(prev.next != INVALID_OFFSET) {
        SEEK_TO_DATA_LOG(g_args.fd, prev.next);
        err = read(g_args.fd, &prev, sizeof(struct data_log_free_list_node));
        assert(err == sizeof(struct data_log_free_list_node));
    }

    struct data_log_free_list_node node;
    node.next = INVALID_OFFSET;
    node.offset = offest;
    node.size = size;

    prev.next = node.offset;
    SEEK_TO_DATA_LOG(g_args.fd, prev.offset);
    err = write(g_args.fd, &prev, sizeof(struct data_log_free_list_node));
    assert(err == sizeof(struct data_log_free_list_node));

    SEEK_TO_DATA_LOG(g_args.fd, node.offset);
    err = write(g_args.fd, &node, sizeof(struct data_log_free_list_node));
    assert(err == sizeof(struct data_log_free_list_node));

    return 0;
}


/**
 * Return the index where the given fingerprint SHOULD be found in
 * he cache
 */
static u_int32_t get_cache_index(const char *fingerprint)
{
    /* It doesn't actually matter which bits we choose, as long as we are
     * consistent. So let's treat the first four bytes as an integer and take
     * the lower bits of that. */
    u_int32_t mask = (1 << CACHE_SIZE) - 1;
    u_int32_t result = ((u_int32_t *)fingerprint)[0] & mask;
    assert(result < mask);
    return result;
}

/**
 * Return a HAST LOG TABLE entry in terms of given fingerprint
 */
static struct hash_log_entry lookup_fingerprint(char *fingerprint)
{

    ssize_t err;

    // Search in CACHE
    u_int32_t index = get_cache_index(fingerprint);
    if (!memcmp(fingerprint, cache[index].fingerprint, FINGERPRINT_SIZE)) {
        // Awesome, this fingerprint is already cached, so we are good to go.
        return cache[index];
    }

    // Didn't hit in cache, so we have to look on disk.
    uint64_t hash_log_address = hash_index_lookup(fingerprint);
    assert(hash_log_address != (uint64_t)-1);



    // ==========================================
    //               update cache
    // ==========================================
    /* Now let's look up everything in the 4K block containing the hash log
     * entry we want. This way we can cache it all for later. */
    hash_log_address -= hash_log_address % HASH_LOG_BLOCK_SIZE;
    SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
    struct hash_log_entry h;

    for (unsigned i = 0; i < HASH_LOG_BLOCK_SIZE/sizeof(struct hash_log_entry); i++) {
        err = read(g_args.hash_table_fd, &h, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));

        u_int32_t j = get_cache_index(h.fingerprint);
        memcpy(cache + j, &h, FINGERPRINT_SIZE);
    }

    /* Now we should have looked up the fingerprint we wanted, along with a
     * bunch of others. */

    err = memcmp(fingerprint, cache[index].fingerprint, FINGERPRINT_SIZE);
    if (err != 0) {
        hash_log_address = hash_index_lookup(fingerprint);
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
        struct hash_log_entry h_tmp;
        err = read(g_args.hash_table_fd, &h_tmp, sizeof(struct hash_log_entry));
//        fprintf(stderr, "hash log entry: %02x\nfingerprint: %02x\n", h_tmp.fingerprint, fingerprint);
    }

    return cache[index];
}

/**
 * Decrease the ref_count of a physical block
 */
static int decrement_refcount(char *fingerprint)
{
    // todo: decrement_refcount
    struct hash_log_entry hle;
    uint64_t hash_log_address = hash_index_lookup(fingerprint);
    SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
    ssize_t err = read(g_args.hash_table_fd, &hle, sizeof(struct hash_log_entry));
    assert(err == sizeof(struct hash_log_entry));

    if (hle.ref_count > 1) {
        hle.ref_count--;
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
        err = write(g_args.hash_table_fd, &hle, sizeof(struct hash_log_entry));
    } else {
        /* The ref_count is now zero, so we need to do some garbage collection
         * here. */
        hash_index_remove(fingerprint);
        physical_block_free(hle.data_log_offset, hle.block_size);
        hash_log_free(hash_log_address);
    }

    return 0;
}

// offset: nbd
static int write_one_block(const void *buf, uint32_t block_size, uint64_t offset)
{
    char log_line[1024*1024];
    clock_t detect_begin, detect_end;
    clock_t write_begin, write_end;

    assert(block_size > 0);

    ssize_t err;
    char fingerprint[FINGERPRINT_SIZE];
    struct block_map_entry bm_entry;

    detect_begin = clock();
    /* Compute the fingerprint of the new block */
    SHA1(buf, block_size, (unsigned char *) fingerprint);

    if (fingerprint_is_zero(fingerprint)) {
        zlog_info(g_args.log_error,
                  "[write one block] | debug | fingerprint is zero");
    }

    /* Update b+tree anyway, even though this fingerprint has already been stored */
    bm_entry.start = offset;
    bm_entry.length = block_size;
    memcpy(bm_entry.fingerprit, fingerprint, FINGERPRINT_SIZE);

    clock_t bs_start = clock();
    if (g_args.MAP == BPTREE_MODE)
        bplus_tree_put(g_args.tree, offset, bm_entry);
    else if (g_args.MAP == SPACE_MODE)
        hash_space_insert(offset, bm_entry);
    clock_t bs_end = clock();

    bs_write += (bs_end - bs_start);
    fprintf(stderr, "[TIMER] | bs write: %.3f\n", (float)bs_write/CLOCKS_PER_SEC);

    uint64_t hash_log_address;
    struct hash_log_entry hl_entry;


    /* See if this fingerprint is already stored in HASH_LOG. */
    hash_log_address = hash_index_lookup(fingerprint);
    detect_end = clock();
    detect_clock += (detect_end - detect_begin);
    if (hash_log_address == (uint64_t) -1) {
        detect_begin = clock();
        /* This block is new. */
        sprintf(log_line, "[NEW] | len: %u, offset: %lu", block_size, offset);
        printf("%s\n", log_line);
        zlog_info(g_args.write_block_category, log_line);

        memcpy(&(hl_entry.fingerprint), fingerprint, FINGERPRINT_SIZE);
        hl_entry.data_log_offset = physical_block_new(block_size);
        hl_entry.ref_count = 1;
        hl_entry.block_size = block_size;

        hash_log_address = hash_log_new();
        /* Update hash index */
        hash_index_insert(fingerprint, hash_log_address);
        /* Update hash log */
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
        err = write(g_args.hash_table_fd, &hl_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
        detect_end = clock();
        detect_clock += (detect_end - detect_begin);

        write_begin = clock();
        // fixme: deleted real write operation
        /* Write data block */
//        SEEK_TO_DATA_LOG(g_args.fd, hl_entry.data_log_offset);
//        err = write(g_args.fd, buf, block_size);
//        assert(err == block_size);
        if (g_args.write_debug)
            printf("[WRITE NEW BLOCK] | size: %d, offset %lu\n", block_size, hl_entry.data_log_offset);
        write_end = clock();
        write_clock += (write_end - write_begin);
    } else {
        detect_begin = clock();
        /// This block has already been stored. We just need to increase the refcount.
        sprintf(log_line, "[REDUNDANT] | len: %u, offset: %lu", block_size, offset);
        printf("%s\n", log_line);
        zlog_info(g_args.write_block_category, log_line);
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
        err = read(g_args.hash_table_fd, &hl_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
        hl_entry.ref_count += 1;
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, hash_log_address);
        err = write(g_args.hash_table_fd, &hl_entry, sizeof(struct hash_log_entry));
        if (g_args.write_debug)
            printf("[WRITE OLD BLOCK]\n");
        assert(err == sizeof(struct hash_log_entry));
        detect_end = clock();
        detect_clock += (detect_end - detect_begin);
    }
    return 0;
}

static int dedup_write(const void *buf, uint32_t len, uint64_t offset)
{
    printf("Write time: %f s, Detect time: %f s\n",
           (float)write_clock/CLOCKS_PER_SEC, (float)detect_clock/CLOCKS_PER_SEC);

    int err;
    void *new_buf;
    struct rabin_t *hash = rabin_init();
    uint8_t *ptr;
    int remaining;
    clock_t detect_begin, detect_end;

    if (last_request.length) {
        new_buf = malloc(last_request.length + len);
        memcpy(new_buf, last_request.buffer, last_request.length);
        memcpy(new_buf+last_request.length, buf, len);
        len = last_request.length + len;
        last_request.length = 0;
    } else {
        new_buf = (uint8_t *)buf;
    }
    ptr = new_buf;

    /// In this situation, we get read request when the last_request is not empty.
    if (len == 0)
        return 0;

    if (len < MAX_BLOCK_SIZE) {
        memcpy(last_request.buffer, new_buf, len);
        last_request.length = len;
        return 0;
    }




    while(1) {
        detect_begin = clock();
        remaining = rabin_next_chunk(hash, ptr, len, &skip_len);

        len -= remaining;
        ptr += remaining;

        /* Print rabin debug information */
        if(g_args.rabin_debug)
            printf("[RABIN] start: %lu, len: %u fingerprint: %016llx\n",
                   last_chunk.start, last_chunk.length, (long long unsigned int)last_chunk.cut_fingerprint);

        /* Write a block */

        detect_end = clock();
        detect_clock += (detect_end - detect_begin);
        err = write_one_block(new_buf+last_chunk.start, last_chunk.length, offset+last_chunk.start);
        assert(err == 0);

        if (len < MAX_BLOCK_SIZE) {
            break;
        }
    }


    if (remaining == -1 && rabin_finalize(hash) != NULL) {
        detect_begin = clock();
        last_request.length = 0;
        if (g_args.rabin_debug)
            printf("[LAST] | %u %016llx\n",
                   last_chunk.length,
                   (long long unsigned int)last_chunk.cut_fingerprint);


        err = write_one_block(new_buf+last_chunk.start, last_chunk.length, offset+last_chunk.start);
        assert(err == 0);
        detect_end = clock();
        detect_clock += (detect_end - detect_begin);
        return 0;
    }

    if (len >= 0) {
        memcpy(last_request.buffer, ptr, len);
        last_request.length = len;
        return 0;
    }
    printf("skip: %.3f\n", skip_len/1024.0f/1024.0f);
    return 0;
}



static int read_one_block(void *buf, uint32_t len, uint64_t offset)
{
    int err;
    SEEK_TO_DATA_LOG(g_args.fd, offset);
    err = read(g_args.fd, buf, len);
    assert(err == len);
    return 0;
}

static int dedup_read(void *buf, uint32_t len, uint64_t offset)
{

    if (last_request.length != 0) {
        dedup_write(NULL, 0, 0);
    }

    if (g_args.read_debug)
        fprintf(stderr, "[HANDLE READ REQUEST] | len: %u offset: %lu\n", len, offset);

    char *bufi = buf;
    struct block_map_entry bmap_entry;
    struct hash_log_entry tmp_entry;

    clock_t bs_start = clock();
    if (g_args.MAP == BPTREE_MODE)
        bmap_entry = bplus_tree_get_fuzzy(g_args.tree, offset);
    else if (g_args.MAP == SPACE_MODE) {
        hash_space space;
        hash_get_space(offset, &space);
        for (int i = 0; i < ENTRIES_PER_SPACE; i ++) {
            if (space[i].start < offset && space[i].start + space[i].length > offset) {
                bmap_entry = space[i];
            }
        }
    }
    clock_t bs_end = clock();
    bs_read += (bs_end - bs_start);

    struct hash_log_entry hle = lookup_fingerprint(bmap_entry.fingerprit);


    return 0;

    /* If we don't BEGIN on a block boundary */
    if (offset != bmap_entry.start) {
        if(bmap_entry.length == 0) {
            memset(bufi, 0, len);
            return 0;
        }
        uint32_t read_size = bmap_entry.length - (offset - bmap_entry.start);
        assert(read_size >= 0);


        tmp_entry = lookup_fingerprint(bmap_entry.fingerprit);


        if (g_args.read_debug) {
            printf("[DEDUP READ 1] | bmap start: %lu bmap end: %lu\n",
                   bmap_entry.start, bmap_entry.start + bmap_entry.length);
//            printf("[DEDUP READ 2] | len: %u offset: %lu\n", read_size, offset);
        }
        read_one_block(bufi, read_size, tmp_entry.data_log_offset);
        bufi += read_size;
        len -= read_size;
        offset += read_size;
    }

    while (len > 0 ) {
        bmap_entry = bplus_tree_get_fuzzy(g_args.tree, offset);
        if (len < bmap_entry.length)
            break;
        if (fingerprint_is_zero(bmap_entry.fingerprit)) {
            memset(bufi, 0, len);
            len = 0;
            continue;
        }
        assert(bmap_entry.length != 0);
        if (bmap_entry.length == 0) {
            printf("error!\n");
            memset(bufi, 0, len);
            return 0;
        }
        // We read a complete block
        if (g_args.read_debug) {
            printf("[DEDUP READ] | len: %u offset: %lu\n", bmap_entry.length, offset);
        }
        tmp_entry = lookup_fingerprint(bmap_entry.fingerprit);
        read_one_block(bufi, bmap_entry.length, tmp_entry.data_log_offset);
        bufi += bmap_entry.length;
        len -= bmap_entry.length;
        offset += bmap_entry.length;
    }
    /* Now we get to the last block, it may be not a complete block*/
    if (len != 0) {
        read_one_block(bufi, len, offset);
    }

    return 0;
}




/* Called upon receipt of a disconnect request. We need to make sure everything
 * is written to stable storage before this function returns. */
static int dedup_disc()
{
    prog_end = clock();
    printf("Run time: %.2f s\n", (float)(prog_end - prog_begin)/CLOCKS_PER_SEC);
    printf("Write time: %f s, Detect time: %f s\n",
           (float)write_clock/CLOCKS_PER_SEC, (float)detect_clock/CLOCKS_PER_SEC);

    ssize_t ret;

    fprintf(stderr, "Just received a disconnect request.\n");
    SEEK_TO_HASH_LOG(g_args.hash_table_fd, 0);
    ret = write(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
    assert(ret == sizeof(uint64_t));


//    seek_to_data_log_free_list(fd);
//    ret = write(fd, &(g_args.data_log_free_list), sizeof(struct data_log_free_list_node));
    assert(ret == sizeof(struct data_log_free_list_node));

    exit(0);
}

static int dedup_flush()
{
    /* TODO: This is about nbd. */
    fprintf(stderr, "Just received a flush request.\n");
    return 0;
}

static int dedup_trim(uint64_t from, uint32_t len)
{
    /* TODO: This is about nbd. */
    (void) from;
    (void) len;
    return 0;
}


static int init()
{
    uint64_t i;
    ssize_t err;


    if (access("./image", F_OK) != -1) {
        if (remove("./image") == 0) {
            printf("Removed existed file %s\n", "./image");
        } else {
            perror("Remove image file");
        }
    }

    if (access(TREE_FILENAME, F_OK) != -1) {
        if (remove(TREE_FILENAME) == 0) {
            printf("Removed existed file %s\n", TREE_FILENAME);
        } else {
            perror("Remove B+Tree db file");
        }
    }
    char tree_boot_filename[255];
    sprintf(tree_boot_filename, "%s.boot", TREE_FILENAME);
    if (access(tree_boot_filename, F_OK) != -1) {
        if (remove(tree_boot_filename) == 0) {
            printf("Removed existed file %s\n", tree_boot_filename);
        } else {
            perror("Remove B+Tree boot file");
        }
    }


    /* We now initialize the hash log and data log. These start out empty, so we
     * put everything in the free list. It might be more efficient to stage this
     * in memory and then write it out in larger blocks. But the Linux buffer
     * cache will probably take care of that anyway for now. */
    for (i = 1; i <= N_BLOCKS; i++) {
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, i - 1);
        err = write(g_args.hash_table_fd, &i, sizeof(uint64_t));
        assert(err == sizeof(uint64_t));
    }

    /* We use a list to manage free data log */
//    g_args.data_log_free_list.offset = sizeof(struct data_log_free_list_node);
//    g_args.data_log_free_list.next = INVALID_OFFSET;
//    g_args.data_log_free_list.size = SIZE;
//
//    seek_to_data_log_free_list(fd);
//    err = write(fd, &(g_args.data_log_free_list), sizeof(struct data_log_free_list_node));
//    assert(err == sizeof(struct data_log_free_list_node));
    return 0;
}


void open_file(void)
{
    struct stat phy_file_stat;
    stat(IMAGE_FILENAME, &phy_file_stat);
    if (S_ISBLK(phy_file_stat.st_mode)){
        /* specified a block device */
        g_args.fd = open64(IMAGE_FILENAME, O_RDWR|O_DIRECT|O_LARGEFILE);
    } else {
        /* FIXME: we should only handle physical device or regular file(not created) */
        g_args.fd = open64(IMAGE_FILENAME, O_RDWR|O_CREAT|O_LARGEFILE);
    }
    assert(g_args.fd != -1);

    g_args.hash_table_fd = open64(HASH_FILENAME, O_CREAT|O_RDWR|O_LARGEFILE, 0644);
    assert(g_args.hash_table_fd != -1);

}


void parse_command_line(int argc, char *argv[])
{
    /* command line args */
    const char *opt_string = "i:n:p:h:s:b";
    const struct option long_opts[] = {
            {"init", required_argument, NULL, 'i'},
            {"nbd", required_argument, NULL, 'n'},
            {"help", no_argument, NULL, 'h'},
            {"space", no_argument, NULL, 's'},
            {"btree", no_argument, NULL, 'b'},
            {NULL, 0, NULL, NULL},
    };

    // default opts
    g_args.MAP = BPTREE_MODE;

    int opt = getopt_long(argc, argv, opt_string, long_opts, NULL);
    while( opt != -1 ) {
        switch(opt) {
            case 'i':   // init mode
                g_args.run_mode = INIT_MODE;
                break;
            case 'n':   // nbd device
                g_args.run_mode = RUN_MODE;
                break;
            case 'b':   // b+tree mode
                g_args.MAP = BPTREE_MODE;
                break;
            case 's':
                g_args.MAP = SPACE_MODE;
                break;
            case 'h':   // help
            default:
                usage();
                break;
        }
        opt = getopt_long(argc, argv, opt_string, long_opts, NULL);
    }
}

/**
 * Print cmd args
 */
static void print_cmd_args()
{
    printf("========== cmd opts ==============\n");
    printf("nbd device: %s\n", NBD_DEVICE);
    printf("physical device: %s\n", IMAGE_FILENAME);
    switch (g_args.run_mode) {
        case RUN_MODE:
            printf("run mode: normal\n");
            break;
        case INIT_MODE:
            printf("run mode: init\n");
            break;
        default:
            printf("run mode: invalid\n");
            break;
    }

    printf("data free list offset: %lu\n", g_args.data_log_free_list.offset);
    printf("data free list size: %lu\n", g_args.data_log_free_list.size);
    printf("data free list next: %lu\n", g_args.data_log_free_list.next);
    printf("===================================\n");
}


static void default_settings(void)
{
    g_args.cmd_debug = false;
    g_args.rabin_debug = false;
    g_args.read_debug = false;
    g_args.write_debug = false;
}


/**
 * Main entry
 */
int main(int argc, char *argv[])
{
    skip_len = 0;
    prog_begin = clock();
    ssize_t err;

    default_settings();
    /* First, we parse the cmd line */
    parse_command_line(argc, argv);

    if (g_args.MAP == BPTREE_MODE) {
        g_args.tree = bplus_tree_init(TREE_FILENAME, 4096);
    }

    open_file();

    if (g_args.cmd_debug) {
        print_debug_info();
        print_cmd_args();
    }

    ////////////////////////////////////////////////
    ////////////         INIT MODE        //////////
    ////////////////////////////////////////////////
    if ( g_args.run_mode == INIT_MODE ) {
        fprintf(stdout, "Performing Initialization!\n");
        init();
        bplus_tree_deinit(g_args.tree);
        print_debug_info();
        return 0;
    ////////////////////////////////////////////////
    ////////////        NORMAL MODE       //////////
    ////////////////////////////////////////////////
    } else if ( g_args.run_mode == RUN_MODE ){
        /* By convention the first entry in the hash log is a pointer to the hash
         * log free list. Likewise for the data log. */
        SEEK_TO_HASH_LOG(g_args.hash_table_fd, 0);
        err = read(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
        assert( err == sizeof(uint64_t));

        data_log_free_offset = 0;

        /* Listen SIGINT signal */
        signal(SIGINT, &dedup_disc);

        struct buse_operations bop = {
                .read = dedup_read,
                .write = dedup_write,
                .disc = dedup_disc,
                .flush = dedup_flush,
                .trim = dedup_trim,
                .size = SIZE,
        };

        cache = calloc(1 << CACHE_SIZE, sizeof(struct hash_log_entry));

        /* Init zlog */
        err = zlog_init("../../config/zlog.conf");
        if(err) {
            fprintf(stderr, "zlog init failed\n");
            return -1;
        }
        g_args.write_block_category = zlog_get_category("write_block");
        if (!g_args.write_block_category) {
            fprintf(stderr, "get write_block_category failed\n");
            zlog_fini();
            return -2;
        }
        g_args.log_error = zlog_get_category("error");
        if (!g_args.log_error) {
            fprintf(stderr, "get log_error failed\n");
            zlog_fini();
            return -2;
        }
        last_request.length = 0;
        buse_main(IMAGE_FILENAME, &bop, NULL);
        free(cache);
        zlog_fini();
        if (g_args.MAP == BPTREE_MODE)
            bplus_tree_deinit(g_args.tree);
        return 0;
    }
}
