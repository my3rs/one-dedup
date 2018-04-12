#define _GNU_SOURCE         // for O_DIRECT
#define _LARGEFILE64_SOURCE // for lseek64

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
#include "bplustree.h"
#include "rabin.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))



// ===================================================
//                  Global Variables
// ===================================================

struct g_args_t {
    char *hash_table_filename;
    int hash_table_fd;
    int fd;
    char *nbd_device_name;
    char *phy_device_name;
    int run_mode;
    int map_mode;
    zlog_category_t* write_block_category;
    struct bplus_tree *tree;
    struct data_log_free_list_node data_log_free_list;
    bool cmd_debug;
    bool rabin_debug;
    bool hash_debug;
};

struct g_args_t g_args;

static int fd;
static void *zeros;
static struct hash_log_entry *cache;
static uint64_t hash_log_free_list;
static uint64_t data_log_free_offset;

enum mode{
    INIT_MODE = 0,
    RUN_MODE  = 1,
    BTREE_MODE = 2,
    SPACE_MODE = 3,
};



// ===================================================
//               Tool Functions: Seek
// ===================================================

static int seek_to_bucket(int _fd, int  i)
{
    int err;

    if (g_args.hash_debug)
        printf("[SEEK TO BUCKET] | num: %d, offset %lu\n", i, i* sizeof(hash_bucket));

    if (g_args.map_mode == BTREE_MODE)

        err =  lseek64(_fd, i* sizeof(hash_bucket), SEEK_SET);
    else
        err = lseek64(_fd, SPACE_SIZE + (i)*sizeof(hash_bucket), SEEK_SET);

    assert(err != -1);

    return 0;
}

static int seek_to_hash_log(int _fd, uint64_t i)
{

    switch (g_args.map_mode) {
        case BTREE_MODE:
            lseek64(_fd, HASH_INDEX_SIZE + i* sizeof(struct hash_log_entry), SEEK_SET);
            return 0;
        case SPACE_MODE:
            lseek64(_fd, SPACE_SIZE + HASH_INDEX_SIZE + i* sizeof(struct hash_log_entry),
                    SEEK_SET);
            return 0;
    }

    return ERROR_INVALID_OFFSET;
}


static int seek_to_data_log_free_list(int _fd)
{
    int err;
    err = lseek64(_fd, 0, SEEK_SET);
    assert(err != -1);

    return 0;
}


static int seek_to_data_log(int _fd, uint64_t offset)
{
    int err;
//    printf("[seek to %lu]\n", offset);
    // We reserve the first 24 bytes for data log free list.
//    err = lseek64(_fd, sizeof(struct data_log_free_list_node) + offset, SEEK_SET);
    err = lseek64(_fd, offset, SEEK_SET);
    assert(err != -1);  // offset is negative or beyond the end of the file

    return 0;
}

static void sha1_fp_to_str(char *dest, unsigned char *src)
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
    fprintf(stderr, BOLD"    -s, --space\n" NONE "\tspace mapping\n\n");
    fprintf(stderr, BOLD"    -b, --btree\n" NONE "\tb+tree mapping\n\n");
}

static void print_debug_info()
{
    fprintf(stderr, "nbd device: %s\n", g_args.nbd_device_name);
    fprintf(stderr, "phy device: %s\n", g_args.phy_device_name);
    fprintf(stderr, "SIZE is %lluM\n", SIZE/1024/1024);
//    fprintf(stderr, "BLOCK_MAP_SIZE is %llu\n", BLOCK_MAP_SIZE);
    fprintf(stderr, "HASH_INDEX_SIZE is %llu\n", HASH_INDEX_SIZE);
    fprintf(stderr, "HASH_LOG_SIZE is %llu\n", HASH_LOG_SIZE);
    fprintf(stderr, "NPHYS_BLOCKS is %llu\n", NPHYS_BLOCKS);
    fprintf(stderr, "NVIRT_BLOCKS is %llu\n", NVIRT_BLOCKS);
}


static int fingerprint_is_zero(char *fingerprint)
{
    int i;

    for (i = 0; i < FINGERPRINT_SIZE; i++) {
        if (fingerprint[i])
            return 0;
    }

    return 1;
}

/**
 * Return the bucket which contains the given fingerprint
 */
static int hash_index_get_bucket(char *hash, hash_bucket *bucket)
{
    /* We don't need to look at the entire hash, just the last few bytes. */
    int32_t *hash_tail = (int32_t *)(hash + FINGERPRINT_SIZE - sizeof(int32_t));
    int bucket_index = *hash_tail % NBUCKETS;

//    printf("hash_tail: %u,NBUCKETS: %llu, index: %d\n", *hash_tail, NBUCKETS, bucket_index);

    seek_to_bucket(g_args.hash_table_fd, bucket_index);
    int err = read(g_args.hash_table_fd, bucket,
            sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);
    assert(err == sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);

    return 0;
}

static int hash_index_put_bucket(char *hash, hash_bucket *bucket)
{
    /* We don't need to look at the entire hash, just the last few bytes. */
    int32_t *hash_tail = (int32_t *)(hash + FINGERPRINT_SIZE - sizeof(int32_t));
    int bucket_index = *hash_tail % NBUCKETS;
    seek_to_bucket(g_args.hash_table_fd, bucket_index);
    int err = write(g_args.hash_table_fd, bucket,
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
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&str_fp[i*2], "%02x", (unsigned int)hash[i]);
    }
    printf("[HASH INDEX INSERT] | Debug | Hash: %s\n", str_fp);

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
    seek_to_hash_log(g_args.hash_table_fd, new_block);
    int err = read(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));


//    printf("[HASH LOG NEW] | DEBUG | free hash log address: %lu\n", new_block);
    return new_block;
}

/**
 * Free a hash_log_entry and change hash_log_free_list to it
 */
static int hash_log_free(uint64_t hash_log_address)
{
    seek_to_hash_log(g_args.hash_table_fd, hash_log_address);
    int err = write(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
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
    int err;
    seek_to_data_log(fd, offest);
    struct data_log_free_list_node prev = g_args.data_log_free_list;
    while(prev.next != INVALID_OFFSET) {
        seek_to_data_log(fd, prev.next);
        err = read(fd, &prev, sizeof(struct data_log_free_list_node));
        assert(err == sizeof(struct data_log_free_list_node));
    }

    struct data_log_free_list_node node;
    node.next = INVALID_OFFSET;
    node.offset = offest;
    node.size = size;

    prev.next = node.offset;
    seek_to_data_log(fd, prev.offset);
    err = write(fd, &prev, sizeof(struct data_log_free_list_node));
    assert(err == sizeof(struct data_log_free_list_node));

    seek_to_data_log(fd, node.offset);
    err = write(fd, &node, sizeof(struct data_log_free_list_node));
    assert(err == sizeof(struct data_log_free_list_node));

    return 0;
}


/**
 * Return the index where the given fingerprint SHOULD be found in
 * he cache
 */
static u_int32_t get_cache_index(char *fingerprint)
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

    int err;

    // Search in CACHE
    u_int32_t index = get_cache_index(fingerprint);
    if (!memcmp(fingerprint, cache[index].fingerprint, FINGERPRINT_SIZE)) {
        // Awesome, this fingerprint is already cached, so we are good to go.
        return cache[index];
    }

    // Didn't hit in cache, so we have to look on disk.
    uint64_t hash_log_address = hash_index_lookup(fingerprint);
    assert(hash_log_address != (uint64_t)-1);



    // todo: Optimize prefetch rules
    // ==========================================
    //               update cache
    // ==========================================
    /* Now let's look up everything in the 4K block containing the hash log
     * entry we want. This way we can cache it all for later. */
    // fixme
    hash_log_address -= hash_log_address % HASH_LOG_BLOCK_SIZE;
    seek_to_hash_log(fd, hash_log_address);
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
        seek_to_hash_log(fd, hash_log_address);
        struct hash_log_entry h_tmp;
        err = read(g_args.hash_table_fd, &h_tmp, sizeof(struct hash_log_entry));
        fprintf(stderr, "hash log entry: %02x\nfingerprint: %02x\n", h_tmp.fingerprint, fingerprint);
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
    seek_to_hash_log(g_args.hash_table_fd, hash_log_address);
    int err = read(g_args.hash_table_fd, &hle, sizeof(struct hash_log_entry));
    assert(err == sizeof(struct hash_log_entry));

    if (hle.ref_count > 1) {
        hle.ref_count--;
        seek_to_hash_log(g_args.hash_table_fd, hash_log_address);
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
static int write_one_block_btree(void *buf, uint32_t block_size, uint64_t offset)
{

    if (block_size == 0) {
        printf("tried to write a empty block!\n");
        return 0;
    }


    char log_line[LOG_LINE_MAX_SIZE];
    int err;
    char fingerprint[FINGERPRINT_SIZE];
    struct block_map_entry bm_entry;

    /* Compute the fingerprint of the new block */
    SHA1(buf, block_size, (unsigned char *) fingerprint);

    if (fingerprint_is_zero(fingerprint)) {
        printf("[write one block] | debug | fingerprint is zero\n");
    }

    /* Update b+tree anyway, even though this fingerprint has already been stored */
    bm_entry.start = offset;
    bm_entry.length = block_size;
    memcpy(bm_entry.fingerprit, fingerprint, FINGERPRINT_SIZE);

    bplus_tree_put(g_args.tree, offset, bm_entry);

    uint64_t hash_log_address;
    struct hash_log_entry hl_entry;


    /* See if this fingerprint is already stored in HASH_LOG. */
    hash_log_address = hash_index_lookup(fingerprint);
    if (hash_log_address == (uint64_t) -1) {
        /* This block is new. */
        memcpy(&(hl_entry.fingerprint), fingerprint, FINGERPRINT_SIZE);



        hl_entry.data_log_offset = physical_block_new(block_size);



        hl_entry.ref_count = 1;
        hl_entry.block_size = block_size;
        hash_log_address = hash_log_new();
        /* Update hash index */
        hash_index_insert(fingerprint, hash_log_address);
        /* Update hash log */
        seek_to_hash_log(g_args.hash_table_fd, hash_log_address);
        err = write(g_args.hash_table_fd, &hl_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
        /* Write data block */
        seek_to_data_log(fd, hl_entry.data_log_offset);
        err = write(fd, buf, block_size);
        printf("[WRITE NEW BLOCK] | size: %d, offset %lu\n", block_size, hl_entry.data_log_offset);
        assert(err == (int)block_size);
    } else {
        /* This block has already been stored. We just need to increase the
         * refcount. */
        seek_to_hash_log(g_args.hash_table_fd, hash_log_address);
        err = read(g_args.hash_table_fd, &hl_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
        hl_entry.ref_count += 1;
        seek_to_hash_log(g_args.hash_table_fd, hash_log_address);
        err = write(g_args.hash_table_fd, &hl_entry, sizeof(struct hash_log_entry));
        printf("[WRITE OLD BLOCK]\n");
        assert(err == sizeof(struct hash_log_entry));
    }

    return 0;
}

static int dedup_write(const void *buf, uint32_t len, uint64_t offset)
{
    int err;
    int length = len;
    size_t bytes = 0;
    unsigned int chunks = 0;
    struct rabin_t *hash;
    hash = rabin_init();
    uint8_t *ptr = buf;
    bytes += len;

    if (len < MIN_BLOCK_SIZE) {
        err = write_one_block_btree(buf, len, offset);
        assert(err == 0);
        return 0;
    }

    while(1) {
        int remaining = rabin_next_chunk(hash, ptr, len);

        if (remaining < 0) {
            break;
        }

        len -= remaining;
        ptr += remaining;

        /* Print rabin debug information */
        if(g_args.rabin_debug)
            printf("[RABIN] start: %lu, len: %lu fingerprint: %016llx\n",
                   last_chunk.start, last_chunk.length, (long long unsigned int)last_chunk.cut_fingerprint);

        chunks++;

        /* Write a block */

        assert(last_chunk.start >= 0);
        assert(last_chunk.length <= length);

        if (last_chunk.start >= 10000000) {
            printf("bigger\n");
        }

        err = write_one_block_btree(buf+last_chunk.start, last_chunk.length, offset+last_chunk.start);
        assert(err == 0);
    }

    if (rabin_finalize(hash) != NULL) {
        chunks++;
        if (g_args.rabin_debug)
            printf("[LAST] | %d %016llx\n",
                   last_chunk.length,
                   (long long unsigned int)last_chunk.cut_fingerprint);
        err = write_one_block_btree(buf+last_chunk.start, last_chunk.length, offset+last_chunk.start);
        assert(err == 0);
    }



    if (g_args.rabin_debug) {
        unsigned int avg = 0;
        if (chunks > 0)
            avg = bytes / chunks;
        fprintf(stderr, "[RABIN]%d chunks, average chunk size %d\n", chunks, avg);
    }

    return 0;
}



static int read_one_block_btree(void *buf, uint32_t len, uint64_t offset)
{
    int err;
    char fingerprint[FINGERPRINT_SIZE];
    struct block_map_entry bmap_entry;
    bmap_entry = bplus_tree_get_fuzzy(g_args.tree, offset);
    memcpy(fingerprint, bmap_entry.fingerprit, sizeof(fingerprint));

    if (fingerprint_is_zero(fingerprint)){
        // In this case we did't find the expected block
        memset(buf, 0, len);
        return 0;
    }

    struct hash_log_entry hlog_entry;
    hlog_entry = lookup_fingerprint(fingerprint);

    seek_to_data_log(fd, hlog_entry.data_log_offset);
    err = read(fd, buf, len);
    assert(err == len);
    return 0;
}

static int dedup_read(void *buf, uint32_t len, uint64_t offset)
{
    char *bufi = buf;
    struct block_map_entry bmap_entry;

    bmap_entry = bplus_tree_get_fuzzy(g_args.tree, offset);

    /* If we don't BEGIN on a block boundary */
    if (offset != bmap_entry.start) {
        if(bmap_entry.length == 0) {
            memset(bufi, 0, len);
            return 0;
        }
        uint32_t read_size = bmap_entry.length - (offset - bmap_entry.start);
        assert(read_size >= 0);
        read_one_block_btree(bufi, read_size, offset);
        bufi += read_size;
        len -= read_size;
        offset += read_size;
    }

    while (len >= 0 ) {
        bmap_entry = bplus_tree_get_fuzzy(g_args.tree, offset);
        if (len < bmap_entry.length)
            break;
        /* We read a complete block */
        uint32_t  read_size = bmap_entry.length;

        if (read_size == 0) {
            memset(bufi, 0, len);
            return 0;
        }

        read_one_block_btree(bufi, read_size, offset);
        bufi += read_size;
        len -= read_size;   // fixme: len never equals to 0
        offset += read_size; // fixme: initial read size = 0
    }
    /* Now we get to the last block, it may be not a complete block*/
    if (len != 0) {
        read_one_block_btree(bufi, len, offset);
    }

    return 0;
}




/* Called upon receipt of a disconnect request. We need to make sure everything
 * is written to stable storage before this function returns. */
static int dedup_disc()
{
    int err;

    fprintf(stderr, "Just received a disconnect request.\n");
    seek_to_hash_log(g_args.hash_table_fd, 0);
    err = write(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));


    seek_to_data_log_free_list(fd);
    err = write(fd, &(g_args.data_log_free_list), sizeof(struct data_log_free_list_node));
    assert(err == sizeof(struct data_log_free_list_node));

    return 0;
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




/**
 * Init in SPACE mode.
 */
static int init_space_mode()
{
    // todo: init space mode
    /* We mmap a bunch of zeros into memory. This way we can write it directly
         * into the file to zero out the block map and hash index. 写时拷贝|匿名映射 */
//    zeros = mmap(NULL, BLOCK_MAP_SIZE + HASH_INDEX_SIZE, PROT_READ,
//                 MAP_PRIVATE | MAP_ANONYMOUS, fd, 0);
}

/**
 * Init in B+TREE mode.
 */
static int init_btree_mode()
{
    uint64_t i;
    int err;




    err = write(g_args.hash_table_fd, zeros, HASH_INDEX_SIZE);
//    zeros = malloc(NBUCKETS * sizeof(struct hash_index_entry)*ENTRIES_PER_BUCKET);
//    memset(zeros, 0, NBUCKETS * sizeof(struct hash_index_entry)*ENTRIES_PER_BUCKET);
//    err = write(g_args.hash_table_fd, zeros, NBUCKETS * sizeof(struct hash_index_entry)*ENTRIES_PER_BUCKET);
    assert(err == HASH_INDEX_SIZE);

    printf("init %llu buckets\n", NBUCKETS);

    /* We now initialize the hash log and data log. These start out empty, so we
     * put everything in the free list. It might be more efficient to stage this
     * in memory and then write it out in larger blocks. But the Linux buffer
     * cache will probably take care of that anyway for now. */
    for (i = 1; i <= NPHYS_BLOCKS; i++) {
        seek_to_hash_log(g_args.hash_table_fd, i - 1);
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

static int init()
{
    if (g_args.map_mode == BTREE_MODE)
        init_btree_mode();
    else
        init_space_mode();
}

/**
 * @brief : Open a device file or a regular file specified by -p
 */
int open_phy_device(char *filename)
{
    struct stat phy_file_stat;
    stat(filename, &phy_file_stat);
    if (S_ISBLK(phy_file_stat.st_mode)){
        /* specified a block device */
        fd = open(filename, O_RDWR|O_DIRECT|O_LARGEFILE);
    } else {
        /* FIXME: we should only handle physical device or regular file(not created) */
//        fprintf(stderr, "Specified a regular file!\n");
        fd = open(filename, O_RDWR|O_CREAT|O_LARGEFILE);
    }
    assert(fd != -1);


    return 0;
}

int open_hash_file(char *filename)
{
    g_args.hash_table_fd = open(filename, O_RDWR | O_CREAT);
    assert(g_args.hash_table_fd != -1);
}

/**
 * Parse cmd args
 */
void parse_command_line(int argc, char *argv[])
{
    /* command line args */
    const char *opt_string = "i:n:p:h:s:b";
    const struct option long_opts[] = {
            {"init", required_argument, NULL, 'i'},
            {"nbd", required_argument, NULL, 'n'},
            {"physical-device", required_argument, NULL, 'p'},
            {"hash-file", required_argument, NULL, 'a'},

            {"help", no_argument, NULL, 'h'},
            {"space", no_argument, NULL, 's'},
            {"btree", no_argument, NULL, 's'},
            {NULL, 0, NULL, NULL},
    };

    if (argc <= 5) {
        usage();
        exit(-1);
    }

    int opt = getopt_long(argc, argv, opt_string, long_opts, NULL);
    while( opt != -1 ) {
        switch(opt) {
            case 'a':   // hash data file
                g_args.hash_table_filename = optarg;
                break;
            case 'i':   // init mode
                g_args.run_mode = INIT_MODE;
                g_args.nbd_device_name = optarg;
                break;
            case 'n':   // nbd device
                g_args.run_mode = RUN_MODE;
                g_args.nbd_device_name = optarg;
                break;
            case 'p':   // image file
                g_args.phy_device_name = optarg;
                break;
            case 's':   // space mode
                g_args.map_mode = SPACE_MODE;
                break;
            case 'b':   // b+tree mode
                g_args.map_mode = BTREE_MODE;
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
    printf("nbd device: %s\n", g_args.nbd_device_name);
    printf("physical device: %s\n", g_args.phy_device_name);
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

    switch (g_args.map_mode) {
        case SPACE_MODE:
            printf("mapping mode: space\n");
            break;
        case BTREE_MODE:
            printf("mapping mode: b+tree\n");
            break;
        default:
            printf("mapping mode: invalid\n");
            break;
    }

    printf("data free list offset: %lu\n", g_args.data_log_free_list.offset);
    printf("data free list size: %lu\n", g_args.data_log_free_list.size);
    printf("data free list next: %lu\n", g_args.data_log_free_list.next);
}



static void hash_debug()
{
    int err;
    int prt;
    for (int i = 1; i <= NPHYS_BLOCKS; i++) {
        int new = hash_log_new();

        printf("%d\n", new);
    }
}

static void debug_settings()
{
    // DEBUG settings
    g_args.cmd_debug = 0;
    g_args.rabin_debug = 1;
    g_args.hash_debug = 0;
}

/**
 * Main entry
 */
int main(int argc, char *argv[])
{
    int err;

    debug_settings();
    /* First, we parse the cmd line */
    parse_command_line(argc, argv);
    open_hash_file(g_args.hash_table_filename);
    open_phy_device(g_args.phy_device_name);

    g_args.tree = bplus_tree_init("./bpt.data", 65536);


    /* Init zeros */
    if (g_args.map_mode == BTREE_MODE)
        zeros = mmap(NULL, HASH_INDEX_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, g_args.hash_table_fd, 0);
    else if (g_args.map_mode == SPACE_MODE)
        zeros = mmap(NULL, SPACE_SIZE + HASH_INDEX_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, g_args.hash_table_fd, 0);
    assert(zeros != (void *) -1);


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
        if (g_args.cmd_debug)
            print_cmd_args();

        /* By convention the first entry in the hash log is a pointer to the hash
         * log free list. Likewise for the data log. */
        seek_to_hash_log(g_args.hash_table_fd, 0);
        err = read(g_args.hash_table_fd, &hash_log_free_list, sizeof(uint64_t));
        assert( err == sizeof(uint64_t));

        data_log_free_offset = 0;
//        seek_to_data_log_free_list(fd);
//        err = read(fd, &(g_args.data_log_free_list), sizeof(struct data_log_free_list_node));
//        assert(err == sizeof(struct data_log_free_list_node));

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

        buse_main(g_args.nbd_device_name, &bop, NULL);
        free(cache);
        zlog_fini();
        bplus_tree_deinit(g_args.tree);

        return 0;
    }
}