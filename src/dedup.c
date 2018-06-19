
#include "dedup.h"

static void *zeros;
static uint64_t skip_len;

struct g_args_t g_args;

static void *zeros;

static uint64_t hash_log_free_list;
static uint64_t data_log_free_offset;
static uint64_t skip_len;
clock_t prog_begin, prog_end;
clock_t write_clock = 0, detect_clock = 0;
clock_t bs_read = 0;
clock_t bs_write = 0;

struct last_request_t last_request;
struct hash_log_entry *cache;

static void set_data_log_offset(uint64_t offset) {
    data_log_free_offset = offset;
}

static void set_hash_log_offset(uint64_t index) {
    hash_log_free_list = index;
}

static struct g_args_t *gArgs() {
    return &g_args;
}

static void fingerprint_to_str(char *dest, char *src)
{
    for (int i=0; i<SHA_DIGEST_LENGTH; i++)
        sprintf(&dest[i*2], "%02x", (unsigned int)src[i]);

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
//    while (node.size < blocksize && node.next != INVALID_PHY_OFFSET) {
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
    while(prev.next != INVALID_PHY_OFFSET) {
        SEEK_TO_DATA_LOG(g_args.fd, prev.next);
        err = read(g_args.fd, &prev, sizeof(struct data_log_free_list_node));
        assert(err == sizeof(struct data_log_free_list_node));
    }

    struct data_log_free_list_node node;
    node.next = INVALID_PHY_OFFSET;
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

    assert(last_request.length >= 0);
    if (last_request.length != 0) {
        new_buf = malloc(last_request.length + len);
        memcpy(new_buf, last_request.buffer, last_request.length);
        memcpy(new_buf+last_request.length, buf, len);
        len += last_request.length;
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
