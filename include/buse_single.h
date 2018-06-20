//
// Created by root on 09/04/18.
//

#ifndef ONE_DEDUP_BUSE_SINGLE_H
#define ONE_DEDUP_BUSE_SINGLE_H


#ifdef __cplusplus
extern "C" {
#endif

/* Most of this file was copied from nbd.h in the nbd distribution. */
#include <linux/types.h>
#include <sys/types.h>
#include <linux/nbd.h>


typedef int (*readfcnt_t)(void *buf, u_int32_t len, u_int64_t offset, void *userdata);
typedef int (*writefcnt_t)(const void *buf, u_int32_t len, u_int64_t offset, void *userdata);
typedef void (*discfcnt_t)(void *userdata);
typedef int (*flushfcnt_t)(void *userdata);
typedef int (*trimfcnt_t)(u_int64_t from, u_int32_t len, void *userdata);

struct buse_operations {
    readfcnt_t read;
    writefcnt_t write;
    discfcnt_t disc;
    flushfcnt_t flush;
    trimfcnt_t trim;
//    int (*read)(void *buf, u_int32_t len, u_int64_t offset, void *userdata);
//    int (*write)(const void *buf, u_int32_t len, u_int64_t offset, void *userdata);
//    void (*disc)(void *userdata);
//    int (*flush)(void *userdata);
//    int (*trim)(u_int64_t from, u_int32_t len, void *userdata);

    // either set size, OR set both blksize and size_blocks
    u_int64_t size;
    u_int32_t blksize;
    u_int64_t size_blocks;
};

int buse_main(const char* dev_file, const struct buse_operations *bop, void *userdata);

#ifdef __cplusplus
}
#endif

#endif //ONE_DEDUP_BUSE_SINGLE_H
