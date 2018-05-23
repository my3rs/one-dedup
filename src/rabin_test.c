#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include "rabin.h"

void *buf;
size_t bytes;

int main() {
    int fd;
    size_t  len;
    unsigned char fingerprint[SHA_DIGEST_LENGTH];
    char str_fp[2*SHA_DIGEST_LENGTH + 1];
    struct rabin_t *hash;


    unsigned int chunks = 0;

    fd = open("./p.tar", O_RDWR);
    buf = malloc(128*1024);
    free(hash);

    while((len = read(fd, buf, 128 * 1024)) > 0) {
        hash = rabin_init();
        uint8_t *ptr = buf;

        bytes += len;

        while (1) {
            int remaining = rabin_next_chunk(hash, ptr, len);

            if (remaining < 0 ) {
                break;
            }

            len -= remaining;
            ptr += remaining;

            SHA1(buf + last_chunk.start, last_chunk.length, fingerprint);
            for (int i=0; i<SHA_DIGEST_LENGTH; i++)
                sprintf(&str_fp[i*2], "%02x", (unsigned int)fingerprint[i]);
            fprintf(stderr, "start: %lu len: %u remaining: %u len: %lu\n",
                    last_chunk.start, last_chunk.length, remaining, len);

            chunks++;
        }
    }


    memset(fingerprint,0,SHA_DIGEST_LENGTH);
    if (rabin_finalize(hash) != NULL) {
        chunks++;
        SHA1(buf + last_chunk.start, last_chunk.length, fingerprint);
        for (int i=0; i<SHA_DIGEST_LENGTH; i++)
            sprintf(&str_fp[i*2], "%02x", (unsigned int)fingerprint[i]);
        fprintf(stderr,"[LAST] start:%lu len: %u\n",
               last_chunk.start,
               last_chunk.length
               );
    }

    unsigned int avg = 0;
    if (chunks > 0)
        avg = bytes / chunks;
    fprintf(stderr, "%d chunks, average chunk size %d\n", chunks, avg);

    return 0;
}