#define _GNU_SOURCE
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include <fcntl.h>
#include <inttypes.h>



#include <sys/mman.h>


#include <getopt.h>
#include <sys/stat.h>
#include <signal.h>

#include "dedup.h"

//#include "buse.h"
#include "buse_single.h"
#include <stdbool.h>
#include <time.h>

#include "global_opts.h"



extern struct last_request_t last_request;
extern struct hash_log_entry *cache;


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
        SEEK_TO_HASH_LOG(gArgs()->hash_table_fd, i - 1);
        err = write(gArgs()->hash_table_fd, &i, sizeof(uint64_t));
        assert(err == sizeof(uint64_t));
    }

    /* We use a list to manage free data log */
//    gArgs()->data_log_free_list.offset = sizeof(struct data_log_free_list_node);
//    gArgs()->data_log_free_list.next = INVALID_OFFSET;
//    gArgs()->data_log_free_list.size = SIZE;
//
//    seek_to_data_log_free_list(fd);
//    err = write(fd, &(gArgs()->data_log_free_list), sizeof(struct data_log_free_list_node));
//    assert(err == sizeof(struct data_log_free_list_node));
    return 0;
}


void open_file(void)
{
    struct stat phy_file_stat;
    stat(IMAGE_FILENAME, &phy_file_stat);
    if (S_ISBLK(phy_file_stat.st_mode)){
        /* specified a block device */
        gArgs()->fd = open64(IMAGE_FILENAME, O_RDWR|O_DIRECT|O_LARGEFILE);
    } else {
        /* FIXME: we should only handle physical device or regular file(not created) */
        gArgs()->fd = open64(IMAGE_FILENAME, O_RDWR|O_CREAT|O_LARGEFILE);
    }
    assert(gArgs()->fd != -1);

    gArgs()->hash_table_fd = open64(HASH_FILENAME, O_CREAT|O_RDWR|O_LARGEFILE, 0644);
    assert(gArgs()->hash_table_fd != -1);

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
    gArgs()->MAP = BPTREE_MODE;

    int opt = getopt_long(argc, argv, opt_string, long_opts, NULL);
    while( opt != -1 ) {
        switch(opt) {
            case 'i':   // init mode
                gArgs()->run_mode = INIT_MODE;
                break;
            case 'n':   // nbd device
                gArgs()->run_mode = RUN_MODE;
                break;
            case 'b':   // b+tree mode
                gArgs()->MAP = BPTREE_MODE;
                break;
            case 's':
                gArgs()->MAP = SPACE_MODE;
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
    switch (gArgs()->run_mode) {
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

    printf("data free list offset: %lu\n", gArgs()->data_log_free_list.offset);
    printf("data free list size: %lu\n", gArgs()->data_log_free_list.size);
    printf("data free list next: %lu\n", gArgs()->data_log_free_list.next);
    printf("===================================\n");
}


static void default_settings(void)
{
    gArgs()->cmd_debug = false;
    gArgs()->rabin_debug = false;
    gArgs()->read_debug = false;
    gArgs()->write_debug = false;
}


/**
 * Main entry
 */
int main(int argc, char *argv[])
{
    ssize_t err;

    default_settings();
    /* First, we parse the cmd line */
    parse_command_line(argc, argv);

    if (gArgs()->MAP == BPTREE_MODE) {
        gArgs()->tree = bplus_tree_init(TREE_FILENAME, 4096);
    }

    open_file();

    if (gArgs()->cmd_debug) {
        print_debug_info();
        print_cmd_args();
    }

    ////////////////////////////////////////////////
    ////////////         INIT MODE        //////////
    ////////////////////////////////////////////////
    if ( gArgs()->run_mode == INIT_MODE ) {
        fprintf(stdout, "Performing Initialization!\n");
        init();
        bplus_tree_deinit(gArgs()->tree);
        print_debug_info();
        return 0;
    ////////////////////////////////////////////////
    ////////////        NORMAL MODE       //////////
    ////////////////////////////////////////////////
    } else if ( gArgs()->run_mode == RUN_MODE ){
        /* By convention the first entry in the hash log is a pointer to the hash
         * log free list. Likewise for the data log. */
        SEEK_TO_HASH_LOG(gArgs()->hash_table_fd, 0);
        int hash_log_index;
        err = read(gArgs()->hash_table_fd, &hash_log_index, sizeof(uint64_t));
        assert( err == sizeof(uint64_t));

        set_hash_log_offset(hash_log_index);
        set_data_log_offset(0);

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
        gArgs()->write_block_category = zlog_get_category("write_block");
        if (!gArgs()->write_block_category) {
            fprintf(stderr, "get write_block_category failed\n");
            zlog_fini();
            return -2;
        }
        gArgs()->log_error = zlog_get_category("error");
        if (!gArgs()->log_error) {
            fprintf(stderr, "get log_error failed\n");
            zlog_fini();
            return -2;
        }
        last_request.length = 0;
        buse_main(NBD_DEVICE, &bop, NULL);
        free(cache);
        zlog_fini();
        if (gArgs()->MAP == BPTREE_MODE)
            bplus_tree_deinit(gArgs()->tree);

        return 0;
    }
}
