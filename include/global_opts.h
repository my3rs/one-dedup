

#ifndef ONE_DEDUP_GLOBAL_OPTS_H
#define ONE_DEDUP_GLOBAL_OPTS_H


#define TREE_FILENAME "./tree"
#define HASH_FILENAME "./hash"
#define IMAGE_FILENAME "./image"
#define NBD_DEVICE "/dev/nbd0"
#define MAPPING BPTREE_MODE

enum {
    INIT_MODE = 0,
    RUN_MODE  = 1,
    BPTREE_MODE = 2,
    SPACE_MODE =3,
};



#endif //ONE_DEDUP_GLOBAL_OPTS_H
