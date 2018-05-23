#include "map.h"
#include <string.h>
#include <unistd.h>
#include <malloc.h>

typedef struct Pair Pair;

typedef struct Bucket Bucket;

struct Pair {
    char *key;
    int *value;
};

struct Bucket {
    unsigned int count;
    Pair *pairs;
};

struct Map {
    unsigned int count;
    Bucket *buckets;
};

static Pair * get_pair(Bucket *bucket, const char *key);
static unsigned long hash(const char *str);

Map * map_create(unsigned int capacity)
{
    Map *map;

    map = malloc(sizeof(Map));
    if (map == NULL) {
        return NULL;
    }
    map->count = capacity;
    map->buckets = malloc(map->count * sizeof(Bucket));
    if (map->buckets == NULL) {
        free(map);
        return NULL;
    }
    memset(map->buckets, 0, map->count * sizeof(Bucket));
    return map;
}

void map_destroy(Map *map)
{
    unsigned int i, j, n, m;
    Bucket *bucket;
    Pair *pair;

    if (map == NULL) {
        return;
    }
    n = map->count;
    bucket = map->buckets;
    i = 0;
    while (i < n) {
        m = bucket->count;
        pair = bucket->pairs;
        j = 0;
        while(j < m) {
            free(pair->key);
            free(pair->value);
            pair++;
            j++;
        }
        free(bucket->pairs);
        bucket++;
        i++;
    }
    free(map->buckets);
    free(map);
}

int map_get(const Map *map, const char *key, int *value)
{
    unsigned int index;
    Bucket *bucket;
    Pair *pair;

    if (map == NULL || key == NULL)
    {
        return 0;
    }

    index = hash(key) % map->count;
    bucket = &(map->buckets[index]);
    pair = get_pair(bucket, key);
    if (pair == NULL)
    {
        return 0;
    }
    *value = *(pair->value);
    return 1;

}

int map_exists(const Map *map, const char *key)
{
    unsigned int index;
    Bucket *bucket;
    Pair *pair;

    if (map == NULL) {
        return 0;
    }
    if (key == NULL) {
        return 0;
    }
    index = hash(key) % map->count;
    bucket = &(map->buckets[index]);
    pair = get_pair(bucket, key);
    if (pair == NULL) {
        return 0;
    }
    return 1;
}

int map_put(Map *map, const char *key, const int value)
{
    unsigned index;     // bucket_index
    Bucket *bucket;
    Pair *pair, *tmp_pairs;
    char *tmp_key, *new_key;
    int *new_value;
    int key_len = strlen(key);

    if (map == NULL || key == NULL)
    {
        return 0;
    }

    index = hash(key) % map->count;
    bucket = &(map->buckets[index]);

    /*
     * 当前 key 有存在对应 value， 替换
     */
    if ((pair = get_pair(bucket, key)) != NULL)
    {
        *(pair->value) = value;
        return 1;
    }

    /* 新 pair: 分配内存 */
    new_key = malloc((key_len + 1) * sizeof(char));
    new_value = malloc(sizeof(int));
    if (new_key == NULL || new_value == NULL) {
        return 0;
    }

    /* Create a key-value pair */
    if (bucket->count == 0) {
        /* The bucket is empty, lazily allocate space for a single
         * key-value pair.
         */
        bucket->pairs = malloc(sizeof(Pair));
        if (bucket->pairs == NULL) {
            free(new_key);
            return 0;
        }
        bucket->count = 1;
    } else {
        /* The bucket wasn't empty but no pair existed that matches the provided
         * key, so create a new key-value pair.
         */
        tmp_pairs = realloc(bucket->pairs, (bucket->count + 1) * sizeof(Pair));
        if (tmp_pairs == NULL) {
            free(new_key);
            free(new_value);
            return 0;
        }
        bucket->pairs = tmp_pairs;
        bucket->count++;
    }
    /* Get the last pair in the chain for the bucket */
    pair = &(bucket->pairs[bucket->count - 1]);
    pair->key = new_key;
    pair->value = new_value;
    /* Copy the key and its value into the key-value pair */
    strcpy(pair->key, key);
    *(pair->value) = value;
    return 1;


}

int map_get_count(const Map *map)
{
    unsigned int i, j, n, m;
    unsigned int count;
    Bucket *bucket;
    Pair *pair;

    if (map == NULL) {
        return 0;
    }
    bucket = map->buckets;
    n = map->count;
    i = 0;
    count = 0;
    while (i < n) {
        pair = bucket->pairs;
        m = bucket->count;
        j = 0;
        while (j < m) {
            count++;
            pair++;
            j++;
        }
        bucket++;
        i++;
    }
    return count;
}

int map_enum(const Map *map, map_enum_func enum_func, const void *obj)
{
    unsigned int i, j, n, m;
    Bucket *bucket;
    Pair *pair;

    if (map == NULL) {
        return 0;
    }
    if (enum_func == NULL) {
        return 0;
    }
    bucket = map->buckets;
    n = map->count;
    i = 0;
    while (i < n) {
        pair = bucket->pairs;
        m = bucket->count;
        j = 0;
        while (j < m) {
            enum_func(pair->key, pair->value, obj);
            pair++;
            j++;
        }
        bucket++;
        i++;
    }
    return 1;
}

/*
 * Returns a pair from the bucket that matches the provided key,
 * or null if no such pair exist.
 */
static Pair * get_pair(Bucket *bucket, const char *key)
{
    unsigned int i, n;
    Pair *pair;

    n = bucket->count;
    if (n == 0) {
        return NULL;
    }
    pair = bucket->pairs;
    i = 0;
    while (i < n) {
        if (pair->key != NULL && pair->value != NULL) {
            if (strcmp(pair->key, key) == 0) {
                return pair;
            }
        }
        pair++;
        i++;
    }
    return NULL;
}

/*
 * Returns a hash code for the provided string.
 */
static unsigned long hash(const char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}


