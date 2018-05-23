/**
 * 测试用的
 * */
#include "map.h"
#include <stdio.h>

static void iter(const char* key, const int *value)
{
    printf("key: %s value: %d\n", key, *value);
}


int main()
{
    Map *map;
    char buf[255];
    int value;
    int result;

    map = map_create(10);

    if (map == NULL) {
        fprintf(stderr, "init failed!\n");
    }
    map_put(map, "AAAAAAAAAAAAAAAAAAAAAAAAAAA", 1);
    map_put(map, "BBBBBBBBBBBBBBBBBBBBBBBBBBB", 2);
    map_put(map, "CCCCCCCCCCCCCCCCCCCCCCCCCCC", 3);

    /* Retrieve a value */
    result = map_get(map, "AAAAAAAAAAAAAAAAAAAAAAAAAAA", &value);
    if (result == 0) {
        fprintf(stderr, "cannot find\n");
    } else {

        printf("key: %s value: %d\n", "AAAAAAAAAAAAAAAAAAAAAAAAAAA", value);

    }
    printf("遍历结果:\n");
    map_enum(map, &iter, NULL);

    /* When done, destroy the StrMap object */
    map_destroy(map);

}



