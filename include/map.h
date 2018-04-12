#ifndef ONEDEDUP_MAP_H
#define ONEDEDUP_MAP_H

#ifdef __cpluscplus
extern "C"
#endif // __cplusplus

//#include "dedup.h"

typedef struct Map Map;

/**
 * 当遍历与值相关的所有键时，此回调函数在每个键值处被调用一次
 * @key: 空字符结尾的 C 字符串，即指纹
 * @value: 指纹对应的 hash_log_entry 的地址
 * @obj: 暂未使用，NULL
 */
typedef void(map_enum_func)(const char *key,const int value,const void *obj);


/**
 * 创建一个哈希表
 * @param capacity : 存储多少个 key-value 对，应大于 0
 * @return : 指向 Map 的指针，或失败时返回 NULL
 */
Map *map_create(unsigned int capacity);

/**
 * 释放一个 Map 的所有占用内存
 * @param map ： 指向 Map 的指针，不可为 NULL
 */
void map_destroy(Map *map);

/**
 * 查找 key 对应的 value
 * @param map 指向 Map 的指针，不可为 NULL
 * @param key 空字符结尾的 C 字符串，不可为 NULL
 * @param value 如果存在对应 key 的值，将其赋给 value
 * @return 如果找到 key 对应的值，返回 1 并将值写到 value；否则返回 0
 */
int map_get(const Map *map, const char *key, int *value);

/**
 * 判断 key 是否存在于 map 中
 * @param map 指向 Map 的指针，不可为 NULL
 * @param key C 字符串指针，需要查询的 key，不可为NULL
 * @return 存在返回 1, 否则返回 0
 */
int map_exists(const Map *map, const char *key);

/**
 * 创建一个 key-value 对，如果提供的 key 已经有了对应的 value，将其覆盖
 * @param map 指向 Map 的指针，不可为 NULL
 * @param key 以空字符结尾的 C 字符串
 * @param value
 * @return 成功返回 1 ，其他情况均返回 0
 */
int map_put(Map *map, const char *key, const int value);

/**
 * 返回 key-value 对的数量
 * @param map 指向 Map 的指针
 * @return key-value 对的数量
 */
int map_get_count(const Map *map);

/**
 * 遍历
 * @param map 指向 Map 的指针
 * @param enum_func 回调函数，用来打印 key-value 对
 * @param obj 传递给回调函数的参数
 * @return 成功返回 1, 否则返回 0
 */
int map_enum(const Map *map, map_enum_func enum_func, const void *obj);

#ifdef __cplusplus
}
#endif

#endif //ONEDEDUP_MAP_H
