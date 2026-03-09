#ifndef C_NVRAM_FUZZ
#define C_NVRAM_FUZZ
typedef enum { false, true } bool;


// 清除nvram并释放内存空间，在fuzzing退出时使用
void nvram_clear();


// 加载现有的nvram.ini
void nvram_load(char* filename);


// 释放COW内存空间，往往在重新开始一轮fuzzing的时候使用
void nvram_cow_reload();

// 初始化nram以及nvram_cow，以及对应的锁
void nvram_init_all();


bool nvram_set(const char* key, char* value);


char* nvram_get(const char *key);


// 清空内存映射关系
void nvram_clear();



#endif
