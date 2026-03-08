#ifndef C_NVRAM_FUZZ
#define C_NVRAM_FUZZ
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// typedef enum { false, true } bool;
#include "common.h"

// 清除nvram并释放内存空间，在fuzzing退出时使用
void nvram_clear();


// 加载现有的nvram.ini
void nvram_load(const char* filename);


// 释放COW内存空间，往往在重新开始一轮fuzzing的时候使用
void nvram_cow_reload();

// 初始化nram以及nvram_cow，以及对应的锁
void nvram_init_all();

// 一个总结函数
void nvram_init_all();


bool nvram_set(const char* key, char* value);


char* nvram_get(const char *key);

void* create_memory(char* file_name, int size);
void* attach_memory(char* file_name, int size);

void nvram_combine_cow();



#endif
