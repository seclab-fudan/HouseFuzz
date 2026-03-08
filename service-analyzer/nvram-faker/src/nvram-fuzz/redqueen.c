#define _GNU_SOURCE
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
#include <stdatomic.h>
#include "libnvram_fuzz.h"




/* redqueen naive implementation
 * mainly by hooking string compare like function and store the string content, then sending back to fuzzer to make dictionary
 * including
 * 0. A switch to turn this mode on and off
 * 1. Creating a shared memory with fuzzer to communicate the found string
 * 2. Store the string in plain format, like (str1: xxx, str2: xxx)
 * 3. After one fuzzing shot, clear the share memory like nvram do
 *
 * The fuzzer should be responsible for searching the found string inside input, and insert keys into dictionary if necessary
*/

const char* redqueen_shmem_name = "/redqueen_shmem";
// const char* redqueen_lock_name = "/redqueen_lock";
const char* redqueen_active_name = "/redqueen_on";
const char* redqueen_open_log_name = "/redqueen_open.log";
#define redqueen_shmem_alloc_size (1024 * 64) // 64KB
#define redqueen_shmem_size (redqueen_shmem_alloc_size - sizeof(_Atomic size_t))
#define redqueen_shmem_index_ptr ((_Atomic size_t *)&redqueen_shmem_buf[redqueen_shmem_size])
int redqueen_initialized = 0;
int redqueen_on = 0;
char* redqueen_shmem_buf = NULL;
// pthread_mutex_t* redqueen_write_lock = NULL;

#define USE_REDQUEEN FALSE
// #define REDQUEEN_DEBUG


void redqueen_init_all(){
    // 这个函数在每个binary加载此共享库的时候调用
    // 映射共享内存，返回共享内存指针

    //首先寻找是否存在文件从而判断是否需要记录strcmp

    char *env_is_main = getenv("AFL_MAIN_BIN");
    char *env_is_child_in_qemu = getenv("AFL_QEMU_CHILD_SETUP");
    redqueen_on = (
        (env_is_main && *env_is_main == '1') || \
        (env_is_child_in_qemu && *env_is_child_in_qemu == '1')
    ) && access(redqueen_active_name, F_OK) == 0;
    if (!redqueen_on) {
        return;
    }

    if (!redqueen_initialized) {
        redqueen_shmem_buf = attach_memory(redqueen_shmem_name, redqueen_shmem_alloc_size);
        if (redqueen_shmem_buf == NULL) {
            fprintf(stderr, "redqueen shmem not initialized\n");
            return;
        }
        redqueen_initialized = 1;
    }
}

void replaceCharacter(char* str, char charToReplace) {
    if (str == NULL) {
        return;
    }

    int length = strlen(str);
    for (int i = 0; i < length; i++) {
        if (str[i] == charToReplace) {
            str[i] = ' ';
        }
    }
}

int my_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}


int __redqueen_write(const char* str_left, const char* str_right){
    // int debug = 1;
    // 将str_left和str_right写入char* redqueen_shmem_buf的末尾，每个一行

    if(redqueen_shmem_buf == NULL){
        FILE* fp = fopen(redqueen_open_log_name, "a+");
        fprintf(fp, "redqueen shmem not initialized at __redqueen_write\n");
        // printf("redqueen shmem not initialized at __redqueen_write");
        return -1;
    }

    if(!str_left || !str_right){
        return 0;
    }
    size_t len_left = strlen(str_left);
    size_t len_right = strlen(str_right);
    if(len_left == 0 || len_right == 0){
        return 0;
    }
    if(len_left > 512 || len_right > 512){
        return 0;
    }

    char* str_left_buf = strdup(str_left);
    if (!str_left_buf) return -1;
    char* str_right_buf = strdup(str_right);
    if (!str_right_buf) return -1;

    replaceCharacter(str_left_buf, '\n');
    replaceCharacter(str_right_buf, '\n');

    len_left = strlen(str_left_buf);
    len_right = strlen(str_right_buf);
    size_t total_len = len_left + len_right + 2; // 两个换行符

    // 检查 redqueen_shmem_buf 是否有足够的空间
    // *redqueen_shmem_index_ptr += total_len; // XHY: This is risky without lock, better use atomic operation
    size_t write_start = atomic_fetch_add(redqueen_shmem_index_ptr, total_len);
    if (write_start + total_len >= redqueen_shmem_size) {
        printf("redqueen shmem full");
        return -1; // 缓冲区空间不足，失败，但是不退出
    }

#ifdef REDQUEEN_DEBUG
    fprintf(stderr, "REDQUEEN_DEBUG\n");
    FILE* fp = fopen("/redqueen_log", "a+");
    fprintf(fp, "tok1: %s\n", str_left_buf);
    fprintf(fp, "tok2: %s\n", str_right_buf);
    fclose(fp);
#endif // REDQUEEN_DEBUG

    memcpy(&redqueen_shmem_buf[write_start], str_left_buf, len_left);
    write_start += len_left;
    redqueen_shmem_buf[write_start++] = '\n';
    memcpy(&redqueen_shmem_buf[write_start], str_right_buf, len_right);
    write_start += len_right;
    redqueen_shmem_buf[write_start++] = '\n';
    redqueen_shmem_buf[write_start] = '\0';

    free(str_left_buf);
    free(str_right_buf);

    return 0;
}

int log_cmp_str(const char* str_left, const char* str_right){
    // 记录str_left, str_right到共享内存中，并且记录在cmp_func下
    // 返回0代表正常，-1代表出错

    // 还需要判断是否需要继续写,通过文件是否存在

    int ret = 0;
    redqueen_init_all();
    if (redqueen_on) {
        // 按照一行一个比较字符串的形式写入共享内存
        ret = __redqueen_write(str_left, str_right);
    }

    return ret;

}

int in_strcmp = 0;
int in_strncmp = 0;
int in_strstr = 0;
int in_strcasecmp = 0;
int in_strncasecmp = 0;



/* GNU */

#if 1


// 如果有redqueen_active_name，那么一定是AFL开启了redqueen_fuzz模式
int strcmp(const char *str1, const char *str2) {
    // if(!str1 || !str2){
    //     return 0;
    // }
    log_cmp_str(str1, str2);

    int result = orig_strcmp(str1, str2);
    return result;
}


int strncmp(const char *str1, const char *str2, size_t n) {
    // if(!str1 || !str2){
    //     return 0;
    // }
    log_cmp_str(str1, str2);

    int result = orig_strncmp(str1, str2, n);
    return result;
}

char* strstr(const char *str1, const char *str2) {
    // if(!str1 || !str2){
    //     return 0;
    // }
    log_cmp_str(str1, str2);

    char* result = orig_strstr(str1, str2);
    return result;
}

int strcasecmp(const char *str1, const char *str2) {
    // if(!str1 || !str2){
    //     return 0;
    // }
    log_cmp_str(str1, str2);

    int result = orig_strcasecmp(str1, str2);
    return result;
}

int strncasecmp(const char *str1, const char *str2, size_t n) {
    // if(!str1 || !str2){
    //     return 0;
    // }
    log_cmp_str(str1, str2);

    int result = orig_strncasecmp(str1, str2, n);
    return result;
}


#endif // USE_REDQUEEN


/* 
typedef int (*porig_system)(const char *command);
int system(const char *command) {

    // 执行system之前先删除这两个环境变量，避免进程启动的时候记录很多无用的信息，以及调用qemu过程中的很多字符串比较信息
    // AFL_QEMU_CHILD_SETUP当且仅当在qemu加载了目标进程之后才会被设置，尽管在之后qemu仍然会记录一些额外的信息，但是可以避免初始化过程中记录过多信息

    // 为什么写了下面这行时，将导致一直段错误
    // unsetenv("LD_PRELOAD");
    unsetenv("AFL_QEMU_CHILD_SETUP");

    porig_system orig_system = (porig_system) dlsym(RTLD_NEXT, "system");

    // 调用原始的 system 函数
    return orig_system(command);
}
*/




