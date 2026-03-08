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


void* create_memory(char* file_name, int size) {
    // check existence of /nvram_shm
    if(access(file_name, F_OK) != 0){
        FILE* fp = fopen(file_name, "w"); 
        if(fp == NULL){
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        fclose(fp);
    }

    key_t key = ftok(file_name, 65);
    
    if(key == -1) {
        perror("ftok");
        exit(EXIT_FAILURE);
    }
    
    int shmid = shmget(key, size, 0666|IPC_CREAT); 

    if(shmid == -1) {
        printf("key is %d\n", key);
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    char* memory_buf = (char*)shmat(shmid, (void*)0, 0);

    if(memory_buf == (void*)-1) {
        perror("shmat");
        exit(EXIT_FAILURE);
    } 

    return memory_buf;
}

// 和create_memory一样，省略了错误判断
void* attach_memory(char* file_name, int size){
    // 将给定文件名对应的shmid附加到当前进程中
    key_t key = ftok(file_name, 65);
    int shmid = shmget(key, size, 0666|IPC_CREAT); 
    char* memory_buf = (char*)shmat(shmid, (void*)0, 0);
    return memory_buf;
}


void deattach_memory(char* file_name){
    // 从给定file_name对应的文件中detach
    ;
}

void destory_memory(char* file_name){
    // 删除对应共享内存空间的映射
    ;
}


static pthread_mutex_t* read_or_create_named_shared_mutex(char* filename) {

    if(access(filename, F_OK) != 0){
      // 说明没有这个文件，需要创建锁
      int fd = open(filename, O_RDWR | O_CREAT, 0666);
      if (fd == -1) {
          // handle error
          printf("can't create mutex file\n");
          exit(-1);
          
      }
      int result = ftruncate(fd, sizeof(pthread_mutex_t));
      if(result){
        printf("ftruncate failed!!\n");
        exit(-1);
      }
      pthread_mutex_t* mutex = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      close(fd);

      pthread_mutexattr_t attr;
      pthread_mutexattr_init(&attr);
      pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
      pthread_mutex_init(mutex, &attr);
      pthread_mutexattr_destroy(&attr);
      return mutex;
    }else{
      // 已经有这个文件，直接读取
      int fd = open(filename, O_RDWR);
    //   assert(fd > 0);
      pthread_mutex_t* mutex = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      close(fd);
      return mutex;
    }
    
}


void* create_memory(char* file_name, int size) {
    // check existence of /nvram_shm
    if(access(file_name, F_OK) != 0){
        FILE* fp = fopen(file_name, "w"); 
        if(fp == NULL){
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        fclose(fp);
    }

    key_t key = ftok(file_name, 65);
    
    if(key == -1) {
        perror("ftok");
        exit(EXIT_FAILURE);
    }
    
    int shmid = shmget(key, size, 0666|IPC_CREAT); 

    if(shmid == -1) {
        printf("key is %d\n", key);
        perror("shmget");
        exit(EXIT_FAILURE);
    }

    char* memory_buf = (char*)shmat(shmid, (void*)0, 0);

    if(memory_buf == (void*)-1) {
        perror("shmat");
        exit(EXIT_FAILURE);
    } 

    return memory_buf;
}

// 和create_memory一样，省略了错误判断
void* attach_memory(char* file_name, int size){
    // 将给定文件名对应的shmid附加到当前进程中
    key_t key = ftok(file_name, 65);
    int shmid = shmget(key, size, 0666|IPC_CREAT); 
    char* memory_buf = (char*)shmat(shmid, (void*)0, 0);
    return memory_buf;
}