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
void* create_memory(const char* file_name, int size);
void* attach_memory(const char* file_name, int size);
pthread_mutex_t* read_or_create_named_shared_mutex(char* filename);


/* GNU C library */
int orig_strcmp (const char *p1, const char *p2);
int orig_strncmp (const char* s1, const char* s2, size_t n);
char * orig_strstr (const char *s1, const char *s2);
int orig_strncasecmp(const char *s1, const char *s2, register size_t n);
int orig_strcasecmp(const char *s1, const char *s2);
