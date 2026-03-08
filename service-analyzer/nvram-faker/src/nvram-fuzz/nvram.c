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

#include "libnvram_fuzz.h"


// 可能要换成64。后面或许可以实现多层的，毕竟KEY长度较大的是少数。或许可以加快搜索速度
#define MAX_KEY_SIZE 48
#define MAX_VALUE_SIZE 96
#define ENTRY_SIZE (MAX_KEY_SIZE + MAX_VALUE_SIZE)
#define MAX_LINE_LENGTH ENTRY_SIZE+2 // for '=' and '\n'

#define NVRAM_VERBOSE
// #define TEST 1


#define NVRAM_SIZE (ENTRY_SIZE * 4000) // 4000个nvram entry

#define USE_PROXY 0
#define PROXY_MEMSIZE (4096)

typedef enum { false, true } bool;

static void *nvram_buf = NULL;
static void *nvram_buf_end = NULL;
int shmid = -1;
char* nvram_name = "/nvram_shm";
char* nvram_mutex_fname = "/nvram_lock";
pthread_mutex_t* main_mutex = NULL;
char null_string[] = "";
int nvram_entry_cnt = 0;


/* copy on write and fast recovery */
#define NVRAM_COW_SIZE (ENTRY_SIZE * 100) // 100个entry(12800)
static void *nvram_cow_buf = NULL;
static void *nvram_cow_buf_end = NULL;
int cow_shmid = -1;
char* cow_name = "/nvram_shm_cow";
char* cow_mutex_fname = "/nvram_cow_lock";
pthread_mutex_t* cow_mutex = NULL;
int cow_entry_cnt = 0;

int nvram_initialized = 0;

char* proxy_mem = NULL;



void set_proxy_num(int index, unsigned char original_num);
void nvram_writeproxy_set(const char* key);
void nvram_calculate(char* bitmap);




typedef struct KeyValuePair {
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
} KeyValuePair;

int nvram_fuzz_STRCMP(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int nvram_fuzz_STRNCMP(const char *s1, const char *s2, size_t  len)
{

    // assert(s1!=NULL && s2 !=NULL);

    while(len--) 
    {
        if(*s1 == 0 || *s1 != *s2)
            return *s1 - *s2;
         
        s1++;
        s2++;
    }
        return 0;
}


char *nvram_fuzz_STRCHR(const char *s, const char ch)
{
 	 if (NULL == s)
		 return NULL;	 
	 
	 const char *pSrc = s;
	 while ('\0' != *pSrc)
	 {
	  	   if (*pSrc == ch)
	  	   {
			   return (char *)pSrc;
		   }		   
	  	   ++ pSrc;
	 }	 
	 return NULL;
} 



void* create_memory(const char* file_name, int size) {
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

// 和create_memory一样
void* attach_memory(const char* file_name, int size){
    // 将给定文件名对应的shmid附加到当前进程中
    key_t key = ftok(file_name, 65);
    if (key == -1) {
        perror("ftok");
        return NULL;
    }
    int shmid = shmget(key, size, 0666|IPC_CREAT); 
    if (shmid == -1) {
        perror("shmget");
        return NULL;
    }
    char* memory_buf = (char*)shmat(shmid, (void*)0, 0);
    if (memory_buf == (void*)-1) {
        perror("shmat");
        return NULL;
    }
    return memory_buf;
}


void nvram_create_memory(){
    nvram_buf = create_memory(nvram_name, NVRAM_SIZE);
    nvram_buf_end = nvram_buf + NVRAM_SIZE;
}

void nvram_cow_create_memory(){
    nvram_cow_buf = create_memory(cow_name, NVRAM_COW_SIZE);
    nvram_cow_buf_end = nvram_cow_buf + NVRAM_COW_SIZE;
}

pthread_mutex_t* read_or_create_named_shared_mutex(char* filename) {

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

void nvram_main_init(){
    nvram_create_memory();

    main_mutex = read_or_create_named_shared_mutex(nvram_mutex_fname);
}

void nvram_cow_init(){
    nvram_cow_create_memory();

    cow_mutex = read_or_create_named_shared_mutex(cow_mutex_fname);
}

void nvram_read_proxy_init(){
    // 只记录nvram读取过程的key值
    proxy_mem = (char*)malloc(4096);
    memset(proxy_mem, 0, 4096);
}


void nvram_init_all(){
    nvram_main_init();
    nvram_cow_init();

#if USE_PROXY
    nvram_read_proxy_init();
#endif
}

void nvram_clear() {
    // 清理两部分的share memory并删除共享内存的映射
    if (nvram_buf) {
        memset(nvram_buf, 0, NVRAM_SIZE);
        shmdt(nvram_buf);
    }
    if (nvram_cow_buf) {
        memset(nvram_cow_buf, 0, NVRAM_COW_SIZE);
        shmdt(nvram_cow_buf);
    }
}

void nvram_cow_reload(){
    // 只需要清理COW buffer，还需要清理proxy_mem

    memset(nvram_cow_buf, 0, NVRAM_COW_SIZE);
#if USE_PROXY
    memset(proxy_mem, 0, 4096);
#endif
#ifdef NVRAM_VERBOSE
// printf("after nvram_cow_reload\n");
#endif
}


unsigned int BKDRHash(const char *str)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;
 
    while (*str)
    {
        hash = hash * seed + (*str++);
    }
 
    return (hash & 0x7FFFFFFF);

}





void nvram_cow_write_map(char* nvram_cow_buf){
    // 相当于一个nvram的bitmap,每个nvram entry用2bit表示，
    // 0未定义
    // 1代表set,01
    // 2代表get,10
    // 3代表既set 又 get,11

    // nvram的map每一个queue都需要储存，但是afl只需要记录queue中整体新产生的nvram hit。采用字符串哈希写入queue的bitmap，在save_if_interesting中分析nvram bitmap获知这次queue的nvram行为
    // queue的bitmap大小：1 byte对应4个字符串，总共设置4KB也就是4096byte，对应16384个字符串

    // 设置write的proxy，nvram_cow_buf中的所有内容都是写入的内容
    char* ptr = (char*) nvram_cow_buf;
    while(ptr!=NULL && nvram_fuzz_STRCMP(ptr, "") != 0){
#if USE_PROXY
        nvram_writeproxy_set(ptr);
#endif
        if(ptr - (char*)nvram_cow_buf >= NVRAM_COW_SIZE){
            // 到达末尾,超出长度范围
            break;
        }
        ptr += ENTRY_SIZE;
    }
}

void nvram_calculate(char* bitmap){
    // 这里的bitmap是queue的nvram_bitmap
    // 计算完成当前的bitmap之后直接copy到目标中即可
    // read是运行时计算的，因此只要计算write即可
    nvram_cow_write_map(nvram_cow_buf);
    memcpy(bitmap, proxy_mem, PROXY_MEMSIZE);
}




bool __nvram_set(const char* key, const char* value, void* mem, int max_size){
    char* ptr = (char*)mem;
    int size = strlen(key);
    int max_size_str = size < MAX_KEY_SIZE ? size : MAX_KEY_SIZE - 1;

    // FILE* fp = fopen("/nvram.log", "a+");
    // fprintf(fp, "nvram_set(%s) to %s\n", key, value);
    // fclose(fp);

    while(ptr!=NULL && nvram_fuzz_STRCMP(ptr, "") != 0){
        if(nvram_fuzz_STRCMP(ptr, key) == 0){
            // 仅增加一部分新的数据在nvram_cow_buf中
            // 一个简单的方法是直接先去搜索目标COW的buffer，再去搜索原始的buffer
            strncpy(ptr+MAX_KEY_SIZE, value, MAX_VALUE_SIZE);
            return true;
        }
        ptr += ENTRY_SIZE;
        if(ptr - (char*)mem >= max_size){
            // 到达末尾,超出长度范围
            return false;
        }
    }

    // 当前ptr指向一个可写的内存
    strncpy(ptr, key, MAX_KEY_SIZE);
    ptr[max_size_str] = '\0';
    strncpy(ptr+MAX_KEY_SIZE, value, MAX_VALUE_SIZE);
    cow_entry_cnt++;
    return true;
}


int main_nvram_set(const char* key, const char* value){
    // 主要在nvram_load时使用
    pthread_mutex_lock(main_mutex);
    __nvram_set(key, value, nvram_buf, NVRAM_SIZE);
    pthread_mutex_unlock(main_mutex);

    return 0;
}


int cow_nvram_set(const char* key, char* value){
    // 内存组织
    // [32] [96]
    // [32] [96]
    // ...
    // 每次寻找key对应的value直接移动指针128字节即可，value超出96字节时，需要设置特殊状态
    pthread_mutex_lock(cow_mutex);
    __nvram_set(key, value, nvram_cow_buf, NVRAM_COW_SIZE);
    pthread_mutex_unlock(cow_mutex);
    return 0;

}

bool nvram_set(const char* key, char* value){
    if(nvram_initialized == 0){
        nvram_init_all();
        nvram_initialized = 1;
    }
    return cow_nvram_set(key, value);
}


char* __nvram_search(const char* key, void* mem, size_t size){
    char* ptr = (char*)mem;
    while(ptr!=NULL && nvram_fuzz_STRCMP(ptr, "") != 0){
        if(nvram_fuzz_STRCMP(ptr, key) == 0){
            // 找到目标entry
            return (ptr+MAX_KEY_SIZE);
        }
        ptr += ENTRY_SIZE;
        if(ptr - (char*)mem >= size){
        // 到达末尾
        return null_string;
    }
    }
    return null_string;
}

// 从大小为4096字节的内存块中(proxy_mem)中读取，index时内存块按照两个bit分割的下标，因此最大为4096*4=16384
// 返回这个读取的数字作为unsigned char的结果
unsigned char get_proxy_num(unsigned int index){
    // 检查索引是否越界
    if (index >= 16381) {
        printf("Index %u out of range. Must be less than 16381.\n", index);
        exit(-1);
    }

    // 每个字节包含4个2-bit元素，通过计算index除以4的商和余数来找到元素所在的字节和元素在字节中的偏移位置。
    unsigned int byte_index = index / 4;
    unsigned int bit_offset = 2 * (index % 4);

    // 现在，我们从内存块中读取正确的字节
    const unsigned char* proxy_mem_bytes = (const unsigned char*)proxy_mem;
    unsigned char byte = proxy_mem_bytes[byte_index];

    // 然后，我们创建一个位掩码并将其应用于读取的字节，以屏蔽我们不关心的bit
    unsigned char mask = 0b11 << bit_offset;
    unsigned char masked_byte = byte & mask;

    // 最后，我们需要将结果右移，使其成为一个0-3的数字
    unsigned char result = masked_byte >> bit_offset;

    return result;
}

// 向大小为4096字节的内存块中(proxy_mem)中写入，index时内存块按照两个bit分割的下标，因此最大为4096*4=16384
// 写入的内容为original_num&3的值
void set_proxy_num(int index, unsigned char original_num){
    // 把输入的数字与0b11相与以确保我们只对接下来的运算使用最低的两个位
    original_num &= 0b11;

    // 检查索引是否越界
    if (index >= 16381) {
        printf("Index %u out of range. Must be less than 16384.\n", index);
        exit(-1);
    }

    //规定每个字节包含4个2-bit元素，通过计算index除以4的商和余数来找到元素所在的字节和bit的偏移位置
    unsigned int byte_index = index / 4;
    unsigned int bit_offset = 2 * (index % 4);

    // 现在，我们从内存块中获取正确的字节
    unsigned char* proxy_mem_bytes = (unsigned char*)proxy_mem;
    unsigned char byte = proxy_mem_bytes[byte_index];

    // 然后，我们创建一个位掩码并将其应用于读取的字节，以屏蔽我们不关心的bit
    unsigned char mask = 0b11 << bit_offset;
    unsigned char inv_mask = ~mask; // 反转位掩码
    byte &= inv_mask; // 屏蔽掉要写入的位置

    // 然后我们把要写入的数字左移到正确的位置
    unsigned char shifted_num = original_num << bit_offset;

    // 最后，我们把数字写入到已经屏蔽过的字节中，并写回到内存块中
    byte |= shifted_num;
    proxy_mem_bytes[byte_index] = byte;
}


void nvram_readproxy_set(const char* key){
    unsigned int prime = 16381; // max is 16383, but not prime
    unsigned int result = BKDRHash(key);
    unsigned int index = result % prime;

    unsigned int read_flag = 0x1;
    unsigned char original_num = get_proxy_num(index);
    original_num |= read_flag;
    
    set_proxy_num(index, original_num);
}

void nvram_writeproxy_set(const char* key){
    // 这个只需要在最后nvram_check时，统一写入时调用即可
    unsigned int prime = 16381; // max is 16383, but not prime
    unsigned int result = BKDRHash(key);
    unsigned int index = result % prime;

    unsigned int write_flag = 0x2;
    unsigned char original_num = get_proxy_num(index);
    original_num |= write_flag;

    set_proxy_num(index, original_num);
}





char* nvram_get(const char *key)
{
    
    // FILE* fp = fopen("/nvram.log", "a+");
    // fprintf(fp, "nvram_get(%s), in\n", key);
    if(nvram_initialized == 0){
        nvram_init_all();
        nvram_initialized = 1;
    }
    // fprintf(fp, "nvram_get(%s), 1\n", key);
    // 设置key被查找的记录
#if USE_PROXY
    nvram_readproxy_set(key);
#endif
    
    // 首先从COW BUFFER中寻找
    // fprintf(fp, "nvram_get(%s), 2\n", key);
    char* result = NULL;
    result = __nvram_search(key, nvram_cow_buf, NVRAM_COW_SIZE);
    if(nvram_fuzz_STRCMP("", result) == 0){
        // 没有在COW BUFFER中找到
        result = __nvram_search(key, nvram_buf, NVRAM_SIZE);
        // fprintf(fp, "nvram_get(%s), 2.5, result (%s)\n", key, result);
        // fclose(fp);
        return result;
    }

    // 设置nvram_unset机制
    if(nvram_fuzz_STRCMP("FUZZ_NULL", result) == 0){
        // fprintf(fp, "nvram_get(%s), 3\n", key);
        // fprintf(fp, "nvram_get(%s),  result (%s)\n", key, "NULL");
        // fclose(fp);
        return "";
    }
    // fprintf(fp, "nvram_get(%s),4, result (%s)\n", result, "NULL");
    // fclose(fp);
    
    // 到这里说明在cow buffer中找到了一个entry
    return result;
}

char* _nvram_get(const char* key)
{
    return nvram_get(key);
}

int nvram_commit(){
    return 1; // 返回大于0的数字表示非0值
}

int nvram_loaddefault(){
    return 0;
}


// 在netgear R6200 libnvram.so里面的特殊函数，不清楚什么时候使用。似乎是根据nbytes大小把nvram里面的全部内容读取进入buf，先随便写一个
size_t nvram_getall(void* buf, size_t nbytes){
    if(nbytes){
        size_t move_bytes = nbytes > NVRAM_SIZE ? NVRAM_SIZE : nbytes;
        memmove(buf, nvram_buf, move_bytes);
        return 0;
    }else{
        return 0;
    }
}

// 给定一个key和value，判断nvram_get(key)是否等于nvram_value
int nvram_match(const char* key, const char* val){
    if(key == NULL){
        return 0;
    }
    char* tmp = nvram_get(key);
    if(nvram_fuzz_STRNCMP(tmp, val, MAX_VALUE_SIZE)== 0){
        return 1;
    }else{
        return 0;
    }
    
}

int nvram_unset(const char* a1){
    nvram_set(a1, "FUZZ_NULL");
    return 0;
}

bool acosNvramConfigInit(){
    return 0;
}

char* acosNvramConfig_get(const char* key){
    return nvram_get(key);
}


const char* acosNvramConfig_bget(const char *result, int a2, int a3){
    if(a2 == 0){
        return NULL;
    }else{
        if(a3){
            return nvram_get(result);
        }else{
            return NULL;
        }
        
    }
}

void acosNvramConfig_setPAParam(){
    return ;
}

bool acosNvramConfig_save(){
    // return j_nvram_commit() <= 0; 说明正常情况下应该返回0
    return 0;
}

int acosNvramConfig_set(const char *a1, char *a2){
    if(a1 == NULL || a2 == NULL){
        return 0;
    }
    return nvram_set(a1, a2);

#ifdef NVRAM_VERBOSE
    printf("nvram_set(%s) to %s\n", a1, a2);
#endif
}

int acosNvramConfig_unset(const char* a1){
    nvram_unset(a1);
    return 0;
}

bool acosNvramConfig_match(const char *a1, const char *a2){
    char* v3 = nvram_get(a1);
    return (v3 && nvram_fuzz_STRCMP(v3, a2)==0);
}

bool acosNvramConfig_invmatch(const char *key, const char *value){
    if(key == NULL){
        return 0;
    }
    if(nvram_match(key, value) == 0){
        return false;
    }else{
        return true;
    }
}

// 这个函数有待商榷，是不是都要返回1 可能和模拟关系比较大
char* acosNvramConfig_exist(const char *a1){
    char* result = nvram_get(a1);
    if(!nvram_fuzz_STRCMP(result, "") || result == NULL){
        return "";
    }
    return result;
}

void acosNvramConfig_read(const char *a1, void *s, size_t a3){
    // 将结果写入到s的Buffer中，大小为a3
    char* result = nvram_get(a1);
    if(result == NULL){
        result = "";
    }
    strncpy(s, result, a3);

#ifdef NVRAM_VERBOSE
    printf("nvram_read(%s), got %s\n", a1, result);
#endif

}

int acosNvramConfig_readAsInt(const char *a1, int *a2){
    // 将结果写入a2，作为int

    bool result;
    if(a1 == NULL){
        result = false;
    }
    if(a2 == NULL){
        result = false;
    }
    if(!result){
        char* tmp_result = nvram_get(a1);
        *a2 = atoi(tmp_result);
        result = true;
    }
    return result;
}


void nvram_load(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        return;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        KeyValuePair kv;

        char* sep = nvram_fuzz_STRCHR(line, '=');
        if (sep == NULL)  {
            printf("Invalid line: %s\n", line);
            continue;
        }
        
        // Zero out the arrays before we copy into them.
        memset(kv.key, 0, sizeof(kv.key));
        memset(kv.value, 0, sizeof(kv.value));

        // Determine the length of the key and value, then copy
        // them into the KeyValuePair.
        size_t key_length = sep - line;
        size_t value_length = strlen(line) - key_length - 1;
        if (key_length >= MAX_KEY_SIZE || value_length >= MAX_VALUE_SIZE){
            printf("Key or Value too long on line: %s\n", line);
            continue;
        }

        strncpy(kv.key, line, key_length); 
        strncpy(kv.value, sep + 1, value_length - 1);  // -1 to skip the newline character

        // Now kv holds the key and value from the line
        // Do something with the kv...
        // printf("Key: %s, Value: %s\n", kv.key, kv.value); 
        main_nvram_set(kv.key, kv.value);
        nvram_entry_cnt++;
    }

#ifdef NVRAM_VERBOSE
    printf("load entry numbers: %d\n", nvram_entry_cnt);
#endif

    fclose(file);
}







#ifdef TEST
void debug_print_proxymap(char* proxy_mem) {
    // 总的元素数量
    const unsigned int total_elements = PROXY_MEMSIZE * 4;

    // 按下标从0到16383打印每个元素
    for (unsigned int i = 0; i < total_elements; ++i) {
        unsigned char num = get_proxy_num(i);
        printf("%u, ", num);
        // 每行打印32个元素
        if ((i + 1) % 32 == 0) {
            printf("\n");
        }
    }
}

void debug_nvram_calculate(){
    nvram_cow_write_map(nvram_cow_buf);
}


int main() {
    nvram_main_init();
    nvram_cow_init();
    char* filename = "./test.ini";
    nvram_load(filename);
    clock_t begin, end ;
    begin = clock();
    for(int i = 0; i < 1000; i++){
        // printf("\nnvram get enable_ether_counter_for_dhcpd is %s\n", nvram_get("enable_ether_counter_for_dhcpd"));
        // printf("nvram get ofdm2gpo is %s\n", nvram_get("ofdm2gpo"));
        // printf("nvram get wl_hwaddr is %s\n", nvram_get("wl_hwaddr"));
        // printf("nvram get aaaa is %s\n", nvram_get("aaaa"));
        // printf("nvram_entry_cnt: %d\n", nvram_entry_cnt);
        nvram_get("enable_ether_counter_for_dhcpd");
        nvram_get("ofdm2gpo");
        nvram_get("aaaa");
        nvram_get("wl_hwaddr");
        nvram_set("whoami", "wzq");
        nvram_set("hacvuIV","cwhoVCWHV");
        nvram_set("wifi_mac", "whatever");
        nvram_set("wifi_mac", "hasitchanged");
        nvram_get("wifi_mac");
        nvram_get("whoami");
        // printf("\n wifi_mac: %s\n", nvram_get("wifi_mac"));
        // printf("\n whoami: %s", nvram_get("whoami"));

    }
    end = clock();
    printf("time span: %ldms\n", (end-begin));

    debug_nvram_calculate();
    debug_print_proxymap(proxy_mem);
    
    nvram_clear();

}

#endif