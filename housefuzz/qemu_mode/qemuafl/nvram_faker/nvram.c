// qemuafl fuzz过程中可以用到的一个库，主要实现nvram_get和nvram_set
// 当出现nvram_set()时，写入到内存中。出现nvram_get时，从内存中寻找并读取
// 需要分为两类，一种是默认的nvram.ini，这一步一开始就读取并且后续不会被清空，另一种是后续添加的，这一步的内容需要清空


struct nvram_entry{
    char* key;
    char* value;
}

// 全局nvram不变结构体与可变结构体
int solid_index = 0;
#define MAX_SOLID (1024)
struct nvram_entry* nvram_solid;

int change_index = 0;
#define MAX_CHANGE (1024)
// 设置init-size是为了防止每次memset的开销过大
#define INIT_SIZE (64)
struct nvram_entry* nvram_change;

int init_flag = 0;



struct nvram_entry* new_nvram_entry(char* key, char* value){
    struct nvram_entry* entry = (struct nvram_entry*)malloc(sizeof(nvram_entry));
    entry->key = key;
    entry->value = value;

    return nvram_entry;
}

void nvram_solid_add(struct nvram_entry* entry){
    nvram_solid[solid_index++] = entry;
}

void init(){
    // 初始化nvram-solid与nvram_change
    nvram_solid = (struct nvram_entry*)malloc(sizeof(struct nvram_entry*)*MAX_SOLID);
    nvram_change = (struct nvram_entry*)malloc(sizeof(struct nvram_entry*)*INIT_SIZE);
    init_flag = 1;
}

void parse_original_ini(char* filename){
    // 逐行读取配置文件
    if(!init_flag){
        init();
    }
    FILE* fp = fopen(filename, "r");
    char buffer[0x100];
    memset(buffer, 0, 0x100);
    while(fgets(buffer, 0x100, fp) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        char *key = strdup(strtok(line, "="));
        char *value = strdup(strtok(NULL, "="));
        struct nvram_entry* new_entry = new_nvram_entry(key, value);
        nvram_solid_add(new_entry);
    }
    
}

char* nvram_get(){
    
}