#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
#define SOCK_NAME "/tmp/aflfuzz.sock"

int inform_aflserver_bug_cmdinj(pid_t pid){
    int sockfd, len;
    struct sockaddr_un addr;
    char send_buf[0x20];
    memset(send_buf, '\0', 0x20);
    // printf("serv_shmem_id: %d\n", serv_shmem_id);

    // 发送 S|<pid>|<shmem_id> 表示pid对应的进程注册了shmem_id对应的共享内存
    snprintf(send_buf,0x1f, "I|%d|0", pid);
    // printf("send_buf: %s\n", send_buf);

    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        perror("inform_aflserver: socket error");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_NAME, sizeof(addr.sun_path)-1);

    len = sizeof(addr);
    if (connect(sockfd, (struct sockaddr *)&addr, len) == -1) {
            perror("inform_aflserver: connect");
            return -1;
    }
    if (send(sockfd, send_buf, strlen(send_buf), 0) == -1) {
            perror("inform_aflserver: send");
            return -1;
        }
    close(sockfd);
    return 0;
}


int system(const char *command) {
    int (*orig_system)(const char *command);
    orig_system = dlsym(RTLD_NEXT, "system");
    
    if (orig_system == NULL) {
        write(STDERR_FILENO, "Failed to resolve 'system' symbol\n", 33);
        _exit(EXIT_FAILURE);
    }

    // write(STDOUT_FILENO, "Executing command...\n", 20);
    int ret = orig_system(command);
    // write(STDOUT_FILENO, "Command execution finished.\n", 27);
    if(ret < 0){
        inform_aflserver_bug_cmdinj(getpid());
    }
    return ret;
}