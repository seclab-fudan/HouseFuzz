/*
 *  exit support for qemu
 *
 *  Copyright (c) 2018 Alex Bennée <alex.bennee@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu.h"
#ifdef CONFIG_GPROF
#include <sys/gmon.h>
#endif

#ifdef CONFIG_GCOV
extern void __gcov_dump(void);
#endif

#define SOCK_NAME "/tmp/aflfuzz.sock"

int inform_aflserver_end(int pid)
{
        int sockfd, len;
        struct sockaddr_un addr;
        char send_buf[0x20];
        memset(send_buf, '\0', 0x20);
        // printf("serv_shmem_id: %d\n", serv_shmem_id);

        snprintf(send_buf,0x20, "E|%d", pid);
        // printf("send_buf: %s\n", send_buf);

        if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        perror("inform_aflserver_end: socket error ");
        return -1;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCK_NAME, sizeof(addr.sun_path)-1);

        len = sizeof(addr);
        if (connect(sockfd, (struct sockaddr *)&addr, len) == -1) {
                perror("inform_aflserver_end: connect ");
                return -1;
        }
        if (send(sockfd, send_buf, strlen(send_buf), 0) == -1) {
                perror("inform_aflserver_end: send ");
                return -1;
        }
        close(sockfd);
        return 0;

}

extern pthread_mutex_t* global_shmem_mutex;

void preexit_cleanup(CPUArchState *env, int code)
{

        /* 告知afl-server当前进程退出,仅当自己是子进程的时候 */
        // FILE* fp = fopen("/AFLplusplus/debug.txt","a+");
        // fprintf(fp, "in exit, AFL_MAIN_PARENT is %s, pid is %d, ppid is %d\n", getenv("AFL_MAIN_PARENT"), getpid(), getppid());
        // fclose(fp);

        // 主进程不用告诉，主进程fork时清除这个环境变量，子进程需要告诉
        // 5.15 现在用不到End这个标志了，改用锁控制进程
        // if(!getenv("AFL_MAIN_BIN") || strcmp(getenv("AFL_MAIN_BIN"), "0") == 0){
        //         // inform_aflserver_end(getpid());
        // }
        if(global_shmem_mutex != NULL){
                pthread_mutex_unlock(global_shmem_mutex);
        }
        
                
        // if(strcmp(getenv("AFL_MAIN_PARENT"), "0") == 0)
        // { 
                
        // }
                
#ifdef CONFIG_GPROF
        _mcleanup();
#endif
#ifdef CONFIG_GCOV
        __gcov_dump();
#endif
        gdb_exit(code);
        qemu_plugin_atexit_cb();
}
