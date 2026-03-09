/*
   american fuzzy lop++ - forkserver code
   --------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>


   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */
#define _GNU_SOURCE 1
#include "config.h"
#include "types.h"
#include "debug.h"
#include "common.h"
#include "list.h"
#include "forkserver.h"
#include "hash.h"

// #include "nvram.h"
#include "afl-fuzz.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>

// for pwait
#include <sys/capability.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sysexits.h>

#define FALSE (0)
#define TRUE (1)
#define PTRACE_EXIT_SIGINFO_STATUS (SIGTRAP | (PTRACE_EVENT_EXIT << 8))

pid_t pid_for_detach;

extern afl_state_t *my_global_afl = NULL;
// extern int got_sigchld = 0;


/**
 * The correct fds for reading and writing pipes
 */

/* Describe integer as memory size. */

static list_t fsrv_list = {.element_prealloc_count = 0};

static void fsrv_exec_child(afl_forkserver_t *fsrv, char **argv) {

  if (fsrv->qemu_mode || fsrv->cs_mode) {

    setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0);

  }


  execv(fsrv->target_path, argv);

  WARNF("Execv failed in forkserver.");

}

int get_tracee_exit_status(pid_t pid) {
    unsigned long tracee_exit_status;
    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &tracee_exit_status) == -1) {
        printf("Error getting process %d exit status\n", pid);
        return -1;
    }
    else {
        // unless I'm missing something the man page neglects to mention
        // that PTRACE_GETEVENTMSG gives (status << 8), but it does
        return (int)(tracee_exit_status >> 8);
    }
}

int cap_free_safe(void* p_capabilities) {
    int status = cap_free(p_capabilities);
    if (status == -1) {
        printf("cap_free failed");
    }
    return status;
}


int check_process_state(pid_t pid) {
    char path[30], line[100], state;
    FILE *statusf;

    sprintf(path, "/proc/%d/status", pid);
    statusf = fopen(path, "r");
    if(statusf == NULL)
        return -1;

    while(fgets(line, 100, statusf)) {
        if(strncmp(line, "State:", 6) == 0) {
            sscanf(line, "%*s %c", &state);
            if(state == 'S' || state == 'D') {
                fclose(statusf);
                return 1;  // Waiting
            }
        }
        if(strncmp(line, "SigPnd:", 7) == 0) {
            unsigned long int pending_signals;
            sscanf(line, "%*s %lx", &pending_signals);
            if(pending_signals) {
                fclose(statusf);
                return 2;  // Pending
            }
        }
    }
    
    fclose(statusf);
    return 0;  // Running or other non-relevant status
}


int acquire_capabilities(size_t n, const cap_value_t* capabilities_to_acquire) {
    int cap_acquire_was_successful = FALSE;
    cap_t capabilities;
    cap_flag_value_t cap_status;
    size_t i;
    char* capability_spec = NULL;

    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        printf("getting capabilities of this process failed\n");
        return FALSE;
    }

    capability_spec = cap_to_text(capabilities, NULL);
    printf( "process capabilities: %s\n", capability_spec);
    cap_free_safe(capability_spec);

    // first try setting the capabilities
    if (cap_set_flag(capabilities, CAP_EFFECTIVE, n, capabilities_to_acquire, CAP_SET) == -1) {
        // this generally shouldn't happen
        printf( "modifying capability structure failed\n");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    if (cap_set_proc(capabilities) == 0) {
        // everything should be okay at this point
        printf("setting process capabilities succeeded\n");
        cap_acquire_was_successful = TRUE;
        // but let's be a little paranoid and check whether this process
        // _actually_ has the capabilities set
        cap_free_safe(capabilities);
        capabilities = cap_get_proc();
        for (i = 0; i < n; i++) {
            if (cap_get_flag(capabilities, capabilities_to_acquire[i], CAP_EFFECTIVE, &cap_status) == -1) {
                printf("checking effective capabilities failed\n");
                cap_free_safe(&capabilities);
                return FALSE;
            }
            if (cap_status != CAP_SET) {
                capability_spec = cap_to_name(capabilities_to_acquire[i]);
                printf("process did not acquire %s", capability_spec);
                cap_free_safe(capability_spec);
                cap_acquire_was_successful = FALSE;
            }
        }
        return cap_acquire_was_successful;
    }
    cap_acquire_was_successful = FALSE;
    printf("setting process capabilities failed\n");

      // let's find out why
    for (i = 0; i < n; i++) {
        // check if the capability was supported at all
        if (!CAP_IS_SUPPORTED(capabilities_to_acquire[i])) {
            capability_spec = cap_to_name(capabilities_to_acquire[i]);
            printf( "capability %s is not supported", capability_spec);
            cap_free_safe(capability_spec);
            continue;
        }
        // check if it's permitted to set the capability
        if (cap_get_flag(capabilities, capabilities_to_acquire[i], CAP_PERMITTED, &cap_status) == -1) {
            printf( "checking permitted capabilities failed");
            continue;
        }
        capability_spec = cap_to_name(capabilities_to_acquire[i]);
        if (cap_status == CAP_SET) {
            printf( "process is permitted to acquire %s", capability_spec);
        }
        else {
            printf( "process is not permitted to acquire %s", capability_spec);
        }
        cap_free(capability_spec);
    }

    cap_free_safe(&capabilities);
  return cap_acquire_was_successful;
}




#if defined(_SVID_SOURCE) \
 || _XOPEN_SOURCE >= 500 \
 || defined(_XOPEN_SOURCE) && defined(_XOPEN_SOURCE_EXTENDED) \
 || _POSIX_C_SOURCE >= 200809L
# define HAVE_WAITID

static int pid_has_end(pid_t pid){
  siginfo_t siginfo;
  while(1){
    if(waitid(P_PID, pid, &siginfo, WEXITED | WSTOPPED | WNOHANG) != 0){
      
      return -1;
    }
    if (siginfo.si_pid == 0) {
      return 0;
    }

    if (siginfo.si_code == CLD_TRAPPED && siginfo.si_status == PTRACE_EXIT_SIGINFO_STATUS) {
      return 1;
    }

    else if (siginfo.si_code == CLD_EXITED) {
      return 1;
    }

    else if (siginfo.si_code == CLD_KILLED || siginfo.si_code == CLD_DUMPED) {
      return 1;
    }

    else if (siginfo.si_code == CLD_TRAPPED) {
      ptrace(PTRACE_CONT, pid, NULL, siginfo.si_status);
      return 0;
    }
  }
}




static int wait_using_waitid(pid_t pid) {
    siginfo_t siginfo;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long time_start =(unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;
    unsigned long long time_now = 0;
    int child_timeout = 0;
    

    do {
        usleep(5000);
        gettimeofday(&tv, NULL);
        time_now =(unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;
        int pending_flag = 0;
        
        if(time_now - time_start > 1000 || pending_flag > 0){
          printf("TIMEOUT!!!!!\n");
          child_timeout = 1;
          kill(pid, SIGKILL);
          break; 

        }
        siginfo.si_pid = 0; // not strictly necessary? see man waitid
        /* If waitid() encountered some unknown error, break out of the loop
         * and abort the program to avoid screwing anything up
         */
        // printf("waitid(%d)\n", pid);
        if (waitid(P_PID, pid, &siginfo, WEXITED | WSTOPPED | WNOHANG) != 0) {
            printf( "Failed to wait on process %d\n", pid);
            // fprintf(fsrv_fp, "[waitid] failed to wait on %d\n", pid);
            // fprintf(fsrv_fp, "%s\n", strerror(errno));
            // fclose(fsrv_fp);
            return -1;
        }

        if (siginfo.si_pid == 0) {
            continue;
        }



        /* The tracee process is exiting, in which case waitid() will yield
         * the magic combination PTRACE_EXIT_SIGINFO_STATUS. In this case,
         * break out of the loop and return.
         */
        if (siginfo.si_code == CLD_TRAPPED && siginfo.si_status == PTRACE_EXIT_SIGINFO_STATUS) {
            return 0;
        }

        /* The tracee has somehow exited without this process (the tracer)
         * being notified with a SIGTRAP. This shouldn't happen, but it is easy
         * to recover from.
         */
        else if (siginfo.si_code == CLD_EXITED) {
            return 0;
        }

        /* The tracee has been terminated by a signal. This shouldn't happen
         * unless the signal is SIGKILL, because if the tracee receives SIGTERM
         * or SIGINT or so on, that should be translated into the SIGTRAP that
         * indicates the tracee is about to exit. And the case above where
         * waitpid_return_status >> 8 == PTRACE_EXIT_SIGINFO_STATUS should
         * be invoked instead of this.
         */


        
        else if (siginfo.si_code == CLD_KILLED || siginfo.si_code == CLD_DUMPED) {
            return 0;
        }

        /* The tracee has received a signal other than the SIGTRAP which
         * indicates that it is about to exit. In this case, we should
         * reinject the signal and wait again.
         */
        else if (siginfo.si_code == CLD_TRAPPED) {
            // printf( "tracee received signal %d; reinjecting and continuing", siginfo.si_status);
            // fprintf(fsrv_fp, "[waitid] pid %d receive %d signal with CLD_TRAPPED, continue\n", pid, siginfo.si_signo);
            ptrace(PTRACE_CONT, pid, NULL, siginfo.si_status);
        }
    } while (TRUE);
    if(child_timeout){
      return -127;
    }
    return -1;
}
#endif




int ptrace_pid(pid_t pid) {
    long ptrace_return;
    cap_value_t capability_to_acquire[1];
    if (geteuid() != 0) {
#if defined(CAP_SYS_PTRACE)
        capability_to_acquire[0] = CAP_SYS_PTRACE;
#else
        printf( "CAP_SYS_PTRACE not available\n");
        return EX_SOFTWARE;
#endif
        if (!acquire_capabilities(1, capability_to_acquire)) {
            return EX_SOFTWARE;
        }
    }

    ptrace_return = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    ptrace(PTRACE_CONT, pid, NULL, NULL); // 继续运行
    if (ptrace_return == -1) {
      printf("can't ptrace target pid: %d, error is %s\n", pid, strerror(errno));
      return -1;
    }
  // printf("successfully ptrace pid: %d\n", pid);
  return 0;
}




int wait_using_ptrace(pid_t pid) {
    long ptrace_return;
    int wait_return = -1;
    cap_value_t capability_to_acquire[1];
    struct sigaction oldsiga_term, oldsiga_int;

    if (geteuid() != 0) {
#if defined(CAP_SYS_PTRACE)
        capability_to_acquire[0] = CAP_SYS_PTRACE;
#else
        printf( "CAP_SYS_PTRACE not available\n");
        return EX_SOFTWARE;
#endif
        if (!acquire_capabilities(1, capability_to_acquire)) {
            return EX_SOFTWARE;
        }
    }

    /* Set up a signal handler so that if the program receives a SIGINT (Ctrl+C)
     * or SIGTERM, it will detach from the tracee
     */
    pid_for_detach = pid;

    ptrace_return = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (ptrace_return == -1) {
        return EX_OSERR;
    }

    wait_return = wait_using_waitid(pid);

    if (wait_return == -1) {
        return EX_OSERR;
    }
    sigaction(SIGTERM, &oldsiga_term, NULL);
    sigaction(SIGINT, &oldsiga_int, NULL);


    return wait_return;
}




/* Initializes the struct */

void afl_fsrv_init(afl_forkserver_t *fsrv) {

#ifdef __linux__
  fsrv->nyx_handlers = NULL;
  fsrv->out_dir_path = NULL;
  fsrv->nyx_mode = 0;
  fsrv->nyx_parent = false;
  fsrv->nyx_standalone = false;
  fsrv->nyx_runner = NULL;
  fsrv->nyx_id = 0xFFFFFFFF;
  fsrv->nyx_bind_cpu_id = 0xFFFFFFFF;
#endif

  // this structure needs default so we initialize it if this was not done
  // already
  fsrv->out_fd = -1;
  fsrv->out_dir_fd = -1;
  fsrv->dev_null_fd = -1;
  fsrv->dev_urandom_fd = -1;

  /* Settings */
  fsrv->use_stdin = true;
  fsrv->no_unlink = false;
  fsrv->exec_tmout = EXEC_TIMEOUT;
  fsrv->init_tmout = EXEC_TIMEOUT * FORK_WAIT_MULT;
  fsrv->mem_limit = MEM_LIMIT;
  fsrv->out_file = NULL;
  fsrv->kill_signal = SIGKILL;

  /* exec related stuff */
  fsrv->child_pid = -1;
  fsrv->map_size = get_map_size();
  fsrv->real_map_size = fsrv->map_size;
  fsrv->use_fauxsrv = false;
  fsrv->last_run_timed_out = false;
  fsrv->debug = false;
  fsrv->uses_crash_exitcode = false;
  fsrv->uses_asan = false;

  fsrv->init_child_func = fsrv_exec_child;
  list_append(&fsrv_list, fsrv);

}

/* Initialize a new forkserver instance, duplicating "global" settings */
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from) {

  fsrv_to->use_stdin = from->use_stdin;
  fsrv_to->dev_null_fd = from->dev_null_fd;
  fsrv_to->exec_tmout = from->exec_tmout;
  fsrv_to->init_tmout = from->init_tmout;
  fsrv_to->mem_limit = from->mem_limit;
  fsrv_to->map_size = from->map_size;
  fsrv_to->real_map_size = from->real_map_size;
  fsrv_to->support_shmem_fuzz = from->support_shmem_fuzz;
  fsrv_to->out_file = from->out_file;
  fsrv_to->dev_urandom_fd = from->dev_urandom_fd;
  fsrv_to->out_fd = from->out_fd;  // not sure this is a good idea
  fsrv_to->no_unlink = from->no_unlink;
  fsrv_to->uses_crash_exitcode = from->uses_crash_exitcode;
  fsrv_to->crash_exitcode = from->crash_exitcode;
  fsrv_to->kill_signal = from->kill_signal;
  fsrv_to->debug = from->debug;

  // These are forkserver specific.
  fsrv_to->out_dir_fd = -1;
  fsrv_to->child_pid = -1;
  fsrv_to->use_fauxsrv = 0;
  fsrv_to->last_run_timed_out = 0;

  fsrv_to->init_child_func = from->init_child_func;
  // Note: do not copy ->add_extra_func or ->persistent_record*

  list_append(&fsrv_list, fsrv_to);

}

/* Wrapper for select() and read(), reading a 32 bit var.
  Returns the time passed to read.
  If the wait times out, returns timeout_ms + 1;
  Returns 0 if an error occurred (fd closed, signal, ...); */
static u32 __attribute__((hot))
read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms, volatile u8 *stop_soon_p) {

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  struct timeval timeout;
  int            sret;
  ssize_t        len_read;

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if !defined(__linux__)
  u32 read_start = get_cur_time_us();
#endif

  /* set exceptfds as well to return when a child exited/closed the pipe. */
restart_select:
  sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

  if (likely(sret > 0)) {

  restart_read:
    if (*stop_soon_p) {

      // Early return - the user wants to quit.
      return 0;

    }

    len_read = read(fd, (u8 *)buf, 4);

    if (likely(len_read == 4)) {  // for speed we put this first

#if defined(__linux__)
      u32 exec_ms = MIN(
          timeout_ms,
          ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
#else
      u32 exec_ms = MIN(timeout_ms, (get_cur_time_us() - read_start) / 1000);
#endif

      // ensure to report 1 ms has passed (0 is an error)
      return exec_ms > 0 ? exec_ms : 1;

    } else if (unlikely(len_read == -1 && errno == EINTR)) {

      goto restart_read;

    } else if (unlikely(len_read < 4)) {

      return 0;

    }

  } else if (unlikely(!sret)) {

    *buf = -1;
    return timeout_ms + 1;

  } else if (unlikely(sret < 0)) {

    if (likely(errno == EINTR)) goto restart_select;

    *buf = -1;
    return 0;

  }

  return 0;  // not reached

}


void get_pad_from_string(const char* str, int* ppid, char* prog_name){
    size_t len = strlen(str) + 1;
    char* str_copy = (char*)alloca(len);
    memcpy(str_copy, str, len);

    char *token = strtok(str_copy, "|");

    int count = 0;
    while (token != NULL) {
        if (count == 1) sscanf(token, "%d", ppid);
        if (count == 2) sscanf(token, "%s", prog_name);
        token = strtok(NULL, "|");
        count++;
    }

}

int proclist_search_shmid(afl_state_t *afl, char* prog_name, int* ret_entry){
  u32 entry;
  for(entry = 0; entry < MAX_PROC_CNT; entry++){
    if(afl->proc_list[entry] == NULL)
      break;
    if(afl->proc_list[entry]->parent_name != NULL){
      int cmplen = strlen(afl->proc_list[entry]->parent_name) > 0x10 ? 0x10: strlen(afl->proc_list[entry]->parent_name);
      if(!strncmp(afl->proc_list[entry]->parent_name ,prog_name, cmplen)){
      *ret_entry = entry;
      return afl->proc_list[entry]->shmid;
      }
    }
  
  }
  return -1;
}

void get_pmpad_from_string(const char* str, int* pid, int* shmid, char* prog_name){
  size_t len = strlen(str) + 1;
  char* str_copy = (char*)alloca(len);
  memcpy(str_copy, str, len);

  char *token = strtok(str_copy, "|");
  int count = 0;
    while (token != NULL) {
        if (count == 1) sscanf(token, "%d", pid);
        if (count == 2) sscanf(token, "%d", shmid);
        if (count == 3) sscanf(token, "%s", prog_name);
        token = strtok(NULL, "|");
        count++;
    }

    // free(str_copy);
}

static struct proc_entry* new_proc_struct(){
  struct proc_entry* new_proc = (struct proc_entry*)malloc(sizeof(struct proc_entry));

  memset(new_proc, 0, sizeof(struct proc_entry));
  new_proc->prog_name = (char*)malloc(0x10);
  memset(new_proc->prog_name,'\0',0x10);

  new_proc->crash_bits = ck_alloc(MAP_SIZE);
  memset(new_proc->crash_bits, 255, MAP_SIZE);

  new_proc->activated_times=0;
  new_proc->has_dict = 0;

  return new_proc;

}

struct proc_entry* proclist_add_child(afl_state_t *afl, int pid, int shmid, char* prog_name){

  struct proc_entry* new_proc = new_proc_struct();

  new_proc->shmid = shmid;
  new_proc->pid = pid;
  new_proc->valid = 1;
  new_proc->activated = 1;
  new_proc->activated_times += 1;
  new_proc->is_child = 1;
  new_proc->parent_name = (char*)malloc(0x10);
  new_proc->type = TYPE_UTILITY;
  new_proc->mutex = NULL;
  strncpy(new_proc->prog_name, prog_name, 0xf);
  strncpy(new_proc->parent_name, prog_name, 0xf);

  new_proc->virgin_bits = ck_alloc(MAP_SIZE);
  memset(new_proc->virgin_bits, 255, MAP_SIZE);
  new_proc->trace_bits = shmat(shmid, NULL, 0);

  u32 entry;
  for(entry = 0; entry < MAX_PROC_CNT; entry++){
      if(afl->proc_list[entry] == NULL){
        afl->proc_list[entry] = new_proc;
        break;
      }
  }
  return new_proc;
}

void get_pgshmid_from_string(const char* str, unsigned long* pgid, int* shmid, char* name)
{
    // char *str_copy = strdup(str);
    size_t len = strlen(str) + 1;
    char* str_copy = (char*)alloca(len);
    memcpy(str_copy, str, len);

    char *token = strtok(str_copy, "|");

    int count = 0;
    while (token != NULL) {
        if (count == 1) sscanf(token, "%lX", pgid);
        if (count == 2) sscanf(token, "%d", shmid);
        if (count == 3) sscanf(token, "%s", name);
        token = strtok(NULL, "|");
        count++;
    }
}

int proclist_search_pgid(afl_state_t *afl, unsigned long pgid, u32* ret_entry){
  u32 entry;
  for(entry = 0; entry < MAX_PROC_CNT; entry++){
    
    if(afl->proc_list[entry] == NULL)
      break;
    if(afl->proc_list[entry]->progid == pgid){
      
      *ret_entry = entry;

      return afl->proc_list[entry]->shmid;
    }
  }

  return -1;
}

void get_shm_addr_from_string(const char* str, int* shmid, unsigned long* bug_addr){
  size_t len = strlen(str) + 1;
  char* str_copy = (char*)alloca(len);
  memcpy(str_copy, str, len);

  char *token = strtok(str_copy, "|");
  int count = 0;
  while (token != NULL) {
        if (count == 1) sscanf(token, "%d", shmid);
        if (count == 2) sscanf(token, "%lu", bug_addr);
        token = strtok(NULL, "|");
        count++;
    }
  // free(str_copy);
}

void get_pgid_from_string(const char* str, unsigned long* pgid, int *pid){
  // char *str_copy = strdup(str);
  size_t len = strlen(str) + 1;
  char* str_copy = (char*)alloca(len);
  memcpy(str_copy, str, len);

  char *token = strtok(str_copy, "|");
  int count = 0;
  while (token != NULL) {
    if (count == 1) sscanf(token, "%lX", pgid);
    if (count == 2) sscanf(token, "%d", pid);
    token = strtok(NULL, "|");
    count ++;
  }
  // free(str_copy);
}

void proclist_add_exec(afl_state_t *afl, unsigned long pgid, int shmid, char* name){
  // struct proc_entry* new_proc = (struct proc_entry*)malloc(sizeof(struct proc_entry));
  struct proc_entry* new_proc = new_proc_struct();
  new_proc->shmid = shmid;
  new_proc->valid = 1;
  new_proc->activated = 1;
  new_proc->activated_times += 1;
  new_proc->progid = pgid;
  new_proc->type = TYPE_UTILITY;
  // new_proc->mutex = get_named_shared_mutex(shmid);
  new_proc->mutex = NULL;
  strncpy(new_proc->prog_name, name, 0xf);

  new_proc->virgin_bits = ck_alloc(MAP_SIZE);
  memset(new_proc->virgin_bits, 255, MAP_SIZE);
  new_proc->trace_bits = shmat(shmid, NULL, 0);

  if(new_proc->trace_bits == (void*)-1){
    FATAL("SHMAT wrong in proclist_add_exec\n");
  }
  // printf("new_proc->trace_bits = %d(%p)\n",new_proc->shmid, new_proc->trace_bits);

  u32 entry;
  for(entry = 0; entry < MAX_PROC_CNT; entry++){
      if(afl->proc_list[entry] == NULL){
        afl->proc_list[entry] = new_proc;
        break;
      }
  }

}


int wait_pid_list[MAX_PROC_CNT];
int wait_pid_cnt = 0;

void add_wait_process(int pid, struct pid_fd** pid_fd_list){
  struct pid_fd* pid_fd_ptr = find_pidfd_by_pid(pid_fd_list, pid);

  if(pid_fd_ptr != NULL){
    if(pid_fd_ptr->active == 0){
      pid_fd_ptr->active = 1;
      return;
    }else{
      return;
    }
  }

  pid_fd_ptr = new_pid_fd(pid);
  insert_list(pid_fd_list, pid_fd_ptr);
  return;
}

void proclist_setvalid(afl_state_t *afl, u32 entry_index, int pid){
  afl->proc_list[entry_index]->valid = 1;
  afl->proc_list[entry_index]->activated = 1;
  afl->proc_list[entry_index]->pid = pid;
  afl->proc_list[entry_index]->activated_times += 1;
}

void get_pid_from_string(const char* str, int* pid){
  // char *str_copy = strdup(str);
  size_t len = strlen(str) + 1;
  char* str_copy = (char*)alloca(len);
  memcpy(str_copy, str, len);

  char *token = strtok(str_copy, "|");
  int count = 0;
  while (token != NULL) {
    if (count == 1) sscanf(token, "%d", pid);
    token = strtok(NULL, "|");
    count ++;
  }
}

void proclist_active_proc(afl_state_t *afl, int shmid){
  u32 entry;
  for(entry = 0; entry < MAX_PROC_CNT; entry++){
      if(afl->proc_list[entry] == NULL)
        continue;
      if(afl->proc_list[entry]->shmid == shmid){
        afl->proc_list[entry]->activated = 1;
        afl->proc_list[entry]->activated_times += 1;
        break;
      }
  }
}

void  deal_with_buf(const char* client_buf, int client_fd, struct pid_fd** pid_fd_list){
  int result = 0;
  int pid = 0;
  int shmid = 0;
  u32 entry_index = 0;
  unsigned long program_id = 0;
  unsigned long int bug_addr = 0;
  char prog_name[0x10];
  char msg_buf[0x20];
  
  char cmd = client_buf[0];
  switch(cmd){
    case 'R':{
        get_pad_from_string(client_buf, &pid, prog_name);
        shmid = proclist_search_shmid(my_global_afl, prog_name, &entry_index);
        
        memset(msg_buf, '\0', 0x20);
        sprintf(msg_buf, "%d", shmid);
        result = write(client_fd, msg_buf, 0x20);
        if(shmid != -1){
          proclist_setvalid(my_global_afl, entry_index, pid);
          add_wait_process(pid, pid_fd_list);
        }
        
        if(result < 0){
          printf("afl-server sendback error, maybe process is killed");
        }
        break;
      }
    case 'C':{
      get_pmpad_from_string(client_buf, &pid, &shmid, prog_name);
      proclist_add_child(my_global_afl, pid, shmid, prog_name);
      add_wait_process(pid, pid_fd_list);
      break;
      }
    case 'H':{
      get_pid_from_string(client_buf, &shmid);
      proclist_active_proc(my_global_afl, shmid);
      break;
    }
    case 'X':{
      get_pgshmid_from_string(client_buf, &program_id, &shmid, prog_name);
      proclist_add_exec(my_global_afl, program_id, shmid, prog_name);
      break;
    }

    case 'Q':{
      get_pgid_from_string(client_buf, &program_id, &pid);
      shmid = proclist_search_pgid(my_global_afl, program_id, &entry_index);
      if(shmid != -1){
            my_global_afl->proc_list[entry_index]->activated = 1;
            my_global_afl->proc_list[entry_index]->valid = 1;
            my_global_afl->proc_list[entry_index]->activated_times += 1;
          }
      add_wait_process(pid, pid_fd_list);
      memset(msg_buf, '\0', 0x20);
      sprintf(msg_buf, "%d", shmid);
      result = write(client_fd, msg_buf, 0x20);
      
      if(result < 0){
        printf("afl-server sendback error, maybe process is killed");
      }
      break;
    }
    case 'B':{
      get_shm_addr_from_string(client_buf, &shmid, &bug_addr);
      my_global_afl->meets_bug += 1;
      my_global_afl->bg_crash->shmid = shmid;
      my_global_afl->bg_crash->addr = bug_addr;
      time_t t;
      time(&t);
      break;
    }
    case 'I':{
      get_shm_addr_from_string(client_buf, &shmid, &bug_addr);
      my_global_afl->meets_cmdinj = true;
      my_global_afl->bg_crash->shmid = shmid;
      my_global_afl->bg_crash->addr = bug_addr;
      break;
    }
    default:
    {
      FILE* fp = fopen("/afl_sock_default", "a+");
      fprintf(fp, "recv_log: %s\n", client_buf);
      fclose(fp);
    }
  }
  // fclose(afl_states_fp);
}


void handle_exited_children() {
    // printf("inside handle_exited_children\n");
    int status;
    
    for(int i = 0; i < MAX_PROC_CNT; i++){
      if(wait_pid_list[i] == -1){
        break;
      }
      if(wait_pid_list[i] == 0){
        continue; 
      }
      status = pid_has_end(wait_pid_list[i]);
      if(status == 0){
      }
      else if(status > 0){
        wait_pid_list[i] = 0;
      }
      else{
        printf("failed to check pid: %d state", wait_pid_list[i]);
      }
    }
    // printf("return from handle_exited_children\n");
}



int check_unexited_child(){
  for(int i = 0; wait_pid_list[i] != -1; i++){
    if(wait_pid_list[i] > 0){
      return 1;
    }
  }
  return 0;
}

int pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(SYS_pidfd_open, pid, flags);
}

struct pid_fd* new_pid_fd(int pid){
  struct pid_fd* tmp_new_pid_fd = (struct pid_fd*)malloc(sizeof(struct pid_fd));
  tmp_new_pid_fd->pid = pid;
  tmp_new_pid_fd->fd = pidfd_open(pid, 0);
  tmp_new_pid_fd->active = 1;
  return tmp_new_pid_fd;
}

pid_t find_pid_by_fd(struct pid_fd** list, int fd){
  if(list == NULL){
    return -1;
  }else{
    for(int i = 0; list[i] != NULL; i++){
      if(list[i]->fd == fd){
        return list[i]->pid;
      }
    }
  }
  return -1;
}

int find_fd_by_pid(struct pid_fd** list, pid_t pid){
  if(list == NULL){
    FATAL("pid_fd list is NULL");
  }else{
    for(int i = 0; list[i] != NULL; i++){
      if(list[i]->pid == pid){
        return list[i]->fd;
      }
    }
  }
  return -1;
}

struct pid_fd* find_pidfd_by_pid(struct pid_fd** list, pid_t pid){
  if(list == NULL){
    FATAL("pid_fd list is NULL");
  }else{
    for(int i = 0; list[i] != NULL; i++){
      if(list[i]->pid == pid){
        return list[i];
      }
    }
  }
  return NULL;
}

void insert_list(struct pid_fd** list, struct pid_fd* entry){
  int i = 0;
  if(list == NULL){
    FATAL("pid_fd list is NULL");
  }
  for(; list[i] != NULL; i++){
    ;
  }
  list[i] = entry;
}

void destroy_list(struct pid_fd** list){
  for(int i = 0; list[i] != NULL; i++){
    free(list[i]);
    list[i] = NULL;
  }
}

void deactive_entry_by_fd(struct pid_fd** list, int fd){
  for(int i = 0; list[i] != NULL; i++){
    if(list[i]->fd == fd){
      list[i]->active = 0;
    }
  }
}

int have_active_proc(struct pid_fd** list){
  for(int i = 0; list[i] != NULL; i++){
    if(list[i]->active > 0){
      // printf("pid: %d still active\n", list[i]->pid);
      // https://stackoverflow.com/questions/9152979/check-if-process-exists-given-its-pid/31931126#31931126
      
      // if(getpgid(list[i]->  pid) <0){
      //   list[i]->active = 0;
      //   continue;
      // }
      
      return 1;
    }
  }
  return 0;
}




int getSO_ERROR(int fd) {
   int err = 1;
   socklen_t len = sizeof err;
   if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
      FATAL("getSO_ERROR");
   if (err)
      errno = err;
   return err;
}

void closeSocket(int fd) {
   if (fd >= 0) {
      getSO_ERROR(fd);
      if (shutdown(fd, SHUT_RDWR) < 0)
         if (errno != ENOTCONN && errno != EINVAL)
            FATAL("shutdown");
      if (close(fd) < 0) 
         FATAL("close");
   }
}

int MAX_PID_FD = 0x30;
struct pid_fd** pid_fd_list = NULL;
int             poll_fds_cnt = 0;
int             max_client = 0x30;

void add_poll_fd(struct pollfd* poll_fds, int fd, short events, short revents)
{
  poll_fds[poll_fds_cnt].fd = fd;
  poll_fds[poll_fds_cnt].events = events;
  poll_fds[poll_fds_cnt].revents = revents;
  poll_fds_cnt++;
  if(poll_fds_cnt > max_client){
    FATAL("poll fd count > max client");
  }

}

int find_active_fd(struct pid_fd** list, int fd) {
  if(list == NULL){
    return 0;
  }else{
    for(int i = 0; list[i] != NULL; i++){
      if(list[i]->fd == fd && list[i]->active){
        return 1;
      }
    }
  }
  return 0;
}


void monitor_process(pid_t pid) {  
    int max_try = 3;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {    
        return;  
    }  
  
    int status;  
    if (waitpid(pid, &status, 0) != pid) {  
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;  
    }  
  
    while (1) {  
        if(max_try <= 0){
          ptrace(PTRACE_DETACH, pid, NULL, NULL);  
          break;
        }
        max_try--;
        
        pid_t ret = waitpid(pid, &status, WNOHANG);  
  
        if (ret == pid) {  
            printf("Process %d has exited\n", pid);  
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            break;  
        } else if (ret == 0) {  
            printf("Process %d is still running\n", pid);  
        } else if (ret == -1) {  
            if (errno == ECHILD) {  
                break;  
            }  
            perror("waitpid with WNOHANG");  
            ptrace(PTRACE_DETACH, pid, NULL, NULL);  
            break;  
        }  
    }  
}



void kill_all_child(struct pid_fd** pid_fd_list)
{
  for(int i = 0; pid_fd_list[i] != NULL; i++){
    if(pid_fd_list[i]->active > 0){
      printf("kill utility child: %d\n", pid_fd_list[i]->pid);
      int kill_ret = kill(pid_fd_list[i]->pid, SIGKILL);
      if(kill_ret < 0){
        FILE* fp_kill = fopen("kill_failure.log", "a+");
        fprintf(fp_kill, "kill pid %d error: %s\n", pid_fd_list[i]->pid, strerror(errno));
        fclose(fp_kill);
      }
      else{
        printf("kill success with return value %d", kill_ret);
        monitor_process(pid_fd_list[i]->pid);
      }
      pid_fd_list[i]->active = 0;
    }
  }
}

static u32 __attribute__((hot))
read_s32_timed_multiprocess(s32 pipe_fd, s32 domain_fd, s32 *buf, u32 timeout_ms, volatile u8 *stop_soon_p) {

  memset(wait_pid_list, -1, MAX_PROC_CNT*sizeof(int));
  if(pid_fd_list == NULL){
    pid_fd_list = (struct pid_fd**)malloc(0x30 * sizeof(struct pid_fd*));
  }

  int            sret;
  int            max_fd;
  int            new_sock;
  struct          sockaddr_in client_addr;
  size_t          addrlen = sizeof(client_addr);  
  char            client_buf[0x50];
  int             fd_list[0x30];
  int             main_bin_exit = 0;
  // fd_set          fdsr;
  int 	          ready_to_quit = 0;

  struct pollfd   poll_fds[max_client];
  
  int             ret = 0;
  int conn_amount = 0;
  struct  timeval   tv_begin,tv_now;
  int             afl_len_read = 0;

  gettimeofday(&tv_begin,NULL);
  wait_pid_cnt = 0;
  my_global_afl->utility_timeout = 0;

  

  u32 read_start = get_cur_time_us();
  memset(fd_list, 0, 0x30*sizeof(int));
  memset(pid_fd_list, 0, 0x30*sizeof(struct pid_fd*));
  max_fd = pipe_fd > domain_fd ? pipe_fd : domain_fd;


  while(1){

    if (*stop_soon_p) {

      printf("return 0 in stop_soon_p\n");
      return 0;

    }
    gettimeofday(&tv_now, NULL);
    double duration = 1000 * (tv_now.tv_sec - tv_begin.tv_sec) + ((tv_now.tv_usec - tv_begin.tv_usec) / 1000.0);
    if(duration > timeout_ms){
      printf("timeout, afl_len_read = %d, main_bin_exit=%d\n", afl_len_read, main_bin_exit);
      if(main_bin_exit == 0){
        *buf = -1;
      }else{
        my_global_afl->utility_timeout = 1;
      }

      kill_all_child(pid_fd_list);
      destroy_list(pid_fd_list);
      ready_to_quit = 1;
    }

    // timeout.tv_sec = (timeout_ms / 1000);
    // timeout.tv_usec = (timeout_ms % 1000) * 1000;
    

    int has_unexited_child = have_active_proc(pid_fd_list);
    if(main_bin_exit == 1 && has_unexited_child == 0){
      destroy_list(pid_fd_list);
      for(int i = 0; i < max_client; i ++){
        if(fd_list[i] != 0){
          close(fd_list[i]);
        }
      }
      u32 exec_ms = MIN(timeout_ms, (get_cur_time_us() - read_start) / 1000);
      return exec_ms > 0 ? exec_ms : 1;
    }
    
    memset(poll_fds, 0, sizeof(struct pollfd)*max_client);
    poll_fds_cnt = 0;
    if(!ready_to_quit){
      add_poll_fd(poll_fds, pipe_fd, POLLIN | POLLERR, 0);
    }
    add_poll_fd(poll_fds, domain_fd, POLLIN | POLLERR, 0);

    
    for(int i = 0; i < max_client; i ++){
      if(fd_list[i] != 0){
        add_poll_fd(poll_fds, fd_list[i], POLLIN | POLLERR | POLLRDHUP, 0);
      }
    }

    for(int i = 0; pid_fd_list[i] != NULL; i++){
      if(pid_fd_list[i]->active > 0){
        // FD_SET(pid_fd_list[i]->fd, &fdsr);
        add_poll_fd(poll_fds, pid_fd_list[i]->fd, POLLIN | POLLERR | POLLRDHUP , 0);
        
        if(pid_fd_list[i]->fd > max_fd){
          max_fd = pid_fd_list[i]->fd;
        }
      }
    }

    sret = poll(poll_fds, poll_fds_cnt, duration < timeout_ms ? timeout_ms - duration : 80);
    if(sret < 0){
      printf("sret < 0\n");
      if(errno == EINTR){
        continue; // while(1) loop
      }else{
        // 出错
        *buf = -1;
        printf("return 0 in *buf=-1, error is %s\n", strerror(errno));
        return 0;
      }
    }
    if(sret == 0 && ready_to_quit)
    {
      kill_all_child(pid_fd_list);
      destroy_list(pid_fd_list);
      return timeout_ms + 1;
    }

    for(int i = 0; i < poll_fds_cnt ; i++){
      if(poll_fds[i].revents & POLLIN){
        if(poll_fds[i].fd == pipe_fd){
          do{
            afl_len_read = read(pipe_fd, (u8 *)buf, 4);
          }
          while(afl_len_read == -1 && errno == EINTR);
          if (unlikely(afl_len_read < 4 && afl_len_read >= 0)) {
            FILE* fp = fopen("afl_error.log", "a+");
            fprintf(fp, "afl_len_read < 4\n");
            fclose(fp);
          }
          main_bin_exit = 1;
        }
        if(poll_fds[i].fd == domain_fd){
          new_sock = accept(domain_fd, (struct sockaddr *)&client_addr, (socklen_t*)&addrlen);
            if(new_sock < 0){
              printf("%s\n", strerror(errno));
              FILE* fp = fopen("afl_error.log", "a+");
              fprintf(fp, "AFL accept error, reason: %s\n", strerror(errno));
              fclose(fp);
            }
            memset(client_buf, 0, 0x50);
            ret = recv(new_sock, client_buf, 0x30, 0);
            if(ret > 0 && ret <= 0x30){
              memset(&client_buf[ret], '\0', 1);
              deal_with_buf(client_buf, new_sock, pid_fd_list);
            }
            close(new_sock);
        } // if(poll_fds[i].fd == domain_fd)
        
        if(find_active_fd(pid_fd_list, poll_fds[i].fd)){
          deactive_entry_by_fd(pid_fd_list, poll_fds[i].fd);
        }
      }
      if((poll_fds[i].revents & POLLRDHUP) || poll_fds[i].revents & POLLERR)
      {
        for(int fd_index = 0; fd_index < max_client; fd_index++){
          if(poll_fds[i].fd == fd_list[fd_index]){
            close(fd_list[fd_index]);
            fd_list[fd_index] = 0;
            conn_amount--;
            break;
          }
        }
      }
    }


  }
    printf("return 0 in end\n");
    return 0;
  }
  






/* Internal forkserver for non_instrumented_mode=1 and non-forkserver mode runs.
  It execvs for each fork, forwarding exit codes and child pids to afl. */

static void afl_fauxsrv_execv(afl_forkserver_t *fsrv, char **argv) {

  unsigned char tmp[4] = {0, 0, 0, 0};
  pid_t         child_pid;

  if (!be_quiet) { ACTF("Using Fauxserver:"); }

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {

    abort();  // TODO: Abort?

  }

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  while (1) {

    uint32_t was_killed;
    int      status;

    /* Wait for parent by reading from the pipe. Exit if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) { exit(0); }

    /* Create a clone of our process. */

    child_pid = fork();

    if (child_pid < 0) { PFATAL("Fork failed"); }

    /* In child process: close fds, resume execution. */

    if (!child_pid) {  // New child

      close(fsrv->out_dir_fd);
      close(fsrv->dev_null_fd);
      close(fsrv->dev_urandom_fd);

      if (fsrv->plot_file != NULL) {

        fclose(fsrv->plot_file);
        fsrv->plot_file = NULL;

      }
      if(fsrv->bincov_file != NULL) {
        fclose(fsrv->bincov_file);
        fsrv->bincov_file = NULL;
      }

      // enable terminating on sigpipe in the childs
      struct sigaction sa;
      memset((char *)&sa, 0, sizeof(sa));
      sa.sa_handler = SIG_DFL;
      sigaction(SIGPIPE, &sa, NULL);

      signal(SIGCHLD, old_sigchld_handler);

      // FORKSRV_FD is for communication with AFL, we don't need it in the
      // child
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      // finally: exec...
      execv(fsrv->target_path, argv);

      /* Use a distinctive bitmap signature to tell the parent about execv()
        falling through. */

      *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;

      WARNF("Execv failed in fauxserver.");
      break;

    }

    /* In parent process: write PID to AFL. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) { exit(0); }

    /* after child exited, get and relay exit status to parent through waitpid.
     */

    if (waitpid(child_pid, &status, 0) < 0) {

      // Zombie Child could not be collected. Scary!
      WARNF("Fauxserver could not determine child's exit code. ");

    }

    /* Relay wait status to AFL pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) { exit(1); }

  }

}

/* Report on the error received via the forkserver controller and exit */
static void report_error_and_exit(int error) {

  switch (error) {

    case FS_ERROR_MAP_SIZE:
      FATAL(
          "AFL_MAP_SIZE is not set and fuzzing target reports that the "
          "required size is very large. Solution: Run the fuzzing target "
          "stand-alone with the environment variable AFL_DEBUG=1 set and set "
          "the value for __afl_final_loc in the AFL_MAP_SIZE environment "
          "variable for afl-fuzz.");
      break;
    case FS_ERROR_MAP_ADDR:
      FATAL(
          "the fuzzing target reports that hardcoded map address might be the "
          "reason the mmap of the shared memory failed. Solution: recompile "
          "the target with either afl-clang-lto and do not set "
          "AFL_LLVM_MAP_ADDR or recompile with afl-clang-fast.");
      break;
    case FS_ERROR_SHM_OPEN:
      FATAL("the fuzzing target reports that the shm_open() call failed.");
      break;
    case FS_ERROR_SHMAT:
      FATAL("the fuzzing target reports that the shmat() call failed.");
      break;
    case FS_ERROR_MMAP:
      FATAL(
          "the fuzzing target reports that the mmap() call to the shared "
          "memory failed.");
      break;
    case FS_ERROR_OLD_CMPLOG:
      FATAL(
          "the -c cmplog target was instrumented with an too old afl++ "
          "version, you need to recompile it.");
      break;
    case FS_ERROR_OLD_CMPLOG_QEMU:
      FATAL(
          "The AFL++ QEMU/FRIDA loaders are from an older version, for -c you "
          "need to recompile it.\n");
      break;
    default:
      FATAL("unknown error code %d from fuzzing target!", error);

  }

}

void init_copy_dir(const char *src, const char *dest) {  
    DIR *dir;  
    struct dirent *entry;  
    char src_path[1024];  
    char dest_path[1024];  
  
    struct stat st = {0};  
    if (stat(dest, &st) == -1) {  
        mkdir(dest, 0755);  
    }  
  
    if (!(dir = opendir(src))) {  
        perror("Failed to open source directory");  
        return;  
    }  
  
    while ((entry = readdir(dir)) != NULL) {  
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {  
            continue;  
        }  
  
        snprintf(src_path, sizeof(src_path), "%s/%s", src, entry->d_name);  
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest, entry->d_name);  
  
        struct stat statbuf;  
        if (stat(src_path, &statbuf) == -1) {  
            perror("Failed to get file status");  
            continue;  
        }  
  
        if (S_ISDIR(statbuf.st_mode)) {  
            mkdir(dest_path, 0755);  
            init_copy_dir(src_path, dest_path);  
        } else {  
            FILE *src_file = fopen(src_path, "rb");  
            FILE *dest_file = fopen(dest_path, "wb");  
  
            if (!src_file || !dest_file) {  
                perror("Failed to open file");  
                if (src_file) fclose(src_file);  
                if (dest_file) fclose(dest_file);  
                continue;  
            }  
  
            char buffer[4096];  
            size_t len;  
            while ((len = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {  
                fwrite(buffer, 1, len, dest_file);  
            }  
  
            fclose(src_file);  
            fclose(dest_file);  
        }  
    }  
  
    closedir(dir);  
}  


/* Spins up fork server. The idea is explained here:

   https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h / llvm_mode */


void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output) {

  int   st_pipe[2], ctl_pipe[2];
  s32   status;
  s32   rlen;
  char *ignore_autodict = getenv("AFL_NO_AUTODICT");

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    if (fsrv->nyx_runner != NULL) { return; }

    if (!be_quiet) { ACTF("Spinning up the NYX backend..."); }

    if (fsrv->out_dir_path == NULL) { FATAL("Nyx workdir path not found..."); }

    char *x = alloc_printf("%s/workdir", fsrv->out_dir_path);

    if (fsrv->nyx_id == 0xFFFFFFFF) { FATAL("Nyx ID is not set..."); }

    if (fsrv->nyx_bind_cpu_id == 0xFFFFFFFF) {

      FATAL("Nyx CPU ID is not set...");

    }

    if (fsrv->nyx_standalone) {

      fsrv->nyx_runner = fsrv->nyx_handlers->nyx_new(
          fsrv->target_path, x, fsrv->nyx_bind_cpu_id, MAX_FILE, true);

    } else {

      if (fsrv->nyx_parent) {

        fsrv->nyx_runner = fsrv->nyx_handlers->nyx_new_parent(
            fsrv->target_path, x, fsrv->nyx_bind_cpu_id, MAX_FILE, true);

      } else {

        fsrv->nyx_runner = fsrv->nyx_handlers->nyx_new_child(
            fsrv->target_path, x, fsrv->nyx_bind_cpu_id, fsrv->nyx_id);

      }

    }

    ck_free(x);

    if (fsrv->nyx_runner == NULL) { FATAL("Something went wrong ..."); }

    u32 tmp_map_size =
        fsrv->nyx_handlers->nyx_get_bitmap_buffer_size(fsrv->nyx_runner);
    fsrv->real_map_size = tmp_map_size;
    fsrv->map_size = (((tmp_map_size + 63) >> 6) << 6);
    if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }

    fsrv->trace_bits =
        fsrv->nyx_handlers->nyx_get_bitmap_buffer(fsrv->nyx_runner);

    fsrv->nyx_handlers->nyx_option_set_reload_mode(
        fsrv->nyx_runner, getenv("NYX_DISABLE_SNAPSHOT_MODE") == NULL);
    fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);

    fsrv->nyx_handlers->nyx_option_set_timeout(fsrv->nyx_runner, 2, 0);
    fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);

    fsrv->nyx_aux_string = malloc(0x1000);
    memset(fsrv->nyx_aux_string, 0, 0x1000);

    /* dry run */
    fsrv->nyx_handlers->nyx_set_afl_input(fsrv->nyx_runner, "INIT", 4);
    switch (fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner)) {

      case Abort:
        fsrv->nyx_handlers->nyx_shutdown(fsrv->nyx_runner);
        FATAL("Error: Nyx abort occured...");
        break;
      case IoError:
        FATAL("Error: QEMU-Nyx has died...");
        break;
      case Error:
        fsrv->nyx_handlers->nyx_shutdown(fsrv->nyx_runner);
        FATAL("Error: Nyx runtime error has occured...");
        break;
      default:
        break;

    }

    /* autodict in Nyx mode */
    if (!ignore_autodict) {

      x = alloc_printf("%s/workdir/dump/afl_autodict.txt", fsrv->out_dir_path);
      int nyx_autodict_fd = open(x, O_RDONLY);
      ck_free(x);

      if (nyx_autodict_fd >= 0) {

        struct stat st;
        if (fstat(nyx_autodict_fd, &st) >= 0) {

          u32 f_len = st.st_size;
          u8 *dict = ck_alloc(f_len);
          if (dict == NULL) {

            FATAL("Could not allocate %u bytes of autodictionary memory",
                  f_len);

          }

          u32 offset = 0, count = 0;
          u32 len = f_len;

          while (len != 0) {

            rlen = read(nyx_autodict_fd, dict + offset, len);
            if (rlen > 0) {

              len -= rlen;
              offset += rlen;

            } else {

              FATAL(
                  "Reading autodictionary fail at position %u with %u bytes "
                  "left.",
                  offset, len);

            }

          }

          offset = 0;
          while (offset < (u32)f_len &&
                 (u8)dict[offset] + offset < (u32)f_len) {

            fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                 (u8)dict[offset]);
            offset += (1 + dict[offset]);
            count++;

          }

          if (!be_quiet) { ACTF("Loaded %u autodictionary entries", count); }
          ck_free(dict);

        }

        close(nyx_autodict_fd);

      }

    }

    return;

  }

#endif

  if (!be_quiet) { ACTF("Spinning up the fork server..."); }

  // printf("check 1\n");

#ifdef AFL_PERSISTENT_RECORD
  if (unlikely(fsrv->persistent_record)) {

    fsrv->persistent_record_data =
        (u8 **)ck_alloc(fsrv->persistent_record * sizeof(u8 *));
    fsrv->persistent_record_len =
        (u32 *)ck_alloc(fsrv->persistent_record * sizeof(u32));

    if (!fsrv->persistent_record_data || !fsrv->persistent_record_len) {

      FATAL("Unable to allocate memory for persistent replay.");

    }

  }

#endif

  if (fsrv->use_fauxsrv) {

    /* TODO: Come up with some nice way to initialize this all */

    if (fsrv->init_child_func != fsrv_exec_child) {

      FATAL("Different forkserver not compatible with fauxserver");

    }

    if (!be_quiet) { ACTF("Using AFL++ faux forkserver..."); }
    fsrv->init_child_func = afl_fauxsrv_execv;

  }

  // printf("check 2\n");
  if (pipe(st_pipe) || pipe(ctl_pipe)) { PFATAL("pipe() failed"); }

  fsrv->last_run_timed_out = 0;
  fsrv->fsrv_pid = fork();

  if (fsrv->fsrv_pid < 0) { PFATAL("fork() failed"); }

  if (!fsrv->fsrv_pid) {

    /* CHILD PROCESS */

    // enable terminating on sigpipe in the childs
    struct sigaction sa;
    memset((char *)&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(SIGPIPE, &sa, NULL);

    // printf("check 3\n");

    struct rlimit r;

    if (!fsrv->cmplog_binary) {

      unsetenv(CMPLOG_SHM_ENV_VAR);  // we do not want that in non-cmplog fsrv

    }

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r);                        /* Ignore errors */

    }

    if (fsrv->mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)fsrv->mem_limit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r);                            /* Ignore errors */
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r);                          /* Ignore errors */
#endif                                                        /* ^RLIMIT_AS */

    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    if (!fsrv->debug) {

      r.rlim_max = r.rlim_cur = 0;
      setrlimit(RLIMIT_CORE, &r);                          /* Ignore errors */

    }

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();
    // printf("check 4\n");

    if (!(debug_child_output)) {
      // printf("check 4.0\n");

      dup2(fsrv->dev_null_fd, 1);
      dup2(fsrv->dev_null_fd, 2);

    }
    // printf("check 4.1\n");

    if (!fsrv->use_stdin) {
      // printf("check 4.2\n");

      dup2(fsrv->dev_null_fd, 0);

    } else {
      // printf("check 4.3\n");

      dup2(fsrv->out_fd, 0);
      close(fsrv->out_fd);

    }
    // printf("check 5\n");

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) { PFATAL("dup2() failed"); } // control
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) { PFATAL("dup2() failed"); } // status

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(fsrv->out_dir_fd);
    close(fsrv->dev_null_fd);
    close(fsrv->dev_urandom_fd);

    if (fsrv->plot_file != NULL) {

      fclose(fsrv->plot_file);
      fsrv->plot_file = NULL;

    }
    
    if(fsrv->bincov_file != NULL) {
        fclose(fsrv->bincov_file);
        fsrv->bincov_file = NULL;
      }
    // printf("check 6\n");
    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) { setenv("LD_BIND_NOW", "1", 1); }

    /* Set sane defaults for ASAN if nothing else is specified. */

    if (!getenv("ASAN_OPTIONS"))
      setenv("ASAN_OPTIONS",
             "abort_on_error=1:"
             "detect_leaks=0:"
             "malloc_context_size=0:"
             "symbolize=0:"
             "allocator_may_return_null=1:"
             "detect_odr_violation=0:"
             "handle_segv=0:"
             "handle_sigbus=0:"
             "handle_abort=0:"
             "handle_sigfpe=0:"
             "handle_sigill=0",
             1);

    /* Set sane defaults for UBSAN if nothing else is specified. */

    if (!getenv("UBSAN_OPTIONS"))
      setenv("UBSAN_OPTIONS",
             "halt_on_error=1:"
             "abort_on_error=1:"
             "malloc_context_size=0:"
             "allocator_may_return_null=1:"
             "symbolize=0:"
             "handle_segv=0:"
             "handle_sigbus=0:"
             "handle_abort=0:"
             "handle_sigfpe=0:"
             "handle_sigill=0",
             1);

    /* Envs for QASan */
    setenv("QASAN_MAX_CALL_STACK", "0", 0);
    setenv("QASAN_SYMBOLIZE", "0", 0);
    printf("check 7\n");

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    if (!getenv("MSAN_OPTIONS"))
      setenv("MSAN_OPTIONS",
           "exit_code=" STRINGIFY(MSAN_ERROR) ":"
           "symbolize=0:"
           "abort_on_error=1:"
           "malloc_context_size=0:"
           "allocator_may_return_null=1:"
           "msan_track_origins=0:"
           "handle_segv=0:"
           "handle_sigbus=0:"
           "handle_abort=0:"
           "handle_sigfpe=0:"
           "handle_sigill=0",
           1);

    /* LSAN, too, does not support abort_on_error=1. */

    if (!getenv("LSAN_OPTIONS"))
      setenv("LSAN_OPTIONS",
            "exitcode=" STRINGIFY(LSAN_ERROR) ":"
            "fast_unwind_on_malloc=0:"
            "symbolize=0:"
            "print_suppressions=0",
            1);

    // printf("before init_child_func\n");

    fsrv->init_child_func(fsrv, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
    FATAL("Error: execv to target failed\n");

  }

  /* PARENT PROCESS */

  char pid_buf[16];
  sprintf(pid_buf, "%d", fsrv->fsrv_pid);
  if (fsrv->cmplog_binary)
    setenv("__AFL_TARGET_PID2", pid_buf, 1);
  else
    setenv("__AFL_TARGET_PID1", pid_buf, 1);

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv->fsrv_ctl_fd = ctl_pipe[1];
  fsrv->fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  rlen = 0;
  if (fsrv->init_tmout) {

    u32 time_ms = read_s32_timed(fsrv->fsrv_st_fd, &status, fsrv->init_tmout,
                                 stop_soon_p);

    if (!time_ms) {

      s32 tmp_pid = fsrv->fsrv_pid;
      if (tmp_pid > 0) {

        kill(tmp_pid, fsrv->kill_signal);
        fsrv->fsrv_pid = -1;

      }

    } else if (time_ms > fsrv->init_tmout) {

      fsrv->last_run_timed_out = 1;
      s32 tmp_pid = fsrv->fsrv_pid;
      if (tmp_pid > 0) {

        kill(tmp_pid, fsrv->kill_signal);
        fsrv->fsrv_pid = -1;

      }

    } else {

      rlen = 4;

    }

  } else {

    rlen = read(fsrv->fsrv_st_fd, &status, 4);

  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {

    if (!be_quiet) { OKF("All right - fork server is up."); }

    init_copy_dir("/afltmp", "/aflfix");
    
    
    if (getenv("AFL_DEBUG")) {

      ACTF("Extended forkserver functions received (%08x).", status);

    }

    if ((status & FS_OPT_ERROR) == FS_OPT_ERROR)
      report_error_and_exit(FS_OPT_GET_ERROR(status));

    if ((status & FS_OPT_ENABLED) == FS_OPT_ENABLED) {

      // workaround for recent afl++ versions
      if ((status & FS_OPT_OLD_AFLPP_WORKAROUND) == FS_OPT_OLD_AFLPP_WORKAROUND)
        status = (status & 0xf0ffffff);

      if ((status & FS_OPT_NEWCMPLOG) == 0 && fsrv->cmplog_binary) {

        if (fsrv->qemu_mode || fsrv->frida_mode) {

          report_error_and_exit(FS_ERROR_OLD_CMPLOG_QEMU);

        } else {

          report_error_and_exit(FS_ERROR_OLD_CMPLOG);

        }

      }

      if ((status & FS_OPT_SNAPSHOT) == FS_OPT_SNAPSHOT) {

        fsrv->snapshot = 1;
        if (!be_quiet) { ACTF("Using SNAPSHOT feature."); }

      }

      if ((status & FS_OPT_SHDMEM_FUZZ) == FS_OPT_SHDMEM_FUZZ) {

        if (fsrv->support_shmem_fuzz) {

          fsrv->use_shmem_fuzz = 1;
          if (!be_quiet) { ACTF("Using SHARED MEMORY FUZZING feature."); }

          if ((status & FS_OPT_AUTODICT) == 0 || ignore_autodict) {

            u32 send_status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);
            if (write(fsrv->fsrv_ctl_fd, &send_status, 4) != 4) {

              FATAL("Writing to forkserver failed.");

            }

          }

        } else {

          FATAL(
              "Target requested sharedmem fuzzing, but we failed to enable "
              "it.");

        }

      }

      if ((status & FS_OPT_MAPSIZE) == FS_OPT_MAPSIZE) {

        u32 tmp_map_size = FS_OPT_GET_MAPSIZE(status) ;

        if (!fsrv->map_size) { fsrv->map_size = MAP_SIZE ; }

        fsrv->real_map_size = tmp_map_size;

        if (tmp_map_size % 64) {

          tmp_map_size = (((tmp_map_size + 63) >> 6) << 6);

        }

        if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }
        if (tmp_map_size > fsrv->map_size) {

          FATAL(
              "Target's coverage map size of %u is larger than the one this "
              "afl++ is set with (%u). Either set AFL_MAP_SIZE=%u and restart "
              " afl-fuzz, or change MAP_SIZE_POW2 in config.h and recompile "
              "afl-fuzz",
              tmp_map_size, fsrv->map_size, tmp_map_size);

        }

        fsrv->map_size = tmp_map_size;

      }

      // printf("[afl-forkserver, reach 1]\n");

      if ((status & FS_OPT_AUTODICT) == FS_OPT_AUTODICT) {

        if (!ignore_autodict) {

          if (fsrv->add_extra_func == NULL || fsrv->afl_ptr == NULL) {

            // this is not afl-fuzz - or it is cmplog - we deny and return
            if (fsrv->use_shmem_fuzz) {

              status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);

            } else {

              status = (FS_OPT_ENABLED);

            }

            if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

              FATAL("Writing to forkserver failed.");

            }

            return;

          }

          if (!be_quiet) { ACTF("Using AUTODICT feature."); }

          if (fsrv->use_shmem_fuzz) {

            status = (FS_OPT_ENABLED | FS_OPT_AUTODICT | FS_OPT_SHDMEM_FUZZ);

          } else {

            status = (FS_OPT_ENABLED | FS_OPT_AUTODICT);

          }

          if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

            FATAL("Writing to forkserver failed.");

          }

          if (read(fsrv->fsrv_st_fd, &status, 4) != 4) {

            FATAL("Reading from forkserver failed.");

          }

          if (status < 2 || (u32)status > 0xffffff) {

            FATAL("Dictionary has an illegal size: %d", status);

          }

          u32 offset = 0, count = 0;
          u32 len = status;
          u8 *dict = ck_alloc(len);
          if (dict == NULL) {

            FATAL("Could not allocate %u bytes of autodictionary memory", len);

          }

          while (len != 0) {

            rlen = read(fsrv->fsrv_st_fd, dict + offset, len);
            if (rlen > 0) {

              len -= rlen;
              offset += rlen;

            } else {

              FATAL(
                  "Reading autodictionary fail at position %u with %u bytes "
                  "left.",
                  offset, len);

            }

          }

          offset = 0;
          while (offset < (u32)status &&
                 (u8)dict[offset] + offset < (u32)status) {

            fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                 (u8)dict[offset]);
            offset += (1 + dict[offset]);
            count++;

          }

          if (!be_quiet) { ACTF("Loaded %u autodictionary entries", count); }
          ck_free(dict);

        }

      }

    }

    return;

  }

  if (fsrv->last_run_timed_out) {

    FATAL(
        "Timeout while initializing fork server (setting "
        "AFL_FORKSRV_INIT_TMOUT may help)");

  }

  if (waitpid(fsrv->fsrv_pid, &status, 0) <= 0) { PFATAL("waitpid() failed"); }

  if (WIFSIGNALED(status)) {

    if (fsrv->mem_limit && fsrv->mem_limit < 500 && fsrv->uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "run with '-m 0'.\n");

    } else if (!fsrv->mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! You can try the following:\n\n"

           "    - The target binary crashes because necessary runtime "
           "conditions it needs\n"
           "      are not met. Try to:\n"
           "      1. Run again with AFL_DEBUG=1 set and check the output of "
           "the target\n"
           "         binary for clues.\n"
           "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
           "analyze the\n"
           "         generated core dump.\n\n"

           "    - Possibly the target requires a huge coverage map and has "
           "CTORS.\n"
           "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

           MSG_FORK_ON_APPLE

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke <afl-users@googlegroups.com> for troubleshooting "
           "tips.\n");

    } else {

      u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! You can try the following:\n\n"

           "    - The target binary crashes because necessary runtime "
           "conditions it needs\n"
           "      are not met. Try to:\n"
           "      1. Run again with AFL_DEBUG=1 set and check the output of "
           "the target\n"
           "         binary for clues.\n"
           "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
           "analyze the\n"
           "         generated core dump.\n\n"

           "    - The current memory limit (%s) is too restrictive, causing "
           "the\n"
           "      target to hit an OOM condition in the dynamic linker. Try "
           "bumping up\n"
           "      the limit with the -m setting in the command line. A simple "
           "way confirm\n"
           "      this diagnosis would be:\n\n"

           MSG_ULIMIT_USAGE
           " /path/to/fuzzed_app )\n\n"

           "      Tip: you can use https://jwilk.net/software/recidivm to\n"
           "      estimate the required amount of virtual memory for the "
           "binary.\n\n"

           MSG_FORK_ON_APPLE

           "    - Possibly the target requires a huge coverage map and has "
           "CTORS.\n"
           "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke <afl-users@googlegroups.com> for troubleshooting "
           "tips.\n",
           stringify_mem_size(val_buf, sizeof(val_buf), fsrv->mem_limit << 20),
           fsrv->mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG) {

    FATAL("Unable to execute target application ('%s')", argv[0]);

  }

  if (fsrv->mem_limit && fsrv->mem_limit < 500 && fsrv->uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    run with '-m 0'.\n");

  } else if (!fsrv->mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete"
         " a\n"
         "handshake with the injected code. You can try the following:\n\n"

         "    - The target binary crashes because necessary runtime conditions "
         "it needs\n"
         "      are not met. Try to:\n"
         "      1. Run again with AFL_DEBUG=1 set and check the output of the "
         "target\n"
         "         binary for clues.\n"
         "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
         "analyze the\n"
         "         generated core dump.\n\n"

         "    - Possibly the target requires a huge coverage map and has "
         "CTORS.\n"
         "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

         "Otherwise there is a horrible bug in the fuzzer.\n"
         "Poke <afl-users@googlegroups.com> for troubleshooting tips.\n");

  } else {

    u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, looks like the target binary terminated "
        "before we could complete a\n"
        "    handshake with the injected code. You can try the following:\n\n"

        "%s"

        "    - The target binary crashes because necessary runtime conditions "
        "it needs\n"
        "      are not met. Try to:\n"
        "      1. Run again with AFL_DEBUG=1 set and check the output of the "
        "target\n"
        "         binary for clues.\n"
        "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
        "analyze the\n"
        "         generated core dump.\n\n"

        "    - Possibly the target requires a huge coverage map and has "
        "CTORS.\n"
        "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

        "    - The current memory limit (%s) is too restrictive, causing an "
        "OOM\n"
        "      fault in the dynamic linker. This can be fixed with the -m "
        "option. A\n"
        "      simple way to confirm the diagnosis may be:\n\n"

        MSG_ULIMIT_USAGE
        " /path/to/fuzzed_app )\n\n"

        "      Tip: you can use https://jwilk.net/software/recidivm to\n"
        "      estimate the required amount of virtual memory for the "
        "binary.\n\n"

        "    - The target was compiled with afl-clang-lto and a constructor "
        "was\n"
        "      instrumented, recompiling without AFL_LLVM_MAP_ADDR might solve "
        "your \n"
        "      problem\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other "
        "options\n"
        "      fail, poke <afl-users@googlegroups.com> for troubleshooting "
        "tips.\n",
        getenv(DEFER_ENV_VAR)
            ? "    - You are using deferred forkserver, but __AFL_INIT() is "
              "never\n"
              "      reached before the program terminates.\n\n"
            : "",
        stringify_int(val_buf, sizeof(val_buf), fsrv->mem_limit << 20),
        fsrv->mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}

/* Stop the forkserver and child */

void afl_fsrv_kill(afl_forkserver_t *fsrv) {

  if (fsrv->child_pid > 0) { kill(fsrv->child_pid, fsrv->kill_signal); }
  if (fsrv->fsrv_pid > 0) {

    kill(fsrv->fsrv_pid, fsrv->kill_signal);
    if (waitpid(fsrv->fsrv_pid, NULL, 0) <= 0) { WARNF("error waitpid\n"); }

  }

  close(fsrv->fsrv_ctl_fd);
  close(fsrv->fsrv_st_fd);
  fsrv->fsrv_pid = -1;
  fsrv->child_pid = -1;

#ifdef __linux__
  if (fsrv->nyx_mode) {

    free(fsrv->nyx_aux_string);
    fsrv->nyx_handlers->nyx_shutdown(fsrv->nyx_runner);

  }

#endif

}

/* Get the map size from the target forkserver */

u32 afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                         volatile u8 *stop_soon_p, u8 debug_child_output) {

  afl_fsrv_start(fsrv, argv, stop_soon_p, debug_child_output);
  return fsrv->map_size;

}

/* Delete the current testcase and write the buf to the testcase file */

void __attribute__((hot))
afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len) {

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    fsrv->nyx_handlers->nyx_set_afl_input(fsrv->nyx_runner, buf, len);
    return;

  }

#endif

#ifdef AFL_PERSISTENT_RECORD
  if (unlikely(fsrv->persistent_record)) {

    fsrv->persistent_record_len[fsrv->persistent_record_idx] = len;
    fsrv->persistent_record_data[fsrv->persistent_record_idx] = afl_realloc(
        (void **)&fsrv->persistent_record_data[fsrv->persistent_record_idx],
        len);

    if (unlikely(!fsrv->persistent_record_data[fsrv->persistent_record_idx])) {

      FATAL("allocating replay memory failed.");

    }

    memcpy(fsrv->persistent_record_data[fsrv->persistent_record_idx], buf, len);

    if (unlikely(++fsrv->persistent_record_idx >= fsrv->persistent_record)) {

      fsrv->persistent_record_idx = 0;

    }

  }

#endif

  if (likely(fsrv->use_shmem_fuzz)) {

    if (unlikely(len > MAX_FILE)) len = MAX_FILE;

    *fsrv->shmem_fuzz_len = len;
    memcpy(fsrv->shmem_fuzz, buf, len);
#ifdef _DEBUG
    if (getenv("AFL_DEBUG")) {

      fprintf(stderr, "FS crc: %016llx len: %u\n",
              hash64(fsrv->shmem_fuzz, *fsrv->shmem_fuzz_len, HASH_CONST),
              *fsrv->shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *fsrv->shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", fsrv->shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *fsrv->shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", buf[i]);
      fprintf(stderr, "\n");

    }

#endif

  } else {

    s32 fd = fsrv->out_fd;

    if (!fsrv->use_stdin && fsrv->out_file) {

      if (unlikely(fsrv->no_unlink)) {

        fd = open(fsrv->out_file, O_WRONLY | O_CREAT | O_TRUNC,
                  DEFAULT_PERMISSION);

      } else {

        unlink(fsrv->out_file);                           /* Ignore errors. */
        fd = open(fsrv->out_file, O_WRONLY | O_CREAT | O_EXCL,
                  DEFAULT_PERMISSION);

      }

      if (fd < 0) { PFATAL("Unable to create '%s'", fsrv->out_file); }

    } else if (unlikely(fd <= 0)) {

      // We should have a (non-stdin) fd at this point, else we got a problem.
      FATAL(
          "Nowhere to write output to (neither out_fd nor out_file set (fd is "
          "%d))",
          fd);

    } else {

      lseek(fd, 0, SEEK_SET);

    }

    // fprintf(stderr, "WRITE %d %u\n", fd, len);
    ck_write(fd, buf, len, fsrv->out_file);

    if (fsrv->use_stdin) {

      if (ftruncate(fd, len)) { PFATAL("ftruncate() failed"); }
      lseek(fd, 0, SEEK_SET);

    } else {

      close(fd);

    }

  }

}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */
// extern afl_state_t *my_global_afl;


fsrv_run_result_t __attribute__((hot))
afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                    volatile u8 *stop_soon_p) {

  s32 res;
  u32 exec_ms;
  u32 write_value = fsrv->last_run_timed_out;
  // u32 child_tmout = 0;

#ifdef __linux__
  if (fsrv->nyx_mode) {

    static uint32_t last_timeout_value = 0;

    if (last_timeout_value != timeout) {

      fsrv->nyx_handlers->nyx_option_set_timeout(
          fsrv->nyx_runner, timeout / 1000, (timeout % 1000) * 1000);
      fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);
      last_timeout_value = timeout;

    }

    enum NyxReturnValue ret_val =
        fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner);

    fsrv->total_execs++;

    switch (ret_val) {

      case Normal:
        return FSRV_RUN_OK;
      case Crash:
      case Asan:
        return FSRV_RUN_CRASH;
      case Timout:
        return FSRV_RUN_TMOUT;
      case InvalidWriteToPayload:
        /* ??? */
        FATAL("FixMe: Nyx InvalidWriteToPayload handler is missing");
        break;
      case Abort:
        fsrv->nyx_handlers->nyx_shutdown(fsrv->nyx_runner);
        FATAL("Error: Nyx abort occured...");
      case IoError:
        if (*stop_soon_p) {

          return 0;

        } else {

          FATAL("Error: QEMU-Nyx has died...");

        }

        break;
      case Error:
        FATAL("Error: Nyx runtime error has occured...");
        break;

    }

    return FSRV_RUN_OK;

  }

#endif
  /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

#ifdef __linux__
  if (!fsrv->nyx_mode) {
    memset(fsrv->trace_bits, 0, fsrv->map_size);
    

  }

#else
  memset(fsrv->trace_bits, 0, fsrv->map_size);
  
#endif

  /* we have the fork server (or faux server) up and running
  First, tell it if the previous run timed out. */

  if ((res = write(fsrv->fsrv_ctl_fd, &write_value, 4)) != 4) {

    if (*stop_soon_p) { return 0; }
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  fsrv->last_run_timed_out = 0;


  if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_pid, 4)) != 4) {
    

    
    if (*stop_soon_p) { return 0; }
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }
  

#ifdef AFL_PERSISTENT_RECORD
  // end of persistent loop?
  if (unlikely(fsrv->persistent_record &&
               fsrv->persistent_record_pid != fsrv->child_pid)) {

    fsrv->persistent_record_pid = fsrv->child_pid;
    u32 idx, val;
    if (unlikely(!fsrv->persistent_record_idx))
      idx = fsrv->persistent_record - 1;
    else
      idx = fsrv->persistent_record_idx - 1;
    val = fsrv->persistent_record_len[idx];
    memset((void *)fsrv->persistent_record_len, 0,
           fsrv->persistent_record * sizeof(u32));
    fsrv->persistent_record_len[idx] = val;

  }

#endif // AFL_PERSISTENT_RECORD

  if (fsrv->child_pid <= 0) {

    if (*stop_soon_p) { return 0; }

    if ((fsrv->child_pid & FS_OPT_ERROR) &&
        FS_OPT_GET_ERROR(fsrv->child_pid) == FS_ERROR_SHM_OPEN)
      FATAL(
          "Target reported shared memory access failed (perhaps increase "
          "shared memory available).");

    FATAL("Fork server is misbehaving (OOM?)");

  }
  
  exec_ms = read_s32_timed_multiprocess(fsrv->fsrv_st_fd, fsrv->domain_fd, &fsrv->child_status, timeout, stop_soon_p);

  
  if (exec_ms > timeout && my_global_afl->utility_timeout == 0) {

    s32 tmp_pid = fsrv->child_pid;
    printf("kill main bin pid: %d\n", tmp_pid);
    if (tmp_pid > 0) {

      kill(tmp_pid, fsrv->kill_signal);
      fsrv->child_pid = -1;
    }

    fsrv->last_run_timed_out = 1;
    printf("after main timeout, want to read from pipe %d\n", fsrv->fsrv_st_fd);
    if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }
    printf("after timeout, has read from pipe %d, exec_ms=%d\n", fsrv->fsrv_st_fd, exec_ms);

  }else if(exec_ms > timeout && my_global_afl->utility_timeout > 0){
    fsrv->last_run_timed_out = 1;
    ;
  }
   


  if (!exec_ms) {

    if (*stop_soon_p) { return 0; }
    SAYF("\n" cLRD "[-] " cRST
         "Unable to communicate with fork server. Some possible reasons:\n\n"
         "    - You've run out of memory. Use -m to increase the the memory "
         "limit\n"
         "      to something higher than %llu.\n"
         "    - The binary or one of the libraries it uses manages to "
         "create\n"
         "      threads before the forkserver initializes.\n"
         "    - The binary, at least in some circumstances, exits in a way "
         "that\n"
         "      also kills the parent process - raise() could be the "
         "culprit.\n"
         "    - If using persistent mode with QEMU, "
         "AFL_QEMU_PERSISTENT_ADDR "
         "is\n"
         "      probably not valid (hint: add the base address in case of "
         "PIE)"
         "\n\n"
         "If all else fails you can disable the fork server via "
         "AFL_NO_FORKSRV=1.\n",
         fsrv->mem_limit);
    RPFATAL(res, "Unable to communicate with fork server");

  }

  if (!WIFSTOPPED(fsrv->child_status)) { fsrv->child_pid = -1; }

  fsrv->total_execs++;

  /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  /* Report outcome to caller. */

  /* Was the run unsuccessful? */
  if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {

    return FSRV_RUN_ERROR;

  }

  /* Did we timeout? */
  if (unlikely(fsrv->last_run_timed_out)) {

    fsrv->last_kill_signal = fsrv->kill_signal;
    return FSRV_RUN_TMOUT;

  }

  /* Did we crash?
  In a normal case, (abort) WIFSIGNALED(child_status) will be set.
  MSAN in uses_asan mode uses a special exit code as it doesn't support
  abort_on_error. On top, a user may specify a custom AFL_CRASH_EXITCODE.
  Handle all three cases here. */

  if (unlikely(
          /* A normal crash/abort */
          /* WIFSIGNALED() 若为非0，表示程序异常终止 */
          (WIFSIGNALED(fsrv->child_status)) ||
          /* special handling for msan and lsan */
          (fsrv->uses_asan &&
           (WEXITSTATUS(fsrv->child_status) == MSAN_ERROR ||
            WEXITSTATUS(fsrv->child_status) == LSAN_ERROR)) ||
          /* the custom crash_exitcode was returned by the target */
          (fsrv->uses_crash_exitcode &&
           WEXITSTATUS(fsrv->child_status) == fsrv->crash_exitcode))) {

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(fsrv->persistent_record)) {

      char fn[PATH_MAX];
      u32  i, writecnt = 0;
      for (i = 0; i < fsrv->persistent_record; ++i) {

        u32 entry = (i + fsrv->persistent_record_idx) % fsrv->persistent_record;
        u8 *data = fsrv->persistent_record_data[entry];
        u32 len = fsrv->persistent_record_len[entry];
        if (likely(len && data)) {

          snprintf(fn, sizeof(fn), "%s/RECORD:%06u,cnt:%06u",
                   fsrv->persistent_record_dir, fsrv->persistent_record_cnt,
                   writecnt++);
          int fd = open(fn, O_CREAT | O_TRUNC | O_WRONLY, 0644);
          if (fd >= 0) {

            ck_write(fd, data, len, fn);
            close(fd);

          }

        }

      }

      ++fsrv->persistent_record_cnt;

    }

#endif // AFL_PERSISTENT_RECORD

    /* For a proper crash, set last_kill_signal to WTERMSIG, else set it to 0 */
    fsrv->last_kill_signal =
        WIFSIGNALED(fsrv->child_status) ? WTERMSIG(fsrv->child_status) : 0;
    return FSRV_RUN_CRASH;

  }

  /* success :) */
  return FSRV_RUN_OK;

}


#define LIST_FOREACH_ME(list, type, block)                            \
  do {                                                             \
                                                                   \
    list_t    *li = (list);                                        \
    element_t *head = get_head((li));                              \
    element_t *el_box = (head)->next;                              \
    if (!el_box) FATAL("foreach over uninitialized list");         \
    while (el_box != head) {                                       \
                                                                   \
      __attribute__((unused)) type *el = (type *)((el_box)->data); \
      /* get next so el_box can be unlinked */                     \
      element_t *next = el_box->next;                              \
      {block};                                                     \
      el_box = next;                                               \
                                                                   \
    }                                                              \
                                                                   \
  } while (0);

void afl_fsrv_killall() {

  LIST_FOREACH_ME(&fsrv_list, afl_forkserver_t, {

    afl_fsrv_kill(el);

  });

}

void afl_fsrv_deinit(afl_forkserver_t *fsrv) {

  afl_fsrv_kill(fsrv);
  list_remove(&fsrv_list, fsrv);

}

