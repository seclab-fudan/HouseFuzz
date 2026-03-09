/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

  // 写入其余proclist中的entry
  u8 procname[PATH_MAX];
  s32 fd_new;
  for(u32 i = 0; i< MAX_PROC_CNT; i++){
    if(afl->proc_list[i] == NULL || afl->proc_list[i]->bitmap_changed == 0){
      continue;
    }else{
      snprintf(procname, PATH_MAX,"%s/fuzz_bitmap_%d", afl->out_dir, afl->proc_list[i]->shmid);
      fd_new = open(procname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
      if(fd_new < 0){PFATAL("Unable to open '%s'", procname);}

      ck_write(fd_new, afl->proc_list[i]->virgin_bits, MAP_SIZE, procname);
      close(fd_new);
    }
  }
}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}



u32 proclist_count_bits(u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((MAP_SIZE + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}




/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2); // 这里似乎只是为了padding
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

u32 internel_count_bytes(u8* mem)
{
  u32 *ptr = (u32 *)mem;
  u32  i = ((MAP_SIZE + 3) >> 2);
  u32  ret = 0;
  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;
}


u32 proclist_count_bytes(afl_state_t *afl)
{
  u32 entry = 0;
  u32 ret = 0;
  for(entry = 0; entry < MAX_PROC_CNT; entry ++){
    if(afl->proc_list[entry] == NULL){
      break;
    }
    if(afl->proc_list[entry]->activated){
      if(proc_in_blacklist(afl, afl->proc_list[entry])){
          continue;
        }
        ret += internel_count_bytes(afl->proc_list[entry]->trace_bits);
    }
  }
  return ret;
}

// 计算所有activated的程序的bytes情况
u32 proclist_count_non_255_bytes(u8* mem){
  u32 *ptr = (u32 *)mem;
  u32  i = ((MAP_SIZE + 3) >> 2);
  u32  ret = 0;
  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;
}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  // 下面这边后面的判断是判断地址是否相同，这有啥意义
  // 有的时候还用在virgin_crash上
  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}


/* 返回1如果只是hit-count发生了变化，返回2如果有新的二元组发现 */
u8 proclist_has_new_bits(struct proc_entry* entry) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)entry->trace_bits;
  u64 *virgin = (u64 *)entry->virgin_bits;

  u32 i = ((MAP_SIZE + 7) >> 3);

#else

  u32 *current = (u32 *)entry->trace_bits;
  u32 *virgin = (u32 *)entry->virgin_bits;

  u32 i = ((MAP_SIZE + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin); // 在这里会修改virgin bits

    current++;
    virgin++;

  }

  // 3.4 下面修改为entry->virgin_bits，这个内容可能在很多地方被写入，需要关注
  // virgin bits是不是就是之前的virgin_map的一个备份
  if (unlikely(ret))
    entry->bitmap_changed = 1;

  return ret;

}


// 和上面函数不同的地方在于这里针对entry的crash_bits进行写入，用来判断是否有新的crash 覆盖率 上面是virgin bits，用来判断是否有新的覆盖率
u8 proclist_has_new_crash_bits(struct proc_entry* entry) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)entry->trace_bits;
  u64 *virgin = (u64 *)entry->crash_bits;

  u32 i = ((MAP_SIZE + 7) >> 3);

#else

  u32 *current = (u32 *)entry->trace_bits;
  u32 *virgin = (u32 *)entry->crash_bits;

  u32 i = ((MAP_SIZE + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin); // 在这里会修改virgin bits

    current++;
    virgin++;

  }


  return ret;

}



/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  return has_new_bits(afl, virgin_map);

}


u32 proc_in_blacklist(afl_state_t *afl, struct proc_entry* proc){
  for(u32 i = 0; i < afl->blacklist_proc_cnt; i++){
    // printf("cmp: (%s, %s)", proc->prog_name, afl->blacklist_proc[i]);
    if(proc->prog_name!= NULL && strcmp(proc->prog_name, afl->blacklist_proc[i]) == 0){
      // printf("found in blacklist: %s\n", proc->prog_name);
      return 1;
    }
  }
  return 0;
  
}


/* 上has_new_bits_unclassified的改写版本，通过循环遍历所有activated的程序。
 *   
*/
// inline u8 proclist_has_new_bits_unclassified(afl_state_t *afl){
u8 proclist_has_new_bits_unclassified(afl_state_t *afl){
  
  int change_cnt = 0;
  int change_target[MAX_PROC_CNT]; // 存放发生改变的program entry
  memset(change_target, 0, MAX_PROC_CNT*sizeof(int));
  // 之后需要根据proc_list查看其余activated进程，检查他们的情况
  // 这里似乎不能用加速的方法
  for(u32 count = 0; count < MAX_PROC_CNT; count++){
    if(afl->proc_list[count] != NULL){
      // FILE *myfp = fopen("afl_states.log","a+");
      // fprintf(myfp, "[proclist_has_new_bits_unclassified] shmid=%d activated=%d\n", afl->proc_list[count]->shmid, afl->proc_list[count]->activated);
      // fclose(myfp);
      if(afl->proc_list[count]->activated){
        if(proc_in_blacklist(afl, afl->proc_list[count])){
          continue;
        }

        // 需要检查activated进程的coverage map，查看是否有新的bit出现
          // FILE *myfp = fopen("afl_states.log","a+");
          // fprintf(myfp, "[proclist_has_new_bits_unclassified] shmid=%d activated\n", afl->proc_list[count]->shmid);
          // fclose(myfp);
        u8* end = afl->proc_list[count]->trace_bits + MAP_SIZE;
          #ifdef WORD_SIZE_64
            if (skim((u64 *)afl->proc_list[count]->virgin_bits, (u64 *)afl->proc_list[count]->trace_bits, (u64 *)end))
              change_target[change_cnt++] = count;
          #else
            if (skim((u32 *)afl->proc_list[count]->virgin_bits, (u32 *)afl->proc_list[count]->trace_bits, (u32 *)end))
              change_target[change_cnt++] = count;
          #endif                                                     /* ^WORD_SIZE_64 */
      }
    }else{
      break;
    }
  }
  // 现在change_target中是发生新路径的目标进程的下标
  int ret = 0;
  int ret_temp = 0;
  if(change_cnt == 0){
    return 0; // 快速返回
  }else{
    for(int i = 0; i< change_cnt; i++){
        proclist_classify_counts(afl->proc_list[change_target[i]]->trace_bits);
        afl->proc_list[change_target[i]]->classified = 1;
        ret_temp = proclist_has_new_bits(afl->proc_list[change_target[i]]); // 在这里回修改virgin bits

        // FILE* state_fp = fopen("/afl_states.log", "a+");
        // fprintf(state_fp, "[proclist_has_n] change_cnt = %d, shmid = %d has ret_tmp = %d\n", change_cnt, afl->proc_list[change_target[i]]->shmid, ret_temp); // 这里打印出了结果，说明子进程等已经把结果写到共享内存了
        // fclose(state_fp);

        if(ret_temp > ret){
          ret = ret_temp; // 只返回较大的数字，因为较大的数字说明有更好的情况发生
        }
    }
  }
  
  return ret;

}

unsigned int aflmulti_count_ipc_distance(afl_state_t *afl){
  // 目前(0324)是按照最小距离计算的，暂时不管总count

  u32 total_distance = -1;

  // 首先考虑主进程
  u64 minimal_distance = *(u64*)(afl->fsrv.trace_bits + afl->fsrv.map_size);
  u32 ipc_prog_count = 0;
  u32 result_score = 0;

  if(minimal_distance != 0){
    // 有距离记录
    total_distance = minimal_distance;
    ipc_prog_count += 1;
  }

  // 在子进程中查找距离信息
  for(u32 cnt = 0; cnt < MAX_PROC_CNT; cnt++){
    if(afl->proc_list[cnt] != NULL){
      if(afl->proc_list[cnt]->activated){
        // 计算子进程ipc距离信息
        // *(unsigned long int*)(&afl->proc_list[cnt]->trace_bits[MAP_SIZE])
        u64 minimal_distance_other = *(unsigned long int*)(&(afl->proc_list[cnt]->trace_bits[MAP_SIZE]));
        if(minimal_distance_other != 0){
          total_distance += minimal_distance_other;
          ipc_prog_count += 1;
        }
      }
    }
  }

  if(ipc_prog_count != 0){
    result_score = total_distance / ipc_prog_count; // 这个整数越小(最小为1)，说明IPC分数越高
    // printf("[count_ipc_distance], total_distance:%d, ipc_prog_count:%d\n", total_distance, ipc_prog_count);
    return result_score;
  }

  return 0;

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */
// 只记录当前路径是否被执行，而不记录执行次数。因此可以将8bit压缩为1bit

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

/* 新加入一个特性: 除了coverage之外，还要加上是否触发了IPC，用activated表示*/

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  u8 is_timeout = 0;
  u8 has_ipc = 0;
  char ipc_buf[0x10];
  memset(ipc_buf, 0, 0x10);
  
  for(u32 cnt = 0; cnt < MAX_PROC_CNT; cnt++){
    if(afl->proc_list[cnt] == NULL){
      break;
    }
    if(proc_in_blacklist(afl, afl->proc_list[cnt])){
          continue;
    }
    if(afl->proc_list[cnt]->activated == 1){
      has_ipc +=1 ;
    }
  }

  if (new_bits & 0xf0) {

    new_bits -= 0x80;
    is_timeout = 1;

  }

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) { // splice的意思是铰接

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu,execs:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time,
            afl->fsrv.total_execs);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov") - 2;
      if (is_timeout) { size_left -= strlen(",+tout"); }
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);


      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);


      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

        

      }

    }

  }

  if (is_timeout) { strcat(ret, ",+tout"); }

  if (new_bits == 2) { strcat(ret, ",+cov"); }

  if(has_ipc){
          snprintf(ipc_buf, 0x10, ",ipc:%d", has_ipc);
          strcat(ret, ipc_buf);
        }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}

#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "post\n"
      "to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the "
      "issues\n"
      " are fixed :)\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 __attribute__((hot))
save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {

  if (unlikely(len == 0)) { return 0; }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, proclist_classfied = 0, is_timeout = 0, proclist_new_bits = 0;
  // unsigned int ipc_distance = 0;
  u8 bigger_newbits = 0;
  s32 fd;
  u64 cksum = 0;
  u32 bg_newbits = 0;
  u32 bg_newbits_tmp = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  /* fast是默认的AFL调度方式 */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    u64 _tmp_;
    _tmp_ = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    for(int i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] != NULL){

        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }
        if(afl->proc_list[i]->activated == 1){
          // printf("proclist_%d has activated with shmid %d\n", i, afl->proc_list[i]->shmid);

            u64 middle_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE ,HASH_CONST);
            _tmp_ ^= middle_result;
        }
        
      }else{
        break;
      }
    }
    cksum = _tmp_;

    /* Saturated increment */
    /* 大概是一个简易的本地记录覆盖率信息的内容? */
    /*一种HIT概率的计算方式，n_fuzz[i]数字越大标识某个分支执行越多 默认FAST，所以会执行到这里*/
    /* 能否直接将cksum改成和多个map的亦或结果，但是需要改动的地方非常多*/
    if (afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF)
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  if (likely(fault == afl->crash_mode || (afl->meets_bug == 0 && afl->meets_cmdinj == 0 && fault != afl->crash_mode))) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);
    proclist_new_bits = proclist_has_new_bits_unclassified(afl);
    // printf("[save_if_interesting] proclist_new_bits=%d\n", proclist_new_bits); // 这里打印出了结果，说明子进程等已经把结果写到共享内存了
    
    // ipc distance暂时不考虑
    // ipc_distance = aflmulti_count_ipc_distance(afl);

    // printf("[save_if_interesting], got ipc_distance=%d\n", ipc_distance);
    // ipc_distance当没有触发的时候是0
    // if(ipc_distance > 0){
    //   if(afl->queue_cur->ipc_distance == 0){
    //     // 第一次写入
    //     afl->queue_cur->ipc_distance = ipc_distance;
    //   }else{
    //     // 写入更小的,作为queue_cur的ipc_distance
    //     afl->queue_cur->ipc_distance = afl->queue_cur->ipc_distance < ipc_distance ? afl->queue_cur->ipc_distance : ipc_distance;
    //   }
    // }
    


    if (likely(!new_bits && !proclist_new_bits)) {

      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    }

    classified = new_bits;
    proclist_classfied = proclist_new_bits;

  save_to_queue:

#ifndef SIMPLE_FILES

    queue_fn =
        alloc_printf("%s/queue/id:%06u,%s.raw", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,.raw")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u.raw", afl->out_dir, afl->queued_items);

#endif                                                    /* ^!SIMPLE_FILES */
    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, mem, len, queue_fn);
    close(fd);
    add_to_queue(afl, queue_fn, len, 0);

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2 || proclist_new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    /* AFLFast schedule? update the new queue entry */
    if (cksum) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* due to classify counts we have to recalculate the checksum */
    u64 _tmp_;
    _tmp_ = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    for(int i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] != NULL){

        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }
        if(afl->proc_list[i]->activated == 1){

            u64 middle_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE ,HASH_CONST);
            _tmp_ ^= middle_result;
        }
        
      }else{
        break;
      }
    }
    afl->queue_top->exec_cksum = _tmp_;

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

  }

  // 这里新增一条检查afl->meets_bug的,如果是也将fault标记为FSRV_RUN_CRASH
  if(afl->meets_bug){
    fault = BG_CRASH;
  }else if(afl->meets_cmdinj){
    fault = BG_CMDINJ;
  }

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        

        // 超时的时候也需要考虑其他进程覆盖情况
        
        // proclist_has_new_bits_unclassified(afl);
        if(!proclist_classfied){
        for(int i = 0; i < MAX_PROC_CNT; i++){
            if(afl->proc_list[i] == NULL){
              break;
            }
            if(proc_in_blacklist(afl, afl->proc_list[i])){
              continue;
            }
            if(afl->proc_list[i]->activated != 0){
              proclist_classify_counts(afl->proc_list[i]->trace_bits);
              afl->proc_list[i]->classified=1;
              proclist_simplify_trace(afl->proc_list[i]->trace_bits);
            }
          }
          proclist_classfied = 1;
        }

        if (has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8 new_fault;
        len = write_to_testcase(afl, &mem, len, 0);
        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_main_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->saved_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case BG_CMDINJ:
      // cmdinj没办法检查，就直接保存吧
      // 在一开始就要清除meets_bug和meets_cmdinj，否则后面一直是cmding
      
      afl->meets_cmdinj = false;
      ++afl->total_cmdinj;
      if (afl->saved_cmdinj >= KEEP_UNIQUE_CRASH) { return keeping; }
      if (unlikely(!afl->saved_crashes) &&(afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

      // 关于cmdinj 因为只会发生在一个进程(dash)中，所以要去重需要考虑所有activate进程的bitmap,看他们的virgin map是否发生变化
      // 直接重用crash bitmap可以吗?
      
      for(int i = 0; i < MAX_PROC_CNT; i++){
        if(afl->proc_list[i] == NULL){
          break;
        }
        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }
        if(afl->proc_list[i]->activated == 1){
            proclist_simplify_trace(afl->proc_list[i]->trace_bits);
            bg_newbits = proclist_has_new_crash_bits(afl->proc_list[i]);
            if(bg_newbits > bigger_newbits){
              bigger_newbits = bg_newbits;
            }
            break;
        }

      }
      // 主进程
      simplify_trace(afl, afl->fsrv.trace_bits);
      if(!has_new_bits(afl, afl->virgin_crash)){
        if(bigger_newbits == 0){
          // 主进程，子进程都没有发现新的coverage
          clear_bug_status(afl);
          return keeping;
        }
      }

      
      

#ifndef SIMPLE_FILES

        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,shmid:%06d,cmdinj,%s", afl->out_dir,
                afl->saved_crashes,afl->bg_crash->shmid,
                describe_op(afl, 0, NAME_MAX - strlen("id:000000,shmid:000000,cmdinj")));
        
      

#else

        // 如果是主程序发生段错误，使用原先的命名方式
        snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu,shmid:%06d,cmdinj,%s", afl->out_dir,
               afl->saved_crashes,afl->bg_crash->shmid,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,shmid:000000,cmdinj")));
      

#endif                                                    /* ^!SIMPLE_FILES */

      clear_bug_status(afl);
      ++afl->saved_crashes;
      ++afl->saved_cmdinj;
      break;

    case BG_CRASH:
      
      // 首先计算出现bug的进程中virgin crash是否有new bits


      for(int i = 0; i < MAX_PROC_CNT; i++){
        if (!afl->proc_list[i]) {
          break;
        }
        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }
        if(afl->proc_list[i]->shmid == afl->bg_crash->shmid){
            if(afl->proc_list[i]->classified == 0){
              proclist_classify_counts(afl->proc_list[i]->trace_bits);
              afl->proc_list[i]->classified = 1;
            }
            proclist_simplify_trace(afl->proc_list[i]->trace_bits);
            bg_newbits_tmp = proclist_has_new_crash_bits(afl->proc_list[i]);
            if(bg_newbits_tmp > bg_newbits){
              bg_newbits = bg_newbits_tmp;
            }
            break;
        }
      }
      //lbw[[fallthrough]];
      /* fall ... */
    case FSRV_RUN_CRASH:

    keep_as_main_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */
      

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {
        // 这里似乎是判断当前出现的fault是不是和之前trace map一样的，如果是一样的就不写入
        // 在qemu_mode下，non_instrumented_mode也是0，所以会进入这个判断。
        // proclist_classfied=0说明background程序的map没有new bits
        // 不过既然都看了没有新的bits，为什么还要再检查一遍

        if (!classified) { classify_counts(&afl->fsrv); }
        // if (!proclist_classfied) {proclist_has_new_bits_unclassified(afl); }
        

        // simplify_trace(afl, afl->fsrv.trace_bits);

        // AFL++原先算法，就是下面两行 只考虑了主进程中virgin_crash bits是否增加
        simplify_trace(afl, afl->fsrv.trace_bits);
        if (!has_new_bits(afl, afl->virgin_crash)) {
            // bg_newbits默认是0，再主进程覆盖率没有变化的时候检查bg_newbits是否变化，如果也没变化就不保存，否则就保存
            if(!bg_newbits){

                clear_bug_status(afl);
                return keeping; 
            }
           }

      }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

        if(afl->meets_bug == false){
          snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal,
                describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));
        }else{
          snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,shmid:%02u,addr:0x%x", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal,afl->bg_crash->shmid,afl->bg_crash->addr);
        }

#else

        // 如果是主程序发生段错误，使用原先的命名方式
        snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      clear_bug_status(afl);

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, mem, len, fn);
  close(fd);

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string, 0x1000);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);

  }

#endif

  return keeping;

}



// 消除两个相邻的pair,是nvram bitmap的计算方式
void singlefy_nvram_bits(u8* bitmap){
  unsigned int* now_bitmap_unit = (unsigned int*) bitmap;
  for(unsigned int i = 0; i < 4096 / sizeof(unsigned int); i+=4){
        unsigned int tmp1 = ((now_bitmap_unit[i] & 0b10101010101010101010101010101010)>>1) ^ (now_bitmap_unit[i] & 0b01010101010101010101010101010101);
        unsigned int tmp2 = ((now_bitmap_unit[i+1] & 0b10101010101010101010101010101010)>>1) ^ (now_bitmap_unit[i+1] & 0b01010101010101010101010101010101);
        unsigned int tmp3 = ((now_bitmap_unit[i+2] & 0b10101010101010101010101010101010)>>1) ^ (now_bitmap_unit[i+2] & 0b01010101010101010101010101010101);
        unsigned int tmp4 = ((now_bitmap_unit[i+3] & 0b10101010101010101010101010101010)>>1) ^ (now_bitmap_unit[i+3] & 0b01010101010101010101010101010101);
        tmp1 |= (tmp1 << 1);
        now_bitmap_unit[i] &= tmp1;
        tmp2 |= (tmp2 << 1);
        now_bitmap_unit[i+1] &= tmp2;
        tmp3 |= (tmp3 << 1);
        now_bitmap_unit[i+2] &= tmp3;
        tmp4 |= (tmp4 << 1);
        now_bitmap_unit[i+3] &= tmp4;
    }
}






int __attribute__((hot))
calculate_pair(u8* now_bitmap, u8* other_bitmap){
  // step1: 按照两bit为一个单位，去除两个bitmap中两个bit都为1的位置，设置成都为0
  // step2: 将两个bitmap进行and操作
  // step3: 判断两个bitmap and之后的结果中，按照两bit为一个单位，判断是否出现两个bit都为1的情形，如果是返回true，否则返回false
  // 这两个bitmap都是经过singlefy的，因此可以直接and
  unsigned int* now_bitmap_unit = (unsigned int*) now_bitmap;
  unsigned int* other_bitmap_unit = (unsigned int*) other_bitmap;
  unsigned int* tmp_bitmap = (unsigned int*)malloc(4096);

  for(unsigned int i = 0; i < 4096 / sizeof(unsigned int); i+=4){
    tmp_bitmap[i] = now_bitmap_unit[i] & other_bitmap_unit[i]; 
    tmp_bitmap[i+1] = now_bitmap_unit[i+1] & other_bitmap_unit[i+1]; 
    tmp_bitmap[i+2] = now_bitmap_unit[i+2] & other_bitmap_unit[i+2]; 
    tmp_bitmap[i+3] = now_bitmap_unit[i+3] & other_bitmap_unit[i+3]; 
  }

  // 检查上述结果tmp_bitmap是否存在3
  for (unsigned int i = 0; i < 4096 / sizeof(unsigned int); i++) {
        if ((tmp_bitmap[i] & 0b11000000110000001100000011000000) ||
            (tmp_bitmap[i] & 0b00110000001100000011000000110000) ||
            (tmp_bitmap[i] & 0b00001100000011000000110000001100) || 
            (tmp_bitmap[i] & 0b00000011000000110000001100000011)){
            return 1; // true
        }
    }
    return 0;
}



// 返回值将增加到afl->queued_discovered
u8 __attribute__((hot))
save_if_interesting_json(afl_state_t *afl, void *mem, u32 len, u8 fault, json_t* input_json) {

  if (unlikely(len == 0)) { return 0; }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, proclist_classfied = 0, is_timeout = 0, proclist_new_bits = 0;
  u8  bigger_newbits = 0;
  // unsigned int ipc_distance = 0;
  u64 cksum = 0;
  u32 bg_newbits = 0, bg_newbits_tmp = 0;
  int dump_result = 0;

  /* Update path frequency. */
  // printf("[save_if_interesting_json], stage,1\n");

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  /* fast是默认的AFL调度方式 */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    u64 _tmp_;
    _tmp_ = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    for(int i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] != NULL){
        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }

        if(afl->proc_list[i]->activated == 1){
          // FILE* state_fp = fopen("/afl_states.log", "a+");
          // fprintf(state_fp, "proclist_%d has activated with shmid %d\n", i, afl->proc_list[i]->shmid);
          // fclose(state_fp);

            u64 middle_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE ,HASH_CONST);
            _tmp_ ^= middle_result;
        }
        
      }else{
        break;
      }
    }
    cksum = _tmp_;

    /* Saturated increment */
    /* 大概是一个简易的本地记录覆盖率信息的内容? */
    /*一种HIT概率的计算方式，n_fuzz[i]数字越大标识某个分支执行越多 默认FAST，所以会执行到这里*/
    /* 能否直接将cksum改成和多个map的亦或结果，但是需要改动的地方非常多*/
    if (afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF)
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }
  // printf("[save_if_interesting_json], stage,2\n");
  // FILE* states_fp = fopen("/afl_states.log", "a+");
  // fprintf(states_fp, "[save_int_json] before has_new_bits_unclassified judge, meets_bug=%d\n", afl->meets_bug);
  // fclose(states_fp);

  // 原本算法是主进程没有触发crash的时候才保存为queue
  // 但是有时经过主进程-->子进程-->主进程crash的场景，这个时候因为触发了子进程所以最好也保存覆盖率，尽管这个时候主进程可能crash了
  // 修改为：主进程没有触发漏洞||主进程触发漏洞并且子进程没有触发漏洞
  // if (fault == afl->crash_mode ||(afl->meets_bug == 0 && afl->meets_cmdinj == 0 && fault != afl->crash_mode)) {
  // 主进程子进程都没有漏洞时考虑保存queue
  if (fault == afl->crash_mode && !afl->meets_bug && !afl->meets_cmdinj) {

    // 如果fault=crash的时候，不会进入这个循环？？？？
    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);
    proclist_new_bits = proclist_has_new_bits_unclassified(afl);
    // printf("[save_if_interesting_json], stage,3\n");
    // FILE* states_fp = fopen("/afl_states.log", "a+");
    // fprintf(states_fp, "[save_int_json] new_bits=%d, proclist_new_bits=%d\n", new_bits, proclist_new_bits);
    // fclose(states_fp);
    
    

    


    if (likely(!new_bits && !proclist_new_bits)) {

      // 没有新的覆盖率产生就返回0，同时不改变queue_cur
      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      // FILE* state_fp = fopen("/afl_states.log", "a+");
      // fprintf(state_fp, "[inside] !new_bits && !proclist_new_bits, meets_bug=%d\n", afl->meets_bug);
      // fclose(state_fp);
      return 0;

    }

    classified = new_bits;
    proclist_classfied = proclist_new_bits;

  // 有覆盖率产生就保存到queue中。首先保存到文件
  save_to_queue:

    // 之后保存到queue队列中
    if(input_json != NULL){
      queue_fn =alloc_printf("%s/queue/id:%06u,%s", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,")));
        dump_result = json_dump_file(input_json, queue_fn, JSON_ENCODE_ANY);
        if (unlikely(dump_result < 0)) { printf("Error: %s\n", strerror(errno)); PFATAL("Unable to dump '%s'", queue_fn); }
        
        // 在add_to_queue中完成了nvram_calculate以及singlefy_nvram_bits
        // add_to_queue直接将queue变成当前queue_top 而不是queue->cur
        add_to_queue(afl, queue_fn, len, 0);

        // 还需要将当前json格式的seed保存到raw格式，供后面使用
        // 临时修改0921,0923改
        queue_fn =
          alloc_printf("%s/queue/id:%06u,%s.raw", afl->out_dir, afl->queued_items,
                        describe_op(afl, new_bits + is_timeout,
                                    NAME_MAX - strlen("id:000000,.raw")));
        size_t input_len = 0;
        char* to_http_seed = json_to_http(input_json, &input_len);
        int fd_tohttp_seed = open(queue_fn,  O_WRONLY| O_CREAT |O_EXCL, DEFAULT_PERMISSION);
        if(unlikely(fd_tohttp_seed < 0)) {PFATAL("Unable to create '%s'", queue_fn);}
        ck_write(fd_tohttp_seed, to_http_seed, input_len, queue_fn);
        close(fd_tohttp_seed);
        free(to_http_seed);
        add_to_queue(afl, queue_fn, input_len, 0);
    }else{
      // input_json == NULL
      // 非json状态下的保存，替换了原先的common_fuzz_stuff中的save_if_interesting
      queue_fn =alloc_printf("%s/queue/id:%06u,%s.raw", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,")));
      int fd_raw = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
      if (unlikely(fd_raw < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
      ck_write(fd_raw, mem, len, queue_fn);
      close(fd_raw);
      add_to_queue(afl, queue_fn, len, 0);
    }

    


#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2 || proclist_new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }
    // printf("[save_if_interesting_json], stage,4\n");

    // 检查nvram行为，每一个queue都有一个map, fuzzer需要找到这个map的读写和之前所有testcase读写之间的关系
    // 例如一个nvram在某个queue中被读取，就要寻找是否在之前所有的queue对nvram的操作中被写入过
    // 同时也要记录对于新的读取或者写入的nvram
    // 有没有可能直接使用bitmap级别的and，和之前所有queue的nvram_bitmap进行与操作，如果得到结果为3说明有read和write
    // 则他们可以作为一个pair或者group,进行fuzzing
    // 需要设置一个pair fuzzing模式，他不直接清空nvram_bits，而是在指定的时候清空
    // 24-6-14
    /*
    int *pair_case = (int*)malloc(1024*sizeof(int));
    int pair_cnt = 0;
    for(u32 i = 0; i < afl->queued_items; i++){
      int is_pair = 0;
      if(afl->queue_buf[i] == NULL){
        continue;
      }else{
        // 如果不这样，假如某个queue自己有一个3，那么和其他所有queue都能够成为pair
        // 那么calculate_pair计算之前就要先去除所有的3，之后再and
        // 最终应该将pair信息保存到queue中，每个queue有一个数组pair_case，储存了和自己成为pair的queue的下标
        is_pair = calculate_pair(afl->queue_buf[i]->nvram_bitmap, afl->queue_top->nvram_bitmap);
        if(is_pair){
          pair_case[pair_cnt++] = i;
        }
      }
    }
    afl->queue_top->pair_case = pair_case;
    */

    /* AFLFast schedule? update the new queue entry */
    if (cksum) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* due to classify counts we have to recalculate the checksum */
    u64 _tmp_;
    _tmp_ = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    for(int i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] != NULL){
        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }

        if(afl->proc_list[i]->activated == 1){

            u64 middle_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE ,HASH_CONST);
            _tmp_ ^= middle_result;
        }
        
      }else{
        break;
      }
    }
    afl->queue_top->exec_cksum = _tmp_;
    // printf("[save_if_interesting_json], stage,5\n");

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    if(afl->meets_bug){
      // FILE* bitmap_fp = fopen("/bitmap.log", "a+");
      // fprintf(bitmap_fp, "[before] calibrate_case, afl->meets_bug=%d, top_queue_len=%d\n", afl->meets_bug,afl->queue_top->len);
      // fprintf(bitmap_fp, "queue_top: \n");
      // json_t* json_root = queue_testcase_get_json(afl, afl->queue_top);
      // fprintf(bitmap_fp, "%s\n", json_dumps(json_root, JSON_ENCODE_ANY));
      // fclose(bitmap_fp);
    }
    // printf("[save_if_interesting_json], stage,6\n");
    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    // FILE* bitmap_fp = fopen("/bitmap.log", "a+");
    // fprintf(bitmap_fp, "[after] calibrate_case, afl->meets_bug=%d, top_queue_len=%d\n", afl->meets_bug, afl->queue_top->len);
    // fclose(bitmap_fp);

    // FILE* state_fp = fopen("/afl_states.log", "a+");
    // fprintf(state_fp, "[after] calibrate_case, afl->meets_bug=%d, top_queue_len=%d\n", afl->meets_bug, afl->queue_top->len);
    // fclose(state_fp);
    
    

    if (likely(afl->q_testcase_max_cache_size) && input_json != NULL) {

      // 保存json内容到q->root中，可能是为了避免重复从磁盘读取文件
      queue_testcase_store_mem_json(afl, afl->queue_top, input_json);

    }else if(likely(afl->q_testcase_max_cache_size) && input_json == NULL){
      queue_testcase_store_mem(afl, afl->queue_top, mem);
    }

    keeping = 1;

  }
  // printf("[save_if_interesting_json], stage,7\n");

  // 这里新增一条检查afl->meets_bug的,如果是也将fault标记为FSRV_RUN_CRASH
  if(afl->meets_bug){
    fault = BG_CRASH;
  }else if(afl->meets_cmdinj){
    fault = BG_CMDINJ;
  }
  // 还可能是afl->crash_mode != fault
  // FILE* bitmap_fp = fopen("/bitmap.log", "a+");
  // FILE* state_fp = fopen("/afl_states.log", "a+");
  

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */
      // printf("[save_if_interesting_json], stage,8\n");

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        

        // 超时的时候也需要考虑其他进程覆盖情况
        proclist_has_new_bits_unclassified(afl);

        for(int i = 0; i < MAX_PROC_CNT; i++){
            if(afl->proc_list[i] == NULL){
              break;
            }
            if(proc_in_blacklist(afl, afl->proc_list[i])){
              continue;
            }
            if(afl->proc_list[i]->activated != 0){
              proclist_classify_counts(afl->proc_list[i]->trace_bits);
              afl->proc_list[i]->classified = 1;
              proclist_simplify_trace(afl->proc_list[i]->trace_bits);
            }
          }

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8 new_fault;
        len = write_to_testcase(afl, &mem, len, 0);
        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon) {
          
          if (new_fault == FSRV_RUN_CRASH) {
            goto keep_as_main_crash;
          } else if (afl->meets_bug) {
            goto keep_as_bg_crash;
          } else if (afl->meets_cmdinj) {
            goto keep_as_cmdinj;
          }

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }
// printf("[save_if_interesting_json], stage,9\n");
#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->saved_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case BG_CMDINJ:

    keep_as_cmdinj:
      // cmdinj没办法检查，就直接保存吧
      // 在一开始就要清除meets_bug和meets_cmdinj，否则后面一直是cmding
      
      // afl->meets_cmdinj = false;
      // afl->meets_bug = false;
      ++afl->total_cmdinj;
      if (afl->saved_cmdinj >= KEEP_UNIQUE_CRASH) { return keeping; }
      if (unlikely(!afl->saved_crashes) &&(afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

      // 关于cmdinj 因为只会发生在一个进程(dash)中，所以要去重需要考虑所有activate进程的bitmap,看他们的virgin map是否发生变化
      // 直接重用crash bitmap可以吗?
      
      for(int i = 0; i < MAX_PROC_CNT; i++){
        if(afl->proc_list[i] == NULL){
          break;
        }
        if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }
        if(afl->proc_list[i]->activated == 1){
            proclist_simplify_trace(afl->proc_list[i]->trace_bits);
            bg_newbits = proclist_has_new_crash_bits(afl->proc_list[i]);
            if(bg_newbits > bigger_newbits){
              bigger_newbits = bg_newbits;
            }
            break;
        }

      }
      // 主进程
      simplify_trace(afl, afl->fsrv.trace_bits);
      if(!has_new_bits(afl, afl->virgin_crash)){
        if(bigger_newbits == 0){
          // 主进程，子进程都没有发现新的coverage
          clear_bug_status(afl);
          return keeping;
        }
      }

      
      

#ifndef SIMPLE_FILES

        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,shmid:%06d,cmdinj,%s", afl->out_dir,
                afl->saved_crashes,afl->bg_crash->shmid,
                describe_op(afl, 0, NAME_MAX - strlen("id:000000,shmid:000000,cmdinj")));
        
      

#else

        // 如果是主程序发生段错误，使用原先的命名方式
        snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu,shmid:%06d,cmdinj,%s", afl->out_dir,
               afl->saved_crashes,afl->bg_crash->shmid,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,shmid:000000,cmdinj")));
      

#endif                                                    /* ^!SIMPLE_FILES */

      clear_bug_status(afl);
      ++afl->saved_crashes;
      ++afl->saved_cmdinj;
      break;

    case BG_CRASH:

    keep_as_bg_crash:
      // 首先查看覆盖率是否发生变化，这里会修改trace_bits
      // 0916: 为什么要加上这一行，想不明白，于是注释了
      // proclist_classfied = proclist_has_new_bits_unclassified(afl);
      
      // 接着计算出现bug的进程中virgin crash是否有new bits
      // printf("[save_if_interesting_json], stage,10\n");

      for(int i = 0; i < MAX_PROC_CNT; i++){
        if(afl->proc_list[i] == NULL){
          // 有时确实不会找到，这是因为使用了主进程的shmid。
          // 一般这种情况是主进程fork出来的进程完成了httpd的所有后续操作，导致fork的时候用了之前的shmid，afl直接用waitpid没有捕获
          // FATAL("NOT found right crash shmid");
          break;
        }
        // printf("checking proc %d, shmid=%d, crash_shmid=%d\n", i, afl->proc_list[i]->shmid, afl->bg_crash->shmid);
        if(afl->proc_list[i]->shmid == afl->bg_crash->shmid){
            // 因为shmid可能被覆盖了?导致全部都是0
            // 似乎states里面的crash也是主进程的没有子进程的
            // printf("found proc %d\n", i);
            if(afl->proc_list[i]->classified == 0){
              proclist_classify_counts(afl->proc_list[i]->trace_bits);
              afl->proc_list[i]->classified = 1;
            }
            proclist_simplify_trace(afl->proc_list[i]->trace_bits);
            bg_newbits_tmp = proclist_has_new_crash_bits(afl->proc_list[i]);
            if(bg_newbits_tmp > bg_newbits){
              bg_newbits = bg_newbits_tmp;
            }
            break;
        }
      }

      // printf("[save_if_interesting_json], stage,10.5\n");
      // fprintf(bitmap_fp, "[bg_newbits], bg_newbits is %d, shmid=%d\n", bg_newbits, afl->bg_crash->shmid);
      
      /* fall ... */
      //lbw[[fallthrough]];
    case FSRV_RUN_CRASH:

    keep_as_main_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */
      

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {
        // 这里似乎是判断当前出现的fault是不是和之前trace map一样的，如果是一样的就不写入
        // 在qemu_mode下，non_instrumented_mode也是0，所以会进入这个判断。
        // proclist_classfied=0说明background程序的map没有new bits
        // 不过既然都看了没有新的bits，为什么还要再检查一遍

        // 0716因为之前只有在没有crash的时候才会classify_counts
        if (!classified) { classify_counts(&afl->fsrv); }
        // if (!proclist_classfied) {classify_counts(&afl->fsrv);}
        

        // simplify_trace(afl, afl->fsrv.trace_bits);

        // AFL++原先算法，就是下面两行 只考虑了主进程中virgin_crash bits是否增加
        simplify_trace(afl, afl->fsrv.trace_bits);
        if (!has_new_bits(afl, afl->virgin_crash)) {
            // bg_newbits默认是0，再主进程覆盖率没有变化的时候检查bg_newbits是否变化，如果也没变化就不保存，否则就保存
            if(!bg_newbits){
                clear_bug_status(afl);
                // FILE* state_fp = fopen("afl_states.log", "a+");
                // fprintf(state_fp, "bg_newbits is %d and no main newbits\n", bg_newbits);
                // fclose(state_fp);
                // 暂时关闭，不知道为什么可能是0
                return keeping; 
            }
           }

      }
      // printf("[save_if_interesting_json], stage,11\n");

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

        if(afl->meets_bug == false){
          snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal,
                describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));
        }else{
          snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,shmid:%02u,addr:0x%x,%d", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal,afl->bg_crash->shmid,afl->bg_crash->addr);
        }
        

#else

        // 如果是主程序发生段错误，使用原先的命名方式
        snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal);

        // fprintf(state_fp, "[save if interesting] before: %d, set to 0\n", afl->meets_bug);
        // afl->meets_bug = 0;
        

      

#endif                                                    /* ^!SIMPLE_FILES */
      // fprintf(state_fp, "[save_if_interesting] before: %d, set to 0\n", afl->meets_bug);
      clear_bug_status(afl);

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */
    if(input_json != NULL){
      dump_result = json_dump_file(input_json, fn, JSON_ENCODE_ANY | JSON_INDENT(4));
      if (unlikely(dump_result < 0)) { PFATAL("Unable to dump '%s'", fn); }

      strcat(fn, ".raw");
      int fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
      if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
      ck_write(fd, mem, len, fn);
      close(fd);
    }else{
      // input_json == NULL
      strcat(fn, ".raw");
      int fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
      if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
      ck_write(fd, mem, len, fn);
      close(fd);
    }
    
    


  return keeping;

}




