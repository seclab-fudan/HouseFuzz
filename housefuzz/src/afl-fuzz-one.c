/*
   american fuzzy lop++ - fuzze_one routines in different flavours
   ---------------------------------------------------------------

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
#include <string.h>
#include <limits.h>
#include "cmplog.h"

/* MOpt */

static int select_algorithm(afl_state_t *afl, u32 max_algorithm) {

  int i_puppet, j_puppet = 0, operator_number = max_algorithm;

  double range_sele =
      (double)afl->probability_now[afl->swarm_now][operator_number - 1];
  double sele = ((double)(rand_below(afl, 10000) * 0.0001 * range_sele));

  for (i_puppet = 0; i_puppet < operator_num; ++i_puppet) {

    if (unlikely(i_puppet == 0)) {

      if (sele < afl->probability_now[afl->swarm_now][i_puppet]) { break; }

    } else {

      if (sele < afl->probability_now[afl->swarm_now][i_puppet]) {

        j_puppet = 1;
        break;

      }

    }

  }

  if ((j_puppet == 1 &&
       sele < afl->probability_now[afl->swarm_now][i_puppet - 1]) ||
      (i_puppet + 1 < operator_num &&
       sele > afl->probability_now[afl->swarm_now][i_puppet + 1])) {

    FATAL("error select_algorithm");

  }

  return i_puppet;

}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static inline u32 choose_block_len(afl_state_t *afl, u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, (u32)3);

  if (unlikely(!afl->run_over10m)) { rlim = 1; }

  switch (rand_below(afl, rlim)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;

    default:

      if (likely(rand_below(afl, 10))) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);

}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) { return 1; }

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {

    ++sh;
    xor_val >>= 1;

  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) { return 1; }

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) { return 0; }

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) {

    return 1;

  }

  return 0;

}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) { return 1; }

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; (u8)i < blen; ++i) {

    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) { return 1; }

  }

  if (blen == 1) { return 0; }

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; (u8)i < blen / 2; ++i) {

    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

  }

  return 0;

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) { return 1; }

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; ++i) {

    for (j = 0; j < sizeof(interesting_8); ++j) {

      u32 tval =
          (old_val & ~(0xff << (i * 8))) | (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) { return 1; }

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) { return 0; }

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; (u8)i < blen - 1; ++i) {

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) { return 1; }

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) { return 1; }

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      if (new_val == (u32)interesting_32[j]) { return 1; }

    }

  }

  return 0;

}

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset.
   We use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) { f_loc = pos; }
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif                                                     /* !IGNORE_FINDS */

const char* SECONDARY_NAME = "topicurl";
json_t *mutation1(json_t* root){
    if(root ==NULL){
      FATAL("null root at mutation1");
    }
    json_t* body = json_object_get(root, "body");
    const char* key;
    json_t* value;
    void *tmp;
    json_object_foreach_safe(body, tmp, key, value) {
        if(!strcmp(key, SECONDARY_NAME)){
          continue;
        }
        char* new_str = (char*)malloc(0xa0);
        if(new_str == NULL) {
            return NULL;
        }
        memset(new_str, 0, 0xa0);
        if(json_string_value(value) != NULL){
          strncpy(new_str, json_string_value(value), 0xa0);
          new_str[0x9f] = '\0';
        }else{
          strncpy(new_str, "wzqwzqwzq", 0xa0);
        }
        size_t str_len = json_string_length(value);
        if(str_len > 0xa0){
          str_len = 0xa0;
        }
        if(str_len > 0){
            for(size_t i = 0; i < str_len -1; i++){
                int addon = rand() % 10 - 5;
                if(rand() % 10 < 5){
                    new_str[i]  = new_str[i] + addon;
                }
                
            }
        }          
        json_object_set_new(body, key, json_string(new_str));
        free(new_str);
    }
    return root;
}

json_t* mutation2(json_t* root){
    return root; 
    if(root ==NULL){
      FATAL("null root at mutation2");
    }
    json_t* body = json_object_get(root, "body");
    const char* key;
    json_t* value;
    void* tmp;

    size_t body_size = json_object_size(body);
   
    json_t** values = malloc(body_size * sizeof(json_t*));
    size_t i = 0;
  
    json_object_foreach_safe(body, tmp, key, value) {
      if(!strcmp(key, SECONDARY_NAME)){
        continue;
      }

      values[i++] = json_deep_copy(value);
    }

    json_object_foreach_safe(body, tmp, key, value) {
      if(!strcmp(key, SECONDARY_NAME)){
        continue;
      }

      size_t random_index = rand() % i;
  
      json_t* new_value = json_deep_copy(values[random_index]);
     
      json_object_set(body, key, new_value);
     
      json_decref(new_value);
    }

    for(size_t j = 0; j < i; j++){
      json_decref(values[j]);
    }

    free(values);
    return root;
}


json_t *mutation3(json_t* root){
  if(root ==NULL){
      FATAL("null root at mutation1");
    }
    json_t* body = json_object_get(root, "body");
    const char* key;
    json_t* value;
    void *tmp;
    
    

    json_object_foreach_safe(body, tmp, key, value) {
        if(!strcmp(key, SECONDARY_NAME)){
          continue;
        }
        int random = rand() % 10; 
        if (random < 1) {
            json_object_del(body, key);
        }
    }
    return root;
}

char *large_token[3] = {"aaaWZQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaWZQwaaaaaaaaaaaaaaaaaaaaaWZQwaaaaaaaa",
                      "aaaaaaaaaaaaaaaaaaaWZQwaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaWZQwzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                      "WZQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaWZQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaWZQWZQWZQWZQwaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
char* small_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

char *large_token_header[3] = {"aaaxhyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyaaaaaaaaaaaaaaaaaaaaaxhywaaaaaaaa",
                      "aaaaaaaaaaaaaaaaaaaxhywaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                      "aaaxhyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyaaaaaaaaaaaaaaaaaaaaaxhywaaaaaaaaxhyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyxhyxhyxhywaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxhyxhyxhyxhywaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

char* injection_token[] = {
    "&&`wzq`",
    "&&wzq",
    "&wzq",
    "||wzq",
    ";$(wzq)",
    "\\n`wzq`",
    "\\r\\n`wzq`",
    ";`wzq`",
    "||`wzq`"
    "\"wzq",
    "`$(wzq)`",
    ";wzq",
    "`wzq`",
    "|wzq",
    "\\wzq",
    "\'wzq",
    "\'wzq\'",
    "(wzq",
    ")wzq",
    ";`wzq`",
    "\",wzq",
    ";\"wzq",
    NULL
};
char* injection_token_header[] = {
    "&&`xhy`",
    "&&xhy",
    "&xhy",
    "||xhy",
    ";$(xhy)",
    "\\n`xhy`",
    "\\r\\n`xhy`",
    ";`xhy`",
    "||`xhy`"
    "\"xhy",
    "`$(xhy)`",
    ";xhy",
    "`xhy`",
    "|xhy",
    "\\xhy",
    "\'xhy",
    "\'xhy\'",
    "(xhy",
    ")xhy",
    ";`xhy`",
    "\",xhy",
    ";\"xhy",
    NULL
};

void itoa(int value, char* str, int base) {
    if (base < 2 || base > 36) { 
        *str = '\0';
    } else {
        snprintf(str, 0x20, (base == 10) ? "%d" : "%x", value);
    }
}

static char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int mod_table[] = {0, 2, 1};

char *b64_encode(char *data, size_t *output_length) {
    size_t input_length = strlen(data);
    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

char *url_encode(char *str, size_t len) {
    char *new_str, *pstr = str, *buf = malloc(len * 3 + 1), *pbuf = buf;
    size_t difference = 0;
    while (difference < len && *pstr) {
        if (isalnum((unsigned char)*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
            *pbuf++ = '+';
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
        difference = pstr - str;
    }
    *pbuf = '\0';
    new_str = strdup(buf);
    free(buf);
    return new_str;
}




int max_numcase[10] = {-1, -255, -65536, -2147483648, 256, 2147483647, 0, 64, 100, -64};
int neg_numcase[5] = {-1, -255, -65536, -2147483648, -64};
char* mutation_one_value(json_t* arg, json_t* possible_values, int is_header){
  
  json_t* static_values = json_object_get(arg, "value");
  int static_values_size = json_array_size(static_values);

  const char* type = json_string_value(json_object_get(arg, "type"));
  const char* encode = json_string_value(json_object_get(arg, "encode"));

  if(is_header == 0){
    if(encode == NULL){
      encode = "normal";
    }
    if(type == NULL){
      type = "str";
    }
  }else{
    const char* types[] = {"int", "str"};
    type = types[rand()%2];
    encode = "normal";
  }
  

  size_t value_size = json_array_size(possible_values);

  

  int rand_num  = 0;
  char* ret_str = NULL;
  if(!strcmp(type, "int")){
    ret_str = (char*)malloc(0x20);
    memset(ret_str, 0, 0x20);
    rand_num = rand() % 6;
    switch (rand_num){
      case 0:{
        itoa(rand() % 256, ret_str, 10);
        break;
      }
      case 1:{
        itoa(256 - (rand()%256), ret_str, 10);
        break;
      }
      case 2:{
        itoa(max_numcase[rand() % 10], ret_str, 10);
        break;
      }
      case 3:{
        free(ret_str);
        int rand_inside = rand() % 2;
        if(rand_inside == 0){
          if(is_header == 0){
          ret_str = strdup(large_token_header[rand()%3]);
          }else{
            ret_str = strdup(small_token);
          }
        }else{
          if(is_header == 0){
            ret_str = strdup(injection_token[rand()%21]);
          }
          else{
             ret_str = strdup(injection_token_header[rand()%21]);
          }
        }
        break;
      }
      case 4:{
        if(static_values_size != 0){
          strncpy(ret_str, json_string_value(json_array_get(static_values, rand()%static_values_size)), 0x20);
        }
        break;
      }
      default:{
        itoa(rand() % 256, ret_str, 10);
        break;
      }
    }
  }
  else{
    if(static_values_size == 0){
      rand_num = rand() % 6;
      switch (rand_num){
        case 0:
        case 1:
        {
          if(is_header == 0)
            ret_str = strdup(large_token[rand() % 3]);
          else
            ret_str = strdup(large_token_header[rand() % 3]);
          break;
        }
        case 2:
        {
          if(is_header == 0)
            ret_str = strdup("wzqwzqwzq");
          else
            ret_str = strdup("xhyxhyxhy");
          break;
        }
        case 3:
        case 4:
        {
          if(is_header == 0)
            ret_str = strdup(injection_token[rand() % 21]);
          else
            ret_str = strdup(injection_token_header[rand() % 21]);
          break;
        }
        case 5:
        {
          if(value_size == 0){
            if(is_header == 0)
              ret_str = strdup("wzqwzqwzq");
            else
              ret_str = strdup("xhyxhyxhy");
            break;
          }
          ret_str = strdup(json_string_value(json_array_get(possible_values, rand() % value_size)));
          break;
        }

      }
    }else{
      rand_num = rand() % 7;
      switch(rand_num){
        case 0:
        case 1:
        case 2:
        case 3:
        {
          ret_str = strdup(json_string_value(json_array_get(static_values, rand() % static_values_size)));
          break;
        }
        case 4:
        {
          ret_str = malloc(0x50);
          memset(ret_str, 0, 0x50);
          if(is_header == 0)
            snprintf(ret_str, 0x50, "%s%s", json_string_value(json_array_get(static_values, rand() % static_values_size)),injection_token[rand() % 21]);
          else
            snprintf(ret_str, 0x50, "%s%s", json_string_value(json_array_get(static_values, rand() % static_values_size)),injection_token_header[rand() % 21]);
          break;
        }
        case 5:
        {
          ret_str = malloc(0x250);
          memset(ret_str, 0, 0x250);
          if(is_header == 0)
            snprintf(ret_str, 0x250, "%s%s", json_string_value(json_array_get(static_values, rand() % static_values_size)), large_token[rand() % 3]);
          else
            snprintf(ret_str, 0x250, "%s%s", json_string_value(json_array_get(static_values, rand() % static_values_size)), large_token_header[rand() % 3]);
          break;
        }
        case 6:
        {
          ret_str = malloc(0x50);
          char* to_use_prefix = NULL;
          for(int i = 0; i < static_values_size; i++){
            const char* static_str = json_string_value(json_array_get(static_values, i));
            if(static_str[strlen(static_str)-1] == '/'){
              if(rand() % 100 < 50){
                to_use_prefix = (char*)static_str;
              }
            }
          }
          if(to_use_prefix == NULL){
            to_use_prefix = "";
          }
          snprintf(ret_str, 0x50, "%s%s", to_use_prefix, json_string_value(json_array_get(static_values, rand() % static_values_size)));

          break;
        }
      }

    }
  }

  if(!strcmp(encode, "url")){
    char* url_str = url_encode(ret_str, strlen(ret_str));
    free(ret_str);
    return url_str;

  }else if(!strcmp(encode, "base64")){
    size_t encoded_size = 0;
    char* b64_str = b64_encode(ret_str, &encoded_size);
    free(ret_str);
    return b64_str;

  }else{
    return ret_str;
  }
  
  FATAL("Control never reaches here");

}








char* complete_arg(const char* format) {
    int BUF_SIZE=128;
    char* completed_str = calloc(BUF_SIZE, sizeof(char));
    char* return_str = calloc(BUF_SIZE, sizeof(char));
    int char_index = 0;
    int write_index = 0;


    while(format[char_index] != '\0') {
        int random_number;
        if(format[char_index] == '%') {
            switch(format[char_index + 1]) {
                case 'd':
                    random_number = rand() % 10;
                    write_index += snprintf(completed_str + write_index, BUF_SIZE - write_index, "%d", random_number);
                    char_index++;
                    break;
                case 's':
                    write_index += snprintf(completed_str + write_index, BUF_SIZE - write_index, "%s", "name");
                    char_index++;
                    break;
                case 'c':
                    write_index += snprintf(completed_str + write_index, BUF_SIZE - write_index, "%c", 'X');
                    char_index++;
                    break;
                default:
                    completed_str[write_index++] = format[char_index];
                    break;
            }
        } else {
            completed_str[write_index++] = format[char_index];
        }

        char_index++;
    }

    completed_str[write_index] = '\0';
    strncpy(return_str, completed_str, BUF_SIZE);
    free(completed_str);
    return return_str;
}


/*主要的mutation*/
json_t* mutation4(json_t* root, afl_state_t* afl){
  if(root ==NULL){
      FATAL("null root at mutation4");
    }
  json_t* body = json_object_get(root, "body");
  

  if(unlikely(afl->debug)){
            DEBUGF("afl->extras_json_cnt: %d\n", afl->extras_json_cnt);
          }
  if(afl->extras_json_cnt == 0){
    return root;
  }
  int json_index = rand() % (afl->extras_json_cnt);
  json_t* func = json_array_get(afl->json_extras, json_index);

  json_t* possible_name = json_object_get(func, "possible_name");
  size_t name_size = json_array_size(possible_name);
  if(name_size == 0){
    return root;
  }
  int random_name_index = rand() % name_size;
  const char* random_name = json_string_value(json_array_get(possible_name, random_name_index));

  if(json_object_get(body, SECONDARY_NAME)){
    json_object_clear(body);
    json_object_set_new(body, SECONDARY_NAME, json_string(random_name));
  }else{
    json_t* request = json_object_get(root, "request");
    json_object_clear(body);
    json_object_set_new(request, "handler_name", json_string(random_name));
  }
  afl->current_fuzz_uri = func;

  json_t* possible_args = json_object_get(func, "possible_args");
  size_t args_size_full = json_array_size(possible_args);
  size_t args_size = 0;
  if(afl->housefuzz_cfg_only == 1){
  	args_size = rand() % 10 + 1;
  }else{
	args_size = args_size_full;
  }
  json_t* possible_values = json_object_get(func, "possible_values");

    if(args_size > 0){
      json_t* arg = NULL;
      for(size_t i = 0; i < args_size; i++){
	if(afl->housefuzz_cfg_only == 1){
		arg = json_array_get(possible_args, rand() % args_size_full);
	}else{
        	arg = json_array_get(possible_args, i);
	}
        
        const char* key = json_string_value(json_object_get(arg, "key"));

        if(likely(json_object_get(arg, "secondary_handler") == NULL)){
          char* one_value = mutation_one_value(arg, possible_values, 0);

          if(rand() % 100 < 10){
              continue;
            }else{
              json_object_set_new(body, key, json_string(one_value));
          }
          free(one_value);
        }else{
          size_t second_uri_size = json_array_size(json_object_get(arg, "secondary_handler"));
          if(second_uri_size == 0){
            FATAL("weird, second_uri_size == 0");
          }
          int second_uri_index = rand() % (second_uri_size);

          json_t* second_uri = json_array_get(afl->json_extras, second_uri_index);
          json_t* second_uri_name = json_object_get(second_uri, "possible_name");
          size_t second_uri_name_size = json_array_size(second_uri_name);
          if(second_uri_name_size == 0){
            FATAL("weird, second_uri_name_size == 0");
          }

          const char* second_uri_name_val = json_string_value(json_array_get(second_uri_name, rand() % second_uri_name_size));
          json_object_set_new(body, key, json_string(second_uri_name_val));

          json_t* second_possible_args = json_object_get(second_uri, "possible_args");
          size_t second_args_size = json_array_size(second_possible_args);
          json_t* second_possible_values = json_object_get(second_uri, "possible_values");

          if(second_args_size > 0){
              json_t* second_arg = NULL;
              for(size_t j = 0; j < second_args_size; j++){
                second_arg = json_array_get(second_possible_args, j);
                const char* second_key = json_string_value(json_object_get(second_arg, "key"));
                char* second_one_value = mutation_one_value(second_arg, second_possible_values, 0);
                if(rand() % 100 < 10){
                    continue;
                  }else{
                    json_object_set_new(body, second_key, json_string(second_one_value));
                }
                free(second_one_value);
          }

        }
      }
    }
  }
  
  json_t* type_object = json_object_get(func, "possible_type");
  int type_object_size = json_array_size(type_object);
  if(type_object_size > 0){
      json_object_set_new(root, "possible_type", json_string(json_string_value(json_array_get(type_object, rand() % type_object_size))));
  }else{
    if(rand() % 2 == 0)
      json_object_set_new(root, "possible_type",json_string("json"));
    else
      json_object_set_new(root, "possible_type",json_string("normal"));
  }
  return root;
}




json_t* mutation5(json_t* root){
  if(root ==NULL){
      FATAL("null root at mutation5");
    }
  json_t* body = json_object_get(root, "body");
  const char* key;
  json_t* value;
  void* tmp;

  json_object_foreach_safe(body, tmp, key, value) {
    if(!strcmp(key, SECONDARY_NAME)){
      continue;
    }
   
    int random = rand() % 20;
    if (random < 10) {
      continue;
    } else {  
      json_t* new_value;
      if (random < 15) {
        new_value = json_string(large_token[rand()%3]);
      } else {
        new_value = json_string(injection_token[rand()%21]);
      }

      json_incref(value);
      json_object_set(body, key, new_value);
      json_decref(value);
      json_decref(new_value);
    }
  }

  return root;
}

json_t* mutation6(json_t* root){
    if(root ==NULL){
      FATAL("null root at mutation6");
    }
    
    json_t* body = json_object_get(root, "body");

    if(json_object_size(body) == 0){
      return root;
    }

    void* iter = json_object_iter(body);
    const char* target1_key = NULL;
    json_t* target1_value = NULL;
    const char* target2_key = NULL;
    json_t* target2_value = NULL;

    while(iter) {
        if(rand()%10<5){
            if(target1_key == NULL){
                target1_value = json_object_iter_value(iter);
                target1_key = json_object_iter_key(iter);
            }else{
                if(target2_key == NULL){
                  target2_value = json_object_iter_value(iter);
                  target2_key = json_object_iter_key(iter);
                }
            }
        }
        iter = json_object_iter_next(body, iter);
    }

    if(target1_key != NULL && target2_key != NULL){
        if(!strcmp(target1_key, SECONDARY_NAME) || !strcmp(target2_key, SECONDARY_NAME)){
          return root;
        }
        json_t* copy1 = json_deep_copy(target1_value);
        json_t* copy2 = json_deep_copy(target2_value);
        json_object_set(body, target1_key, copy2);
        json_object_set(body, target2_key, copy1);
        json_decref(copy1);
        json_decref(copy2);
    }

    return root;
}

char* METHOD_CASE[] = {"POST", "GET", "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY", "M-SEARCH *", "HEAD"};
json_t* mutation7(json_t* root){
    if(root ==NULL){
      FATAL("null root at mutation7");
    }
    json_t* request = json_object_get(root, "request");
    if(rand() % 100 < 80){
      if(rand() % 100 < 50){
        json_object_set_new(request, "method", json_string("POST"));
      }else{
        json_object_set_new(request, "method", json_string("GET"));
      }
    }else{
      json_object_set_new(request, "method", json_string(METHOD_CASE[rand() % 7]));
    }
    
    return root;
}

void convertToUpper(char *str) {
    int i = 0;
    while (str[i]) {
        str[i] = toupper(str[i]);
        i++;
    }
}

json_t* mutation8(json_t* root,  afl_state_t* afl){
  if(root ==NULL){
      FATAL("null root at mutation8");
    }
  json_t* header = json_object_get(root, "header");

  if(afl->headers_extra_cnt == 0){
    return root;
  }
  int header_add_cnt = rand() % 5;
  for(int cnt = 0; cnt< header_add_cnt; cnt++ ){
    json_t* header_add = json_array_get(afl->headers_extra, rand() % afl->headers_extra_cnt);
    const char* header_name = json_string_value(json_object_get(header_add, "name"));
    
    json_t *possible_values = json_object();

    char* one_value = mutation_one_value(header_add, possible_values, 1);
    
    json_object_set_new(header, header_name, json_string(one_value));
  return root;  

}


json_t* mutation9(json_t* root){
  // return root;
  if(root ==NULL){
      FATAL("null root at mutation 9");
    }
  json_t* header = json_object_get(root, "header");
  const char* key;
  json_t* value;
  void* tmp;

  json_object_foreach_safe(header, tmp, key, value) {
    if(!strcmp(key, "Host") || !strcmp(key, "Accept")|| !strcmp(key,  "Connection")|| !strcmp(key,  "Content-Type")|| !strcmp(key,  "User-Agent")) {
      continue;
    }
    json_object_del(header, key);
  }
  return root;

}

json_t* mutation10(json_t* root, afl_state_t* afl){
  return root;
    if(!afl->upnp_dict){
      return root;
    }
    json_t* header = json_object_get(root, "header");
    const char* key;
    json_t* value;
    void* tmp;
    int rand_headernum = 0;
    // int whole_protocal_cnt;

    json_object_foreach_safe(header, tmp, key, value) {
    if(!strcmp(key, "Host") || !strcmp(key, "Accept")|| !strcmp(key,  "Connection")|| !strcmp(key,  "Content-Type")|| !strcmp(key,  "User-Agent")) {
      continue;
    }
    json_object_del(header, key);
  }

    json_t* dict = json_object_get(afl->upnp_dict, "upnp");
    json_t* dict_header = json_object_get(dict, "header");
    json_t* dict_value = json_object_get(dict, "value");

    size_t dict_value_cnt = json_array_size(dict_value);


    size_t header_size = json_array_size(dict_header);
    for(size_t i = 0; i< header_size; i++){
      rand_headernum = rand() % 10;
      char numstr[0x20];
      memset(numstr, 0, 0x20);
      switch (rand_headernum){
        case 0:
          itoa(rand(), numstr, 10);
          json_object_set_new(header, json_string_value(json_array_get(dict_header, i)), json_string(numstr));
          break;
        case 1:
          json_object_set_new(header, json_string_value(json_array_get(dict_header, i)), json_string(small_token));
          break;

        case 2:
          json_object_set_new(header, json_string_value(json_array_get(dict_header, i)), json_string(injection_token[rand()%21]));
          break;

        case 3:
          json_object_set_new(header, json_string_value(json_array_get(dict_header, i)), json_string("wzqwzq"));
          break;

        case 4:
        case 5:
        case 6:
        case 7:
          {
              if(dict_value_cnt > 0){
                const char* full_value = json_string_value(json_array_get(dict_value, rand() % dict_value_cnt));
                char* header_end = strchr(full_value, ':');
                char* value_choose = NULL;
                if(header_end){
                    *header_end = '\0';
                    value_choose = header_end + 1;
                    json_object_set_new(header, full_value, json_string(value_choose));
                }
                break;
              }
              else{
                break;
              }
              
          }
          case 8:
          {
            if(dict_value_cnt > 0){
                const char* chosen_value = json_string_value(json_array_get(dict_value, rand() % dict_value_cnt));
                char* header_choose = strchr(chosen_value, ':');
                char* value_choose = NULL;
                if(header_choose){
                    *header_choose = '\0';
                    value_choose = header_choose + 1;
                    char* tmpbuf = (char*)malloc(0x200);
                    memset(tmpbuf, 0, 0x200);
                    snprintf(tmpbuf, 0x1ff, "%s%s", value_choose, injection_token[rand() % 21]);
                    json_object_set_new(header, header_choose, json_string(tmpbuf));
                    free(tmpbuf);
                }
                break;
              }
              else{
                break;
              }
          }
          case 9:
          {
            if(dict_value_cnt > 0){
                const char* chosen_value = json_string_value(json_array_get(dict_value, rand() % dict_value_cnt));
                char* header_choose = strchr(chosen_value, ':');
                char* value_choose = NULL;
                if(header_choose){
                    *header_choose = '\0';
                    value_choose = header_choose + 1;
                    char* tmpbuf = (char*)malloc(0x200);
                    memset(tmpbuf, 0, 0x200);
                    snprintf(tmpbuf, 0x1ff, "%s%s", value_choose, small_token);
                    json_object_set_new(header, header_choose, json_string(tmpbuf));
                    free(tmpbuf);
                }
                break;
              }
              else{
                break;
              }
          }
        default:
          break;

      }
    }

  return root;
}

json_t* mutation11(json_t* root, afl_state_t* afl){
  if(root ==NULL){
      FATAL("null root at mutation11");
    }
  json_t* header = json_object_get(root, "header");
  if(afl->headers_extra_cnt == 0){
    return root;
  }
  int json_index = rand() % (afl->headers_extra_cnt);
  json_t* func = json_array_get(afl->headers_extra, json_index);

  json_t* possible_values = json_object_get(func, "value");
  size_t values_size = json_array_size(possible_values);
  
  


  const char* key;
  void* tmp;
  json_t* value;

  json_object_foreach_safe(header, tmp, key, value){
    if(!strcmp(key, "Host") || !strcmp(key, "Accept") || !strcmp(key, "Connection") || !strcmp(key, "Content-Type")|| !strcmp(key,  "User-Agent")){
      continue;
    }
    int random = rand() % 6;
    
    json_t* new_value = NULL;
    switch (random){
      case 0:
      case 1:
        new_value = json_string(injection_token_header[rand()%21]);
        json_object_set_new(header, key, new_value);
        break;

      case 2:
      case 3:
        new_value = json_string(large_token_header[rand()%3]);
        json_object_set_new(header, key, new_value);
        break;

      case 4:
      {
        char *random_value = "";
        if(values_size != 0){
          int random_value_index = rand() % values_size;
          random_value = json_string_value(json_array_get(possible_values, random_value_index));
        }
        char concated[2048];
        memset(concated, 0, 2048);
        snprintf(concated, 2047, "%s%s", random_value, large_token_header[rand()%3]);
        json_object_set_new(header, key, json_string(concated));
        break;
      }
      case 5:
        {
          if(json_is_string(value)){
            const char* original = json_string_value(value);
            char* chosen_randinj = injection_token_header[rand()%21];
            size_t len = strlen(original) + strlen(chosen_randinj) + 2;
            char* concated = (char*)malloc(len);
            strcpy(concated, original);
            strcpy(concated, chosen_randinj);
            new_value = json_string(concated);
            json_object_set_new(header, key, new_value);
            free(concated);
          }
          break;
        }
      default:
        continue;
    }
  }
  return root;
}


json_t* mutation12(json_t* root, afl_state_t* afl){
  if(root ==NULL){
      FATAL("null root at mutation12");
    }
  if(afl->perfix_extra_cnt == 0 || afl->name_extra_cnt == 0){
    return root;
  }
  int perfix_num = rand() % (afl->perfix_extra_cnt);
  int name_num = rand() % (afl->name_extra_cnt);
  char* random_name = NULL;
  char* random_perfix = NULL;
  
  int choice = rand() % 3;

  json_t* request = json_object_get(root, "request");
  

  if(choice == 0){
    random_perfix = (char*)json_string_value(json_array_get(afl->perfix_extra, perfix_num));
    json_object_set_new(request, "prefix", json_string(random_perfix));
  }else if(choice == 1){
    if(afl->fulluri_extra_cnt == 0){
      return root;
    }
    int name_num = rand() % (afl->fulluri_extra_cnt);
    random_name = (char*)json_string_value(json_array_get(afl->fulluri_extra, name_num));
    char* dup_full = strdup(random_name);
    int dup_full_len = strlen(dup_full);
    char* slash = strchr(dup_full, '/');
    if(slash == NULL){
      FATAL("api dict full entry wrong format!");
    }
    slash[0] = '\0'; 

    char* dict_prefix = (char*)malloc(dup_full_len+1);
    memset(dict_prefix, 0, dup_full_len+1);
    snprintf(dict_prefix, dup_full_len, "%s/", dup_full);

    char* dict_hname = (char*)malloc(dup_full_len+1);
    memset(dict_hname, 0, dup_full_len);
    snprintf(dict_hname, dup_full_len, "%s", slash+1);

    free(dup_full);
    

    json_object_set_new(request, "prefix", json_string(dict_prefix));
    json_object_set_new(request, "handler_name", json_string(dict_hname));

    free(dict_prefix);
    free(dict_hname);
  }else if(choice == 2){
    random_perfix = (char*)json_string_value(json_array_get(afl->perfix_extra, perfix_num));
    json_object_set_new(request, "prefix", json_string(random_perfix));

    random_name = (char*)json_string_value(json_array_get(afl->name_extra, name_num));
    json_object_set_new(request, "handler_name", json_string(random_name));
  }

  return root;

}
json_t* mutation13(json_t* root, afl_state_t* afl){
  if(root ==NULL){
      FATAL("null root at mutation 13");
    }
  if(unlikely(afl->debug)){
            DEBUGF("mutation13\n");
          }
  
  json_t* request = json_object_get(root, "request");
  json_t* body = json_object_get(root, "body");
  int favored_cnt = 0;
  int uri_cnt = 0;

  if(afl->queue_cur->uri_index == NULL){

      afl->queue_cur->uri_index = (int*)malloc(0x10 * sizeof(int));
      for(int j = 0; j < 0x10; j++){
        afl->queue_cur->uri_index[j] = -1;
      }
      for(u32 index = 0; index < afl->extras_json_cnt; index++){
        json_t* func = json_array_get(afl->json_extras, index);
        json_t* possible_name = json_object_get(func, "possible_name");
        size_t name_size = json_array_size(possible_name);
        for(u32 name_index = 0; name_index < name_size; name_index ++){
          if(strstr(json_string_value(json_object_get(request, "handler_name")), json_string_value(json_array_get(possible_name, name_index)))){
            for(int queue_index = 0; queue_index < 0x10; queue_index++){
              if(afl->queue_cur->uri_index[queue_index] == -1){
                afl->queue_cur->uri_index[queue_index] = index;
                uri_cnt += 1;
                break;
              }
            }
          }
        }
      }
      goto cont;
  }else{
cont:
    DEBUGF("nop, 1\n");
    int rand_num = 0;
    for(favored_cnt = 0; afl->queue_cur->uri_index[favored_cnt] != -1 && favored_cnt < 0x10; favored_cnt++){
      ;
    }
    if(favored_cnt == 0x10){
      favored_cnt = 0;
    }
    if(favored_cnt > 0){
      rand_num = rand() % favored_cnt;
      int corr_uri_index = afl->queue_cur->uri_index[rand_num];
      json_t* func = json_array_get(afl->json_extras, corr_uri_index);
      json_t* possible_name = json_object_get(func, "possible_name");
      size_t name_size = json_array_size(possible_name);
      if(name_size == 0){
        return root;
      }
      int random_name_index = rand() % name_size;
      const char* random_name = json_string_value(json_array_get(possible_name, random_name_index));

      json_t* possible_args = json_object_get(func, "possible_args");
      json_t* possible_values = json_object_get(func, "possible_values");
      size_t args_size = json_array_size(possible_args);
      if(args_size > 0){
        if(json_object_get(body, SECONDARY_NAME)){
          json_object_clear(body);
          json_object_set_new(body, SECONDARY_NAME, json_string(random_name));
        }else{
          json_object_clear(body);
        }
        json_t* arg = NULL;
        char num_str[0x10];
        memset(num_str, 0, 0x10);
        for(size_t i = 0; i < args_size; i++){
          arg = json_array_get(possible_args, i);
          
          const char* key = json_string_value(json_object_get(arg, "key"));

          char* one_value = mutation_one_value(arg, possible_values, 0);

          if(rand() % 100 < 10){
            continue;
          }else{
            json_object_set_new(body, key, json_string(one_value));
          }
          free(one_value);
      }
      if(unlikely(afl->debug)){
            DEBUGF("mutation13 ends\n");
          }
      return root;
    }else{
      if(unlikely(afl->debug)){
            DEBUGF("mutation13 ends\n");
          }
      
      return mutation4(root, afl);
    }

    FATAL("control never reach here");
    }
    if(unlikely(afl->debug)){
            DEBUGF("mutation13 favored_cnt == 0\n");
          }
  return mutation4(root, afl);
  }
}
json_t* mutation14(json_t* root){
  if(root ==NULL){
      FATAL("null root at mutation 14");
    }
  int place = rand() % 5;
  switch (place){
    case 0:{
      json_t* request = json_object_get(root, "request");
      json_object_set_new(request, "method", json_string("wzQ"));
      break;
    }
    case 1:{
      json_t* request = json_object_get(root, "request");
      json_object_set_new(request, "handler_name", json_string("wZq"));
      break;
    }
    case 2:{
      json_t* request = json_object_get(root, "request");
      json_object_set_new(request, "prefix", json_string("Wzq"));
      break;
    }
    case 3:{
      json_t* header = json_object_get(root, "header");
      json_object_set_new(header, "hEaDrE", json_string("WZq"));
      break;
    }
    case 4:{
      json_t* body = json_object_get(root, "body");
      json_object_set_new(body, "WzQ", json_string("wZQ"));
      break;
    }

  }
  return root;

}

json_t* mutation15(json_t* root, afl_state_t* afl){
  if(afl->housefuzz_cfg_only){
    return root;
  }
  json_t* request = json_object_get(root, "request");
  const char* now_uri = json_string_value(json_object_get(request, "handler_name"));
  char* large_buf = NULL;
  int use_large_buf = 0;
  char uri_buf[1024];
  memset(uri_buf, 0, 1024);
  int rand_num = rand() % 5;
  if(rand_num == 0){
    snprintf(uri_buf, 1022, "%s%s", now_uri, large_token_header[rand() % 3]);
  }else if(rand_num == 1){
    snprintf(uri_buf, 1022, "%s%s", large_token_header[rand() % 3], now_uri);
  }else{
    char *appendix[] = {".js", ".asp", ".gif", ".cgi", ".css", ".htm", ".html",".php"};
    int appendix_cnt = 8;
    rand_num = rand() % 10;
    if(rand_num<4){
      snprintf(uri_buf, 1022, "cc%s%s", appendix[rand() % appendix_cnt], large_token_header[rand()%3]);
    }else if(rand_num<9){
      snprintf(uri_buf, 1022, "cc%s%s", large_token_header[rand()%3], appendix[rand() % appendix_cnt]);
    }else{
      use_large_buf = 1;
      large_buf = (char*)malloc(1024*8);
      snprintf(large_buf, 1024*8-1, "%s%s%s%s%s%s%s",appendix[rand() % appendix_cnt],large_token_header[2], large_token_header[2], large_token_header[2], large_token_header[2], large_token_header[2], large_token_header[2]);
    }
    
  }
  if(use_large_buf){
    json_object_set_new(request, "handler_name", json_string(large_buf));
    free(large_buf);
  }else{
  json_object_set_new(request, "handler_name", json_string(uri_buf));
  }
  return root;
}


char* json_to_http_post(json_t* root, size_t* testcase_size) {
    size_t BUFFER_SIZE = 256;
    char* buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, BUFFER_SIZE);
    json_t* request = json_object_get(root, "request");
    const char* method = json_string_value(json_object_get(request, "method"));
    const char* prefix = json_string_value(json_object_get(request, "prefix"));
    const char* handler_name = json_string_value(json_object_get(request, "handler_name"));
    const char* version = json_string_value(json_object_get(request, "version"));
    
    size_t total_size = snprintf(NULL, 0, "%s %s%s HTTP/%s\r\n", method, prefix, handler_name, version) + 1;
    while (total_size >= BUFFER_SIZE) {
        BUFFER_SIZE *= 2;
        char* new_buffer = realloc(buffer, BUFFER_SIZE + 2);
        if (new_buffer == NULL) {
            free(buffer);
            return NULL;
        }
        buffer = new_buffer;
        memset(buffer + (BUFFER_SIZE / 2), 0, BUFFER_SIZE / 2);
    }
    snprintf(buffer, BUFFER_SIZE, "%s %s%s HTTP/%s\r\n", method, prefix, handler_name, version);

    json_t* header = json_object_get(root, "header");
    const char* key;
    json_t* value;
    void *tmp;

    const char* body_type = json_string_value(json_object_get(root, "possible_type"));
    if(!strcmp(body_type, "json")){
      json_object_set_new(header, "Content-Type" ,json_string("application/json"));
    }

    json_object_foreach_safe(header, tmp, key, value) {
    size_t header_size = snprintf(NULL, 0, "%s: %s\r\n", key, json_string_value(value)) + 1;
    total_size += header_size;
    
    while (total_size >= BUFFER_SIZE) {
        BUFFER_SIZE *= 2;
        char* new_buffer = realloc(buffer, BUFFER_SIZE);
        if (new_buffer == NULL) {
            free(buffer);
            return NULL;
        }
        buffer = new_buffer;
        memset(buffer + (BUFFER_SIZE / 2), 0, BUFFER_SIZE / 2);
    }

    snprintf(buffer + strlen(buffer), BUFFER_SIZE - strlen(buffer), "%s: %s\r\n", key, json_string_value(value));
    }
    
    size_t body_size = 0;
    char* tmp_bodybuf = NULL;
    
    if(strcmp(body_type, "json")){

      json_t* body = json_object_get(root, "body");
      size_t size = json_object_size(body);
      size_t index = 0;
      
      size_t addon_size = 0;
      size_t BODY_BUFFER_SIZE = 256;
      tmp_bodybuf = (char*)malloc(BODY_BUFFER_SIZE);
      

      memset(tmp_bodybuf, 0, BODY_BUFFER_SIZE);
      if (size > 0) {
          json_object_foreach(body, key, value) {
              const char* valueStr = json_string_value(value);
              if(!valueStr) {
                  free(tmp_bodybuf);
                  return NULL;
              }
              addon_size = snprintf(NULL, 0, "%s=%s%s", key, valueStr, (++index < size) ? "&" : "") + 1;
              body_size += addon_size;
              while (body_size >= BODY_BUFFER_SIZE-1) {
                  BODY_BUFFER_SIZE *= 2;
                  char* new_buffer = realloc(tmp_bodybuf, BODY_BUFFER_SIZE + 2);
                  if (!new_buffer) {
                      FATAL("realloc error!");
                      free(tmp_bodybuf);
                      return NULL;
                  }
                  tmp_bodybuf = new_buffer;
              }
              strncat(tmp_bodybuf, key, BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
              strncat(tmp_bodybuf, "=", BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
              strncat(tmp_bodybuf, valueStr, BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
              if (index < size) {
                  strncat(tmp_bodybuf, "&", BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
              }
          }
      }
    }else if(!strcmp(body_type, "json")){

      json_t* body = json_object_get(root, "body");
      size_t json_body_size = json_dumpb(body, NULL, 0, 0);
      if(json_body_size == 0){
        FATAL("bad body in request");
      }
      tmp_bodybuf = (char*)malloc(json_body_size+1);
      memset(tmp_bodybuf, 0, json_body_size+1);
      if(tmp_bodybuf == 0){
        FATAL("can't alloc memory");
      }

      body_size = json_dumpb(body, tmp_bodybuf, json_body_size+1, 0);
      
    }
    char* content_length_buf = (char*)malloc(0x30);
    memset(content_length_buf, 0, 0x30);
    int content_length = snprintf(content_length_buf, 0x30, "Content-Length: %zu\r\n", body_size < 1024 ? body_size : 1024) + 1;
    if(rand() % 300 == 0){
      int body_size_neg = neg_numcase[rand() % 5];
      content_length = snprintf(content_length_buf, 0x30, "Content-Length: %d\r\n", body_size_neg) + 1;
    }
    
    total_size += content_length;
    total_size += body_size;
    total_size += 2; 

    int old_buffer_size = BUFFER_SIZE;
    while (total_size >= BUFFER_SIZE) {
        BUFFER_SIZE *= 2;
        buffer = realloc(buffer, BUFFER_SIZE + 2);
        if (buffer == NULL) {
            FATAL("realloc error");
            free(content_length_buf);
            return NULL;
        }
        memset(buffer + old_buffer_size, 0, BUFFER_SIZE - old_buffer_size);
    }
    
    strncat(buffer, content_length_buf, BUFFER_SIZE - strlen(buffer) - 1);
    strncat(buffer, "\r\n", BUFFER_SIZE - strlen(buffer) - 1);

    if (tmp_bodybuf != NULL) {
        snprintf(buffer + strlen(buffer), BUFFER_SIZE - strlen(buffer), "%s\r\n", tmp_bodybuf);
    }else{
        FATAL("tmp_bodybuf is NULL!");
    }

    free(content_length_buf);
    free(tmp_bodybuf);

    buffer[total_size] = '\0';
    *testcase_size = strlen(buffer);

    return buffer;
}


char* json_to_http_get(json_t* root, size_t* testcase_size){
    size_t BUFFER_SIZE = 256;
    char* buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, BUFFER_SIZE);
    *buffer = '\0';
    
    
    json_t* request = json_object_get(root, "request");
    const char* method = json_string_value(json_object_get(request, "method"));
    const char* prefix = json_string_value(json_object_get(request, "prefix"));
    const char* handler_name = json_string_value(json_object_get(request, "handler_name"));
    const char* version = json_string_value(json_object_get(request, "version"));
    json_t* body = json_object_get(root, "body");
    size_t size = json_object_size(body);
    size_t index = 0;
    const char* key;
    json_t* value;
    size_t body_size = 0;
    size_t addon_size = 0;
    size_t BODY_BUFFER_SIZE = 256;
    char*  tmp_bodybuf = (char*)malloc(BODY_BUFFER_SIZE);
    memset(tmp_bodybuf, 0, BODY_BUFFER_SIZE);
    if (size > 0) {
        json_object_foreach(body, key, value) {
            const char* valueStr = json_string_value(value);
            if(!valueStr) {
                free(tmp_bodybuf);
                return NULL;
            }
            addon_size = snprintf(NULL, 0, "%s=%s%s", key, valueStr, (++index < size) ? "&" : "");
            body_size += addon_size;
            while (body_size + 0x10 >= BODY_BUFFER_SIZE) {
                BODY_BUFFER_SIZE *= 2;
                char* new_buffer = realloc(tmp_bodybuf, BODY_BUFFER_SIZE + 2);
                if (!new_buffer) {
                    FATAL("realloc error!");
                    free(tmp_bodybuf);
                    return NULL;
                }
                tmp_bodybuf = new_buffer;
            }
            strncat(tmp_bodybuf, key, BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
            strncat(tmp_bodybuf, "=", BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
            strncat(tmp_bodybuf, valueStr, BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
            if (index < size) {
                strncat(tmp_bodybuf, "&", BODY_BUFFER_SIZE - strlen(tmp_bodybuf) - 1);
            }
        }
    }
    


    
    size_t total_size = snprintf(NULL, 0, "%s %s%s?%s HTTP/%s\r\n", method, prefix, handler_name, tmp_bodybuf, version);
    while (total_size >= BUFFER_SIZE) {
        size_t old_buffer_size = BUFFER_SIZE;
        BUFFER_SIZE *= 2;
        char* new_buffer = realloc(buffer, BUFFER_SIZE + 2);
        if (new_buffer == NULL) {
            free(buffer);
            return NULL;
        }
        buffer = new_buffer;
        memset(buffer + old_buffer_size, 0, BUFFER_SIZE - old_buffer_size);
    }
    snprintf(buffer, BUFFER_SIZE, "%s %s%s?%s HTTP/%s\r\n", method, prefix, handler_name, tmp_bodybuf, version);

    free(tmp_bodybuf);

    json_t* header = json_object_get(root, "header");
    
    void *tmp;

    json_object_foreach_safe(header, tmp, key, value) {
      total_size += snprintf(NULL, 0, "%s: %s\r\n", key, json_string_value(value));
      while(total_size+0x10 > BUFFER_SIZE){ 
          BUFFER_SIZE *= 2;
          char* new_buffer = realloc(buffer, BUFFER_SIZE + 2);
          if (new_buffer == NULL) {
              free(buffer);
              return NULL;
          }
          buffer = new_buffer;
      }
      strcat(buffer, key);
      strcat(buffer, ": ");
      strcat(buffer, json_string_value(value));
      strcat(buffer, "\r\n");
    }

    char* content_length_buf = (char*)malloc(0x30);
    memset(content_length_buf, 0, 0x30);
    int content_length = snprintf(content_length_buf, 0x30, "Content-Length: %zu\r\n", body_size < 1024 ? body_size : 1024) + 1;
    if(rand() % 300 == 0){
      int body_size_neg = neg_numcase[rand() % 5];
      content_length = snprintf(content_length_buf, 0x30, "Content-Length: %d\r\n", body_size_neg) + 1;
    }

    total_size += content_length;
    total_size += body_size;
    total_size += 2; 
    int old_buffer_size = BUFFER_SIZE;
    while (total_size >= BUFFER_SIZE) { 
        BUFFER_SIZE *= 2;
        buffer = realloc(buffer, BUFFER_SIZE + 2);
        if (buffer == NULL) {
            FATAL("realloc error");
            return NULL;
        }
        memset(buffer + old_buffer_size, 0, BUFFER_SIZE - old_buffer_size);
    }
    
    strncat(buffer, content_length_buf, BUFFER_SIZE - strlen(buffer) - 1);
    free(content_length_buf);

    
    strcat(buffer, "\r\n");
    total_size = strlen(buffer);

    *testcase_size = total_size;

    
    return buffer;

}

bool str_not_in_array(json_t* json_array, const char* str){
  size_t array_sz = json_array_size(json_array);
  for(size_t i = 0; i < array_sz; i++){
    const char* alreday_have = json_string_value(json_array_get(json_array, i));
    if(!strcmp(alreday_have, str)){
      return 0;
    }
  }
  
  return 1;
}

bool int_not_in_array(json_t* json_array, int num){
  size_t array_sz = json_array_size(json_array);
  for(size_t i = 0; i < array_sz; i++){
    int alreday_have = json_integer_value(json_array_get(json_array, i));
    if(alreday_have == num){
      return 0;
    }
  }
  return 1;
}


char* replace_char(const char* ori, char ch){
  
  if(!strchr(ori, ch)){
    return strdup(ori);
  }

  size_t ori_size = strlen(ori);

  char* result = (char*)malloc(ori_size);
  size_t result_sz = 0;
  memset(result, 0, ori_size);

  for(size_t index = 0; index < ori_size; index ++){
    if(ori[index] != ch){
      result[result_sz++] = ori[index];
    }
  }

  return result;
}



void maybe_put_dict(afl_state_t* afl, char* line_has, char* line_toadd, json_t* json_in){
  const char* key;
  json_t* value;

  json_t* request = json_object_get(json_in, "request");
  json_t* header = json_object_get(json_in, "header");
  json_t* body = json_object_get(json_in, "body");

  bool request_found = 0;
  bool header_found = 0;
  bool body_found = 0;
  
  
  if(strcasestr(line_toadd, "wzq") != NULL){
        return;
    }
  
  const char* method = json_string_value(json_object_get(request, "method"));
  if(strstr(line_has, method)){
    
    if(strchr(line_toadd, ' ') == 0){
      json_object_set_new(afl->current_fuzz_uri, "method", json_string(line_toadd));
      return ;
    }else{
      char* line_toadd_dup = strdup(line_toadd);
      char* space = strchr(line_toadd_dup , ' ');
      int has_found = 0;
      *space = 0;
      char* uri = space + 1;
      json_object_set_new(afl->current_fuzz_uri, "method", json_string(line_toadd_dup));
      for(size_t uri_cnt = 0; uri_cnt < afl->extras_json_cnt; uri_cnt++){
        json_t* func = json_array_get(afl->json_extras, uri_cnt);
        json_t* possible_name = json_object_get(func, "possible_name");
        size_t name_size = json_array_size(possible_name);
        for(size_t name_cnt = 0; name_cnt < name_size; name_cnt++){
            if(!strcmp(uri, json_string_value(json_array_get(possible_name, name_cnt)))){
              has_found = 1;
              break;
            }
          }
      if(has_found ==1){
        break;
      }
    }
    if(has_found == 0){
        json_t* new_obj = json_object();
        json_t* name_array = json_array();
        json_t* args_array = json_array();
        json_t* possible_value_array = json_array();
        json_t* possible_type_array = json_array();

        json_array_append_new(name_array, json_string(uri));
        json_array_append_new(possible_type_array, json_string("normal"));
        json_array_append_new(possible_type_array, json_string("json"));
        json_object_set_new(new_obj, "possible_name", name_array);
        json_object_set_new(new_obj, "possible_args", args_array);
        json_object_set_new(new_obj, "possible_values", possible_value_array);
        json_object_set_new(new_obj, "possible_type", possible_type_array);

        json_array_append_new(afl->json_extras, new_obj);
        afl->extras_json_cnt += 1;
    }
    free(line_toadd_dup);
    }
  }
  
  json_object_foreach(request, key, value){
    if(strstr(line_has, json_string_value(value))/* || strstr(json_string_value(value), line_has)*/){
      request_found = 1;
      int has_found = 0;
      if(!strcmp(key, "handler_name")){
        for(size_t uri_cnt = 0; uri_cnt < afl->extras_json_cnt; uri_cnt++){
          json_t* func = json_array_get(afl->json_extras, uri_cnt);

          json_t* possible_name = json_object_get(func, "possible_name");
          size_t name_size = json_array_size(possible_name);
          for(size_t name_cnt = 0; name_cnt < name_size; name_cnt++){
            if(!strcmp(line_toadd, json_string_value(json_array_get(possible_name, name_cnt)))){
              has_found = 1;
              break;
            }
          }
          if(has_found != 0){
            break;
          }
        }
        if(has_found == 0){
          json_t* new_obj = json_object();
          json_t* name_array = json_array();
          json_t* args_array = json_array();
          json_t* possible_value_array = json_array();
          json_t* possible_type_array = json_array();

          

          json_array_append_new(name_array, json_string(line_toadd));
          json_array_append_new(possible_type_array, json_string("normal"));
          json_array_append_new(possible_type_array, json_string("json"));
          json_object_set_new(new_obj, "possible_name", name_array);
          json_object_set_new(new_obj, "possible_args", args_array);
          json_object_set_new(new_obj, "possible_values", possible_value_array);
          json_object_set_new(new_obj, "possible_type", possible_type_array);

          json_array_append_new(afl->json_extras, new_obj);
          afl->extras_json_cnt += 1;
        }
        
      }
      if(line_toadd[0] == '/' || line_toadd[strlen(line_toadd)-1] == '/'){
          if(str_not_in_array(afl->name_extra, line_toadd)){
          json_array_append_new(afl->name_extra, json_string(line_toadd));
          afl->name_extra_cnt += 1;  
        }

        size_t line_toadd_len = strlen(line_toadd);
        char* line_toadd_slash = (char*)malloc(line_toadd_len+0x10);
        memset(line_toadd_slash, 0, line_toadd_len+0x10);
        
        
        if(line_toadd_len > 0 && line_toadd[line_toadd_len-1] != '/'){
            strcat(line_toadd_slash, line_toadd);
            strcat(line_toadd_slash, "/");
        }else{
            strcat(line_toadd_slash, line_toadd);
        }
        if(str_not_in_array(afl->perfix_extra, line_toadd_slash)){
            json_array_append_new(afl->perfix_extra, json_string(line_toadd_slash));
            afl->perfix_extra_cnt += 1;
          }
        free(line_toadd_slash);
      } 
    }
  }

   json_object_foreach(header, key, value){
    if(strchr(line_toadd, ':') == NULL){
      if(strstr(line_has, json_string_value(value))){
        for(size_t header_cnt = 0; header_cnt != afl->headers_extra_cnt; header_cnt++){
          json_t* header_obj = json_array_get(afl->headers_extra, header_cnt);
          const char* header_name = json_string_value(json_object_get(header_obj, "name"));
          if(header_name == NULL){
            break;
          }
          if(!strcmp(header_name, key)){
            char* line_toadd_new = replace_char(line_toadd, '=');
            json_t* header_value = json_object_get(header_obj, "value");
            if(str_not_in_array(header_value, line_toadd_new)){
              json_array_append_new(header_value, json_string(line_toadd_new));
            }
            free(line_toadd_new);
            header_found = 1;
          }
        }
      }
   }
    if(strstr(line_has, key)){
      char* line_toadd_new = replace_char(line_toadd, ':');
      for(size_t header_cnt = 0; header_cnt != afl->headers_extra_cnt; header_cnt++){
        json_t* header_obj = json_array_get(afl->headers_extra, header_cnt);
        const char* header_name = json_string_value(json_object_get(header_obj, "name"));
        if(header_name == NULL){
            break;
          }
        if(!strcmp(header_name, line_toadd_new)){
          header_found = 1;
          break;
        }
      }
      if(header_found == 0){
        json_t* new_header = json_object();
        json_t* new_object_array = json_array();
        
        json_object_set_new(new_header, "name", json_string(line_toadd_new));
        json_object_set_new(new_header, "value", new_object_array);
        json_array_append_new(afl->headers_extra, new_header);
        header_found = 1;
        afl->headers_extra_cnt = json_array_size(afl->headers_extra);
        

      }
      free(line_toadd_new);
    }
   }

  json_object_foreach(body, key, value){
    if(strchr(line_toadd, '?') != NULL || strchr(line_toadd, '=') != NULL){
      if(strstr(line_has, key)){
        json_t* uri_args = json_object_get(afl->current_fuzz_uri, "possible_args");
        size_t uri_args_size = json_array_size(uri_args);
        for(size_t index = 0; index < uri_args_size; index++){
          json_t* key_obj = json_array_get(uri_args, index);
          const char* curkeyname = json_string_value(json_object_get(key_obj, "key"));
          if(!strcmp(line_toadd, curkeyname)){
            body_found = 1;
            break;
          }
      }
      if(body_found == 0){
        json_t* key_object = json_object();
        char* line_toadd_1 = replace_char(line_toadd, '?');
        char* line_toadd_new = replace_char(line_toadd_1, '=');
        free(line_toadd_1);

        json_object_set_new(key_object, "key", json_string(line_toadd_new));
        json_object_set_new(key_object, "type", json_string("str"));
        json_object_set_new(key_object, "encode", json_string("normal"));
        
        json_t* key_value_array = json_array();
        json_object_set_new(key_object, "value", key_value_array);

        json_t* current_keyobj = json_object_get(afl->current_fuzz_uri, "possible_args");
        json_array_append_new(current_keyobj, key_object);
        free(line_toadd_new);
        body_found = 1;
      }

      }
    }
    
    if(body_found == 0 && (strstr(line_has, json_string_value(value)) /*|| strstr(json_string_value(value), line_has)*/)){
      if(request_found == 1 || header_found == 1/* && strchr(line_has, '?')*/){
        break;
      }
      json_t* uri_args = json_object_get(afl->current_fuzz_uri, "possible_args");
      size_t uri_args_size = json_array_size(uri_args);
      for(size_t index = 0; index < uri_args_size; index ++){
        json_t* key_obj = json_array_get(uri_args, index);
        const char* curkeyname = json_string_value(json_object_get(key_obj, "key"));
        if(!strcmp(key, curkeyname)){

          

          json_t* key_corvalue = json_object_get(key_obj, "value");
          if(str_not_in_array(key_corvalue, line_toadd)){
            json_array_append_new(key_corvalue, json_string(line_toadd));
          }
          body_found = 1;
          break;
        }
      }    
    }
  }
}

void replaceCharacter2space(char* str, char charToReplace) {
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



void redqueen_add_dict(char* redqueen_shmem, json_t* json_in, u8* out_buf, afl_state_t* afl){
  char* newline = "\n";
  char* token1 = NULL;
  char* token2 = NULL;

  replaceCharacter2space(out_buf, '\n');

  token1 = strtok(redqueen_shmem, newline);

  while(token1 != NULL){
    char* line1 = token1;
    token2 = strtok(NULL, newline);
    if(token2 == NULL){
      break;
      FATAL("redqueen output isn't pair");
    }
    char* line2 = token2;
    char* line1_strstr = strstr(out_buf, line1);
    char* line2_strstr = strstr(out_buf, line2);
    
    if(line1_strstr && !line2_strstr){
      maybe_put_dict(afl, line1, line2, json_in);
    }else if (!line1_strstr && line2_strstr){
      maybe_put_dict(afl, line2, line1, json_in);

    }
    token1 = strtok(NULL, newline);
  }

}



char* json_to_http(json_t* root, size_t* testcase_size) {
    if(root ==NULL){
      FATAL("null root at json_to_http");
    }
    
    json_t* request = json_object_get(root, "request");
    char* result = NULL;
    const char* method = json_string_value(json_object_get(request, "method"));

    if(method == NULL){
      FATAL("method field is NULL");
    }
    if(!strcmp(method, "POST") || !strcmp(method, "GET")){
      result = json_to_http_post(root, testcase_size);
      return result;
    }
    else{
      result = json_to_http_get(root, testcase_size);
      return result;
    }
    FATAL("json_to_http cannot match");
}


json_t* get_handler_array(afl_state_t* afl){
  json_t* tmp_json_array = json_array();
  for(u32 i = 0; i < afl->extras_json_cnt; i++){
    json_t* func = json_array_get(afl->json_extras, i);
    json_array_append_new(tmp_json_array, json_object_get(func, "possible_name"));
  }

  return tmp_json_array;
}


json_t* has_value_in_handler_name(json_t* arg_value, json_t* all_names, size_t arg_size){
  json_t* secondary_uri_index_case = NULL;
  size_t name_cnt = json_array_size(all_names);
  for(u32 name_index = 0; name_index < name_cnt; name_index++){
    json_t* name_array = json_array_get(all_names, name_index);
    u32 name_array_size = json_array_size(name_array);
    for(u32 array_index = 0; array_index < name_array_size; array_index++){
        for(u32 arg_index = 0; arg_index < arg_size; arg_index++){
          const char* arg_name = json_string_value(json_array_get(arg_value, arg_index));
          const char* uri_name = json_string_value(json_array_get(name_array, array_index));

          if(!strcmp(arg_name, uri_name)){
            if(secondary_uri_index_case == NULL)
            {
              secondary_uri_index_case = json_array();
            }
            if(int_not_in_array(secondary_uri_index_case, name_index))
            {
              json_array_append_new(secondary_uri_index_case, json_integer(name_index));
            }
            
          }
        }
    }
    
  }

  return secondary_uri_index_case;
}


void find_secondary_uri(afl_state_t* afl){
  json_t* json_dict = afl->json_extras;
  afl->extras_json_cnt = json_array_size(json_dict);
  json_t* handlername_array = get_handler_array(afl);
  
  for(u32 i = 0; i < afl->extras_json_cnt; i++){
    json_t* func = json_array_get(json_dict, i);

    json_t* possible_args = json_object_get(func, "possible_args");
    size_t args_size = json_array_size(possible_args);
    for(u32 j = 0 ;  j < args_size; j++){
      json_t* pos_arg = json_array_get(possible_args, i);
      json_t* arg_value = json_object_get(pos_arg, "value");
      size_t arg_size = json_array_size(arg_value);
      if(arg_size < 10){
        continue;
      }

      json_t* valid_secondary_handler = has_value_in_handler_name(arg_value, handlername_array, arg_size);
      if(valid_secondary_handler){
          json_object_set(pos_arg, "secondary_handler", valid_secondary_handler);
      }
    }
  }
}


void update_main_dict_wrap(afl_state_t* afl){
    for(u32 cnt = 0; cnt < MAX_PROC_CNT; cnt++){
      if(afl->proc_list[cnt] == NULL){
        break;
      }
      if(likely(afl->proc_list[cnt]->has_dict == 1)){
        continue;
      }
      update_main_dict(afl, afl->proc_list[cnt]->prog_name);
      afl->proc_list[cnt]->has_dict = 1;
    }
}





int fix_index = 5;

u8 fuzz_one_http(afl_state_t *afl) {
  u32 i;
  u8 *out_buf = 0;
  u32  perf_score = 100, orig_perf=1;
  u32  uri_favored = 0;
  size_t testcase_size;
  afl->stage_name = "http_gen";

  u8 ret_val = 1;

  json_t *json_in, *json_out;


  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((afl->queue_cur->fuzz_level || !afl->queue_cur->favored) &&
        likely(rand_below(afl, 100) < SKIP_TO_NEW_PROB)) {

      return 1;

    }

  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             afl->queued_items > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 && !afl->queue_cur->fuzz_level) {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

    }

  }



  if (unlikely(afl->not_on_tty)) {

    ACTF(
        "Fuzzing test case #%u (%u total, %llu crashes saved, "
        "perf_score=%0.0f, exec_us=%llu, hits=%u, map=%u, ascii=%u)...",
        afl->current_entry, afl->queued_items, afl->saved_crashes,
        afl->queue_cur->perf_score, afl->queue_cur->exec_us,
        likely(afl->n_fuzz) ? afl->n_fuzz[afl->queue_cur->n_fuzz_entry] : 0,
        afl->queue_cur->bitmap_size, afl->queue_cur->is_ascii);
    fflush(stdout);

  }

  if(unlikely(afl->debug)){
  DEBUGF("inside json_httpd_mutation, 0\n");
}



  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  if(unlikely(afl->debug)){
  DEBUGF("inside json_httpd_mutation, 0.5\n");
}


  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    afl->queue_cur->perf_score = orig_perf = perf_score =
        calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {

    goto json_abandon_entry;

  }

  if (likely(afl->queue_cur->passed_det) || likely(afl->skip_deterministic) ||
      likely(perf_score <
             (afl->queue_cur->depth * 30 <= afl->havoc_max_mult * 100
                  ? afl->queue_cur->depth * 30
                  : afl->havoc_max_mult * 100))) {

    goto json_httpd_mutation;

  }

  if (unlikely(afl->main_node_max &&
               (afl->queue_cur->exec_cksum % afl->main_node_max) !=
                   afl->main_node_id - 1)) {

    goto json_httpd_mutation;

  }



json_httpd_mutation:

  DEBUGF("nop, 1\n");
  int max_mutation_way = 20;
  if(unlikely(afl->debug)){
    DEBUGF("inside json_httpd_mutation, 1\n");
  }

  
  update_main_dict_wrap(afl);
  if(strstr(afl->queue_cur->fname, ".raw") != NULL){
    FATAL("raw seed reach ueue_testcase_get_json");
  }
  json_in = queue_testcase_get_json(afl, afl->queue_cur);
  afl->stage_max = afl->queue_cur->perf_score / 100;

  if(json_in == NULL){
    FATAL("json_in is null before mutation");
  }

  json_out = json_in;

  uri_favored = afl->queue_cur->uri_favored;
  

for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur){
  u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
  afl->stage_cur_val = use_stacking;
#ifdef INTROSPECTION
  
  snprintf(afl->mutation, sizeof(afl->mutation), "%s HTTP-%u",
            afl->queue_cur->fname, use_stacking);
#endif
  for (i = 0; i < use_stacking; ++i) {
    int randnum = rand() % 10;

    switch (rand_below(afl, max_mutation_way)) {
      case 0:{
#ifdef INTROSPECTION
          if(unlikely(afl->debug)){
            DEBUGF("way0\n");
          }
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INCR");
          strcat(afl->mutation, afl->m_tmp);
#endif
        json_out = mutation1(json_in);
        break;
      }

      case 1:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CHANGE");
          strcat(afl->mutation, afl->m_tmp);
#endif
          if(unlikely(afl->debug)){
            DEBUGF("way1\n");
          }
          json_out = mutation2(json_in);
          break;
      }

      case 2:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ADD_DEL");
          strcat(afl->mutation, afl->m_tmp);
#endif
        if(unlikely(afl->debug)){
            DEBUGF("way2\n");
          }
        json_out = mutation3(json_in);
        break;
      }

      case 3:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HYBRID");
          strcat(afl->mutation, afl->m_tmp);
#endif   
       if(unlikely(afl->debug)){
            DEBUGF("way3\n");
          }
        json_out = mutation4(json_in, afl);
        break;
        }

      case 4:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DICT");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way4\n");
          }
        json_out = mutation5(json_in);
        break;
        }

      case 5:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ATTACK");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way5\n");
          }
        json_out = mutation6(json_in);
        break;
        }


      case 6:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HYBRID");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way6\n");
          }
        
        if(uri_favored && randnum < fix_index){
            json_out = mutation13(json_in, afl);
        }else{
          json_out = mutation4(json_in, afl);
        }
        break;
        }

      case 7:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HYBRID");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way7\n");
          }
        if(uri_favored && randnum < fix_index){
            json_out = mutation13(json_in, afl);
        }else{
          json_out = mutation12(json_in, afl);
        }
        break;
        }

      case 8:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HYBRID");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way8\n");
          }
        json_out = mutation6(json_in);
        break;
        }

      case 9:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HYBRID");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way9\n");
          }
        if(uri_favored && randnum < fix_index){
            json_out = mutation13(json_in, afl);
        }else{
          json_out = mutation12(json_in, afl);
        }
        break;
        }

      case 10:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HYBRID");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way10\n");
          }
        if(uri_favored && randnum < fix_index){
            json_out = mutation13(json_in, afl);
        }else{
          json_out = mutation12(json_in, afl);
        }
        break;
        }
        case 11:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " METHOD");
          strcat(afl->mutation, afl->m_tmp);
#endif   
        if(unlikely(afl->debug)){
            DEBUGF("way11\n");
          }
        json_out = mutation7(json_in);
        break;
        }
        case 12:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HEADER");
          strcat(afl->mutation, afl->m_tmp);
#endif
        if(unlikely(afl->debug)){
            DEBUGF("way12\n");
          }
          if(uri_favored){
            break;
          }
          json_out = mutation8(json_in, afl);
          break;
        }

        case 13:
        case 14:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLEAR");
          strcat(afl->mutation, afl->m_tmp);
#endif
        if(unlikely(afl->debug)){
            DEBUGF("way13, 14\n");
          }
        json_out = mutation9(json_in);
        break;
        }

        case 15:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HEADER");
          strcat(afl->mutation, afl->m_tmp);
#endif

    if(unlikely(afl->debug)){
            DEBUGF("way15\n");
          }
          json_out = mutation10(json_in, afl);
          break;
        }
        case 16:{
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " HEADER");
          strcat(afl->mutation, afl->m_tmp);
#endif
    if(unlikely(afl->debug)){
            DEBUGF("way16\n");
          }
          json_out = mutation11(json_in, afl);
          break;
        }
        case 17:{
          if(uri_favored){
            break;
          }else{
            json_out = mutation12(json_in, afl);
          }
          break;
        }
        case 18:{
          json_out = mutation15(json_in, afl);
          break;
        }
        

      default:{
        if(afl->housefuzz_redqueen_shmem != NULL){
          json_out = mutation14(json_in);
          break;
        }
        if(uri_favored && randnum < fix_index){
            json_out = mutation13(json_in, afl);
        }else{
          json_out = mutation12(json_in, afl);
        }
        break;
      }

      }
      json_in = json_out;
}

      out_buf = json_to_http(json_out, &testcase_size);

      if(unlikely(afl->debug)){
            DEBUGF("before common_fuzz_stuff_json\n");
          }
      
      if(afl->housefuzz_redqueen_shmem == NULL)
      {
        if(common_fuzz_stuff_json(afl, out_buf, testcase_size, json_out)) {
          if(unlikely(afl->debug)){
            DEBUGF("after common_fuzz_stuff_json\n");
          }
          free(out_buf); 
          goto json_abandon_entry;
          }
        if(unlikely(afl->debug)){
            DEBUGF("after common_fuzz_stuff_json\n");
          }
      }
      else if(afl->housefuzz_redqueen_shmem != NULL){
        int has_no_new = common_fuzz_stuff_json(afl, out_buf, testcase_size, json_out);
        redqueen_add_dict(afl->housefuzz_redqueen_shmem, json_out, out_buf, afl);
        clear_redqueen_shmem();

        if(has_no_new){
          free(out_buf); goto json_abandon_entry;
        }
      }
      free(out_buf);
    }
    if(((afl->last_find_time != 0 && get_cur_time() - afl->last_find_time > 300000) || (afl->redqueen_test!=0 && get_cur_time() - afl->start_time > 10000 && afl->redqueen_activated_times == 0)) 
    && afl->housefuzz_redqueen_shmem == NULL
    && afl->housefuzz_cfg_only == 0) 
    {
      FILE* fp = fopen("/redqueen_open.log", "a+");
      time_t t;
      time(&t);
      fprintf(fp, "SETUP redqueen, time is %ld\n", t);
      fclose(fp);

      if(access("/redqueen_on", F_OK) == 0){
        FATAL("redqueen_on present before starting redqueen");
      }
      if(access("/redqueen_shmem", F_OK) == -1 || afl->housefuzz_redqueen_shmem == NULL){
        afl->housefuzz_redqueen_shmem = setup_redqueen_shmem();
        if(afl->housefuzz_redqueen_shmem == NULL)
        {
          FATAL("Can't setup redqueen");
        }
        
      }
      afl->redqueen_start_time = get_cur_time();
      
    }

    if(afl->redqueen_start_time != 0 && (get_cur_time() - afl->redqueen_start_time > 300000 * 1) && afl->housefuzz_redqueen_shmem!= NULL
		    &&afl->housefuzz_cfg_only == 0)
    {
      afl->redqueen_activated_times += 1;
      FILE* fp = fopen("/redqueen_open.log", "a+");
      time_t t;
      time(&t);
      fprintf(fp, "STOP redqueen, time is %ld, activate time: %d\n", t, afl->redqueen_activated_times);
      fclose(fp);

      if(access("/redqueen_on", F_OK) != 0){
          FATAL("No redqueen_on file");
      }

      unset_redqueen_shmem();
      afl->housefuzz_redqueen_shmem = NULL;
      if(access("/redqueen_on", F_OK) == 0){
          FATAL("Cannot close redqueen_on file");
      }
      afl->redqueen_start_time = 0;
      json_dump_file(afl->json_extras, "updated_main.json", JSON_INDENT(4));
      json_dump_file(afl->headers_extra, "updated_header.json", JSON_INDENT(4));
      json_dump_file(afl->perfix_extra, "updated_perfix.json", JSON_INDENT(4));
    }
    



json_abandon_entry:

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      !afl->queue_cur->was_fuzzed && !afl->queue_cur->disabled) {

    --afl->pending_not_fuzzed;
    afl->queue_cur->was_fuzzed = 1;
    afl->reinit_table = 1;
    if (afl->queue_cur->favored) { --afl->pending_favored; }

  }

  ++afl->queue_cur->fuzz_level;
  return ret_val;
  

}


/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one_original(afl_state_t *afl) {

  u32 len, temp_len;
  u32 j;
  u32 i;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0, prev_cksum, _prev_cksum;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  if(afl->redqueen_start_time != 0){
    afl->redqueen_activated_times += 1;
    FILE* fp = fopen("redqueen_open.log", "a+");
    time_t t;
    time(&t);
    fprintf(fp, "STOP redqueen due to change to fuzz_one_original, time is %ld, activate time: %d\n", t, afl->redqueen_activated_times);
    fclose(fp);
  }
  unset_redqueen_shmem();
  afl->housefuzz_redqueen_shmem = NULL;
  if(access("/redqueen_on", F_OK) == 0){
    FATAL("cannot close redqueen_on file");
  }
  afl->redqueen_start_time = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  if (unlikely(afl->custom_mutators_count)) {

    /* The custom mutator will decide to skip this test case or not. */

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_queue_get &&
          !el->afl_custom_queue_get(el->data, afl->queue_cur->fname)) {

        return 1;

      }

    });

  }

  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((afl->queue_cur->fuzz_level || !afl->queue_cur->favored) &&
        likely(rand_below(afl, 100) < SKIP_TO_NEW_PROB)) {

      return 1;

    }

  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             afl->queued_items > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 && !afl->queue_cur->fuzz_level) {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

  if (unlikely(afl->not_on_tty)) {

    ACTF(
        "Fuzzing test case #%u (%u total, %llu crashes saved, "
        "perf_score=%0.0f, exec_us=%llu, hits=%u, map=%u, ascii=%u)...",
        afl->current_entry, afl->queued_items, afl->saved_crashes,
        afl->queue_cur->perf_score, afl->queue_cur->exec_us,
        likely(afl->n_fuzz) ? afl->n_fuzz[afl->queue_cur->n_fuzz_entry] : 0,
        afl->queue_cur->bitmap_size, afl->queue_cur->is_ascii);
    fflush(stdout);

  }

  orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);
  len = afl->queue_cur->len;

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      afl->queue_cur->exec_cksum = 0;

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (unlikely(res == FSRV_RUN_ERROR)) {

        FATAL("Unable to execute target application");

      }

    }

    if (unlikely(afl->stop_soon) || res != afl->crash_mode) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (unlikely(!afl->non_instrumented_mode && !afl->queue_cur->trim_done &&
               !afl->disable_trim)) {

    u32 old_len = afl->queue_cur->len;

    u8 res = trim_case(afl, afl->queue_cur, in_buf);
    orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (unlikely(afl->stop_soon)) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    afl->queue_cur->trim_done = 1;

    len = afl->queue_cur->len;

    /* maybe current entry is not ready for splicing anymore */
    if (unlikely(len <= 4 && old_len > 4)) --afl->ready_for_splicing_count;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    afl->queue_cur->perf_score = orig_perf = perf_score =
        calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {

    goto abandon_entry;

  }

  if (unlikely(afl->shm.cmplog_mode &&
               afl->queue_cur->colorized < afl->cmplog_lvl &&
               (u32)len <= afl->cmplog_max_filesize)) {

    if (unlikely(len < 4)) {

      afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    } else {

      if (afl->cmplog_lvl == 3 ||
          (afl->cmplog_lvl == 2 && afl->queue_cur->tc_ref) ||
          afl->queue_cur->favored ||
          !(afl->fsrv.total_execs % afl->queued_items) ||
          get_cur_time() - afl->last_find_time > 300000) {

        if (input_to_state_stage(afl, in_buf, out_buf, len)) {

          goto abandon_entry;

        }

      }

    }

  }

  /* Skip right away if -d is given, if it has not been chosen sufficiently
     often to warrant the expensive deterministic stage (fuzz_level), or
     if it has gone through deterministic testing in earlier, resumed runs
     (passed_det). */

  if (likely(afl->queue_cur->passed_det) || likely(afl->skip_deterministic) ||
      likely(perf_score <
             (afl->queue_cur->depth * 30 <= afl->havoc_max_mult * 100
                  ? afl->queue_cur->depth * 30
                  : afl->havoc_max_mult * 100))) {

    goto custom_mutator_stage;

  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this main instance. */

  if (unlikely(afl->main_node_max &&
               (afl->queue_cur->exec_cksum % afl->main_node_max) !=
                   afl->main_node_id - 1)) {

    goto custom_mutator_stage;

  }

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  /* Get a clean cksum. */

  if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

  prev_cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
  for(u32 i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] == NULL){
        break;
      }
      if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
      }
      if(afl->proc_list[i]->activated == 1){
        u64 tmp_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE, HASH_CONST);
        prev_cksum ^= tmp_result;
      }
    }
  _prev_cksum = prev_cksum;

  /* Now flip bits. */

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT1-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!afl->non_instrumented_mode && (afl->stage_cur & 7) == 7) {

      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      for(u32 i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] == NULL){
        break;
      }
      if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
        }
      if(afl->proc_list[i]->activated == 1){
        u64 tmp_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE, HASH_CONST);
        cksum ^= tmp_result;
      }
    }

      if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != _prev_cksum) {

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

      }

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;

  /* Two walking bits. */

  afl->stage_name = "bitflip 2/1";
  afl->stage_short = "flip2";
  afl->stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT2-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP2] += afl->stage_max;

  /* Four walking bits. */

  afl->stage_name = "bitflip 4/1";
  afl->stage_short = "flip4";
  afl->stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT4-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP4] += afl->stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map = afl_realloc(AFL_BUF_PARAM(eff), EFF_ALEN(len));
  if (unlikely(!eff_map)) { PFATAL("alloc"); }
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {

    eff_map[EFF_APOS(len - 1)] = 1;
    ++eff_cnt;

  }

  /* Walking byte. */

  afl->stage_name = "bitflip 8/8";
  afl->stage_short = "flip8";
  afl->stage_max = len;

  orig_hit_cnt = new_hit_cnt;
  prev_cksum = _prev_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur;

    out_buf[afl->stage_cur] ^= 0xFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT8-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(afl->stage_cur)]) {

      u64 cksum;

      /* If in non-instrumented mode or if the file is very short, just flag
         everything without wasting time on checksums. */

      if (!afl->non_instrumented_mode && len >= EFF_MIN_LEN) {

        cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      for(u32 i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] == NULL){
        break;
      }
      if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
      }
      if(afl->proc_list[i]->activated == 1){
        u64 tmp_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE, HASH_CONST);
        cksum ^= tmp_result;
      }
    }

      } else {

        cksum = ~prev_cksum;

      }

      if (cksum != prev_cksum) {

        eff_map[EFF_APOS(afl->stage_cur)] = 1;
        ++eff_cnt;

      }

    }

    out_buf[afl->stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != (u32)EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    afl->blocks_eff_select += EFF_ALEN(len);

  } else {

    afl->blocks_eff_select += eff_cnt;

  }

  afl->blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP8] += afl->stage_max;

  /* Two walking bytes. */

  if (len < 2) { goto skip_bitflip; }

  afl->stage_name = "bitflip 16/8";
  afl->stage_short = "flip16";
  afl->stage_cur = 0;
  afl->stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT16-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP16] += afl->stage_max;

  if (len < 4) { goto skip_bitflip; }

  /* Four walking bytes. */

  afl->stage_name = "bitflip 32/8";
  afl->stage_short = "flip32";
  afl->stage_cur = 0;
  afl->stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT32-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP32] += afl->stage_max;

skip_bitflip:

  if (afl->no_arith) { goto skip_arith; }

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  afl->stage_name = "arith 8/8";
  afl->stage_short = "arith8";
  afl->stage_cur = 0;
  afl->stage_max = 2 * len * ARITH_MAX;

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= 2 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = j;
        out_buf[i] = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH8+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = -j;
        out_buf[i] = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH8--%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) { goto skip_arith; }

  afl->stage_name = "arith 16/8";
  afl->stage_short = "arith16";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16--%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian comes next. Same deal. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16+BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16_BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      *(u16 *)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH16] += afl->stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) { goto skip_arith; }

  afl->stage_name = "arith 32/8";
  afl->stage_short = "arith32";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xffff) < (u32)j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian next. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32+BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((SWAP32(orig) & 0xffff) < (u32)j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32_BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      *(u32 *)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH32] += afl->stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  afl->stage_name = "interest 8/8";
  afl->stage_short = "int8";
  afl->stage_cur = 0;
  afl->stage_max = len * sizeof(interesting_8);

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= sizeof(interesting_8);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < (u32)sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        --afl->stage_max;
        continue;

      }

      afl->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation), "%s INTERESTING8_%u_%u",
               afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      out_buf[i] = orig;
      ++afl->stage_cur;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST8] += afl->stage_max;

  /* Setting 16-bit integers, both endians. */

  if (afl->no_arith || len < 2) { goto skip_interest; }

  afl->stage_name = "interest 16/8";
  afl->stage_short = "int16";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= sizeof(interesting_16);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      afl->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s INTERESTING16_%u_%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s INTERESTING16BE_%u_%u", afl->queue_cur->fname, i, j);
#endif

        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    *(u16 *)(out_buf + i) = orig;

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST16] += afl->stage_max;

  if (len < 4) { goto skip_interest; }

  /* Setting 32-bit integers, both endians. */

  afl->stage_name = "interest 32/8";
  afl->stage_short = "int32";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= sizeof(interesting_32) >> 1;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      afl->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s INTERESTING32_%u_%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s INTERESTING32BE_%u_%u", afl->queue_cur->fname, i, j);
#endif

        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    *(u32 *)(out_buf + i) = orig;

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST32] += afl->stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!afl->extras_cnt) { goto skip_user_extras; }

  /* Overwrite with user-supplied extras. */

  afl->stage_name = "user extras (over)";
  afl->stage_short = "ext_UO";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < afl->extras_cnt; ++j) {

      /* Skip extras probabilistically if afl->extras_cnt > AFL_MAX_DET_EXTRAS.
         Also skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((afl->extras_cnt > afl->max_det_extras &&
           rand_below(afl, afl->extras_cnt) >= afl->max_det_extras) ||
          afl->extras[j].len > len - i ||
          !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->extras[j].len;
      memcpy(out_buf + i, afl->extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UO] += afl->stage_max;

  /* Insertion of user-supplied extras. */

  afl->stage_name = "user extras (insert)";
  afl->stage_short = "ext_UI";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->extras_cnt; ++j) {

      if (len + afl->extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->extras[j].data, afl->extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation), "%s EXTRAS_insert-%u-%u",
               afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UI] += afl->stage_max;

skip_user_extras:

  if (!afl->a_extras_cnt) { goto skip_extras; }

  afl->stage_name = "auto extras (over)";
  afl->stage_short = "ext_AO";
  afl->stage_cur = 0;
  afl->stage_max = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS) * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    u32 min_extra_len = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS);
    for (j = 0; j < min_extra_len; ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (afl->a_extras[j].len > len - i ||
          !memcmp(afl->a_extras[j].data, out_buf + i, afl->a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->a_extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->a_extras[j].len;
      memcpy(out_buf + i, afl->a_extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s AUTO_EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AO] += afl->stage_max;

  /* Insertion of auto extras. */

  afl->stage_name = "auto extras (insert)";
  afl->stage_short = "ext_AI";
  afl->stage_cur = 0;
  afl->stage_max = afl->a_extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->a_extras_cnt; ++j) {

      if (len + afl->a_extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->a_extras[j].data, afl->a_extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->a_extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s AUTO_EXTRAS_insert-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->a_extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_AI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AI] += afl->stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!afl->queue_cur->passed_det) { mark_as_det_done(afl, afl->queue_cur); }

custom_mutator_stage:
  /*******************
   * CUSTOM MUTATORS *
   *******************/

  if (likely(!afl->custom_mutators_count)) { goto havoc_stage; }

  afl->stage_name = "custom mutator";
  afl->stage_short = "custom";
  afl->stage_max = HAVOC_CYCLES * perf_score / afl->havoc_div / 100;
  afl->stage_val_type = STAGE_VAL_NONE;
  bool has_custom_fuzz = false;

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  const u32 max_seed_size = MAX_FILE, saved_max = afl->stage_max;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

#ifdef INTROSPECTION
  afl->mutation[0] = 0;
#endif

  LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

    if (el->afl_custom_fuzz) {

      afl->current_custom_fuzz = el;

      if (el->afl_custom_fuzz_count) {

        afl->stage_max = el->afl_custom_fuzz_count(el->data, out_buf, len);

      } else {

        afl->stage_max = saved_max;

      }

      has_custom_fuzz = true;

      afl->stage_short = el->name_short;

      if (afl->stage_max) {

        for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;
             ++afl->stage_cur) {

          struct queue_entry *target = NULL;
          u32                 tid;
          u8                 *new_buf = NULL;
          u32                 target_len = 0;

          /* check if splicing makes sense yet (enough entries) */
          if (likely(afl->ready_for_splicing_count > 1)) {

            /* Pick a random other queue entry for passing to external API
               that has the necessary length */

            do {

              tid = rand_below(afl, afl->queued_items);

            } while (unlikely(tid == afl->current_entry ||

                              afl->queue_buf[tid]->len < 4));

            target = afl->queue_buf[tid];
            afl->splicing_with = tid;

            /* Read the additional testcase into a new buffer. */
            new_buf = queue_testcase_get(afl, target);
            target_len = target->len;

          }

          u8 *mutated_buf = NULL;

          size_t mutated_size =
              el->afl_custom_fuzz(el->data, out_buf, len, &mutated_buf, new_buf,
                                  target_len, max_seed_size);

          if (unlikely(!mutated_buf)) {

            FATAL("Error in custom_fuzz. Size returned: %zu", mutated_size);

          }

          if (mutated_size > 0) {

            if (common_fuzz_stuff(afl, mutated_buf, (u32)mutated_size)) {

              goto abandon_entry;

            }

            if (!el->afl_custom_fuzz_count) {

              /* If we're finding new stuff, let's run for a bit longer, limits
                permitting. */

              if (afl->queued_items != havoc_queued) {

                if (perf_score <= afl->havoc_max_mult * 100) {

                  afl->stage_max *= 2;
                  perf_score *= 2;

                }

                havoc_queued = afl->queued_items;

              }

            }

          }

          /* out_buf may have been changed by the call to custom_fuzz */
          memcpy(out_buf, in_buf, len);

        }

      }

    }

  });

  afl->current_custom_fuzz = NULL;

  if (!has_custom_fuzz) goto havoc_stage;

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_CUSTOM_MUTATOR] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_CUSTOM_MUTATOR] += afl->stage_max;

  if (likely(afl->custom_only)) {

    /* Skip other stages */
    ret_val = 0;
    goto abandon_entry;

  }

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    afl->stage_name = "havoc";
    afl->stage_short = "havoc";
    afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                     perf_score / afl->havoc_div / 100;

  } else {

    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "splice %u", splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = "splice";
    afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

  }

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  temp_len = len;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  havoc_queued = afl->queued_items;

  if (afl->custom_mutators_count) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->stacked_custom && el->afl_custom_havoc_mutation_probability) {

        el->stacked_custom_prob =
            el->afl_custom_havoc_mutation_probability(el->data);
        if (el->stacked_custom_prob > 100) {

          FATAL(
              "The probability returned by "
              "afl_custom_havoc_mutation_propability "
              "has to be in the range 0-100.");

        }

      }

    });

  }

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

#define MAX_HAVOC_ENTRY 64
#define MUTATE_ASCII_DICT 64

  u32 r_max, r;

  r_max = (MAX_HAVOC_ENTRY + 1) + (afl->extras_cnt ? 4 : 0) +
          (afl->a_extras_cnt
               ? (unlikely(afl->cmplog_binary && afl->queue_cur->is_ascii)
                      ? MUTATE_ASCII_DICT
                      : 4)
               : 0);

  if (unlikely(afl->expand_havoc && afl->ready_for_splicing_count > 1)) {

    /* add expensive havoc cases here, they are activated after a full
       cycle without finds happened */

    r_max += 4;

  }

  if (unlikely(get_cur_time() - afl->last_find_time > 5000 /* 5 seconds */ &&
               afl->ready_for_splicing_count > 1)) {

    /* add expensive havoc cases here if there is no findings in the last 5s */

    r_max += 4;

  }

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

    afl->stage_cur_val = use_stacking;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s HAVOC-%u",
             afl->queue_cur->fname, use_stacking);
#endif

    for (i = 0; i < use_stacking; ++i) {

      if (afl->custom_mutators_count) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (el->stacked_custom &&
              rand_below(afl, 100) < el->stacked_custom_prob) {

            u8    *custom_havoc_buf = NULL;
            size_t new_len = el->afl_custom_havoc_mutation(
                el->data, out_buf, temp_len, &custom_havoc_buf, MAX_FILE);
            if (unlikely(!custom_havoc_buf)) {

              FATAL("Error in custom_havoc (return %zu)", new_len);

            }

            if (likely(new_len > 0 && custom_havoc_buf)) {

              temp_len = new_len;
              if (out_buf != custom_havoc_buf) {

                out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len);
                if (unlikely(!afl->out_buf)) { PFATAL("alloc"); }
                memcpy(out_buf, custom_havoc_buf, temp_len);

              }

            }

          }

        });

      }

      switch ((r = rand_below(afl, r_max))) {

        case 0 ... 3: {

          /* Flip a single bit somewhere. Spooky! */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT1");
          strcat(afl->mutation, afl->m_tmp);
#endif
          FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
          break;

        }

        case 4 ... 7: {

          /* Set byte to interesting value. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] =
              interesting_8[rand_below(afl, sizeof(interesting_8))];
          break;

        }

        case 8 ... 9: {

          /* Set word to interesting value, little endian. */

          if (temp_len < 2) { break; }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16");
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          break;

        }

        case 10 ... 11: {

          /* Set word to interesting value, big endian. */

          if (temp_len < 2) { break; }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE");
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

          break;

        }

        case 12 ... 13: {

          /* Set dword to interesting value, little endian. */

          if (temp_len < 4) { break; }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32");
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

          break;

        }

        case 14 ... 15: {

          /* Set dword to interesting value, big endian. */

          if (temp_len < 4) { break; }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE");
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          break;

        }

        case 16 ... 19: {

          /* Randomly subtract from byte. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
          break;

        }

        case 20 ... 23: {

          /* Randomly add to byte. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8+");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
          break;

        }

        case 24 ... 25: {

          /* Randomly subtract from word, little endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16_-%u", pos);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 26 ... 27: {

          /* Randomly subtract from word, big endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16_BE-%u_%u", pos,
                   num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

          break;

        }

        case 28 ... 29: {

          /* Randomly add to word, little endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+-%u", pos);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 30 ... 31: {

          /* Randomly add to word, big endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+BE-%u_%u", pos,
                   num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

          break;

        }

        case 32 ... 33: {

          /* Randomly subtract from dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_-%u", pos);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 34 ... 35: {

          /* Randomly subtract from dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_BE-%u-%u", pos,
                   num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          break;

        }

        case 36 ... 37: {

          /* Randomly add to dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+-%u", pos);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 38 ... 39: {

          /* Randomly add to dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+BE-%u-%u", pos,
                   num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          break;

        }

        case 40 ... 43: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
          break;

        }

        case 44 ... 46: {

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes. */

            u32 clone_len = choose_block_len(afl, temp_len);
            u32 clone_from = rand_below(afl, temp_len - clone_len + 1);
            u32 clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s-%u-%u-%u",
                     "clone", clone_from, clone_to, clone_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;

          }

          break;

        }

        case 47: {

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Insert a block of constant bytes (25%). */

            u32 clone_len = choose_block_len(afl, HAVOC_BLK_XL);
            u32 clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s-%u-%u",
                     "insert", clone_to, clone_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memset(new_buf + clone_to,
                   rand_below(afl, 2) ? rand_below(afl, 256)
                                      : out_buf[rand_below(afl, temp_len)],
                   clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;

          }

          break;

        }

        case 48 ... 50: {

          /* Overwrite bytes with a randomly selected chunk bytes. */

          if (temp_len < 2) { break; }

          u32 copy_len = choose_block_len(afl, temp_len - 1);
          u32 copy_from = rand_below(afl, temp_len - copy_len + 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

          if (likely(copy_from != copy_to)) {

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " OVERWRITE_COPY-%u-%u-%u",
                     copy_from, copy_to, copy_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          }

          break;

        }

        case 51: {

          /* Overwrite bytes with fixed bytes. */

          if (temp_len < 2) { break; }

          u32 copy_len = choose_block_len(afl, temp_len - 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " OVERWRITE_FIXED-%u-%u",
                   copy_to, copy_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memset(out_buf + copy_to,
                 rand_below(afl, 2) ? rand_below(afl, 256)
                                    : out_buf[rand_below(afl, temp_len)],
                 copy_len);

          break;

        }

        case 52: {

          /* Increase byte by 1. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ADDBYTE_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)]++;
          break;

        }

        case 53: {

          /* Decrease byte by 1. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SUBBYTE_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)]--;
          break;

        }

        case 54: {

          /* Flip byte. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP8_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] ^= 0xff;
          break;

        }

        case 55 ... 56: {

          if (temp_len < 4) { break; }

          /* Switch bytes. */

          u32 to_end, switch_to, switch_len, switch_from;
          switch_from = rand_below(afl, temp_len);
          do {

            switch_to = rand_below(afl, temp_len);

          } while (switch_from == switch_to);

          if (switch_from < switch_to) {

            switch_len = switch_to - switch_from;
            to_end = temp_len - switch_to;

          } else {

            switch_len = switch_from - switch_to;
            to_end = temp_len - switch_from;

          }

          switch_len = choose_block_len(afl, MIN(switch_len, to_end));

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SWITCH-%s-%u-%u-%u",
                   "switch", switch_from, switch_to, switch_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), switch_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

          /* Backup */

          memcpy(new_buf, out_buf + switch_from, switch_len);

          /* Switch 1 */

          memcpy(out_buf + switch_from, out_buf + switch_to, switch_len);

          /* Switch 2 */

          memcpy(out_buf + switch_to, new_buf, switch_len);

          break;

        }

        // MAX_HAVOC_ENTRY = 64
        case 57 ... MAX_HAVOC_ENTRY: {

          /* Delete bytes. */

          if (temp_len < 2) { break; }

          /* Don't delete too much. */

          u32 del_len = choose_block_len(afl, temp_len - 1);
          u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL-%u-%u", del_from,
                   del_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          break;

        }

        default:

          r -= (MAX_HAVOC_ENTRY + 1);

          if (afl->extras_cnt) {

            if (r < 2) {

              /* Use the dictionary. */

              u32 use_extra = rand_below(afl, afl->extras_cnt);
              u32 extra_len = afl->extras[use_extra].len;

              if (extra_len > temp_len) { break; }

              u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA_OVERWRITE-%u-%u",
                       insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif
              memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                     extra_len);

              break;

            } else if (r < 4) {

              u32 use_extra = rand_below(afl, afl->extras_cnt);
              u32 extra_len = afl->extras[use_extra].len;
              if (temp_len + extra_len >= MAX_FILE) { break; }

              u8 *ptr = afl->extras[use_extra].data;
              u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA_INSERT-%u-%u",
                       insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif

              out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
              if (unlikely(!out_buf)) { PFATAL("alloc"); }

              /* Tail */
              memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                      temp_len - insert_at);

              /* Inserted part */
              memcpy(out_buf + insert_at, ptr, extra_len);
              temp_len += extra_len;

              break;

            } else {

              r -= 4;

            }

          }

          if (afl->a_extras_cnt) {

            u32 r_cmp = 2;

            if (unlikely(afl->cmplog_binary && afl->queue_cur->is_ascii)) {

              r_cmp = MUTATE_ASCII_DICT >> 1;

            }

            if (r < r_cmp) {

              /* Use the dictionary. */

              u32 use_extra = rand_below(afl, afl->a_extras_cnt);
              u32 extra_len = afl->a_extras[use_extra].len;

              if (extra_len > temp_len) { break; }

              u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                       " AUTO_EXTRA_OVERWRITE-%u-%u", insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif
              memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                     extra_len);

              break;

            } else if (r < (r_cmp << 1)) {

              u32 use_extra = rand_below(afl, afl->a_extras_cnt);
              u32 extra_len = afl->a_extras[use_extra].len;
              if (temp_len + extra_len >= MAX_FILE) { break; }

              u8 *ptr = afl->a_extras[use_extra].data;
              u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                       " AUTO_EXTRA_INSERT-%u-%u", insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif

              out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
              if (unlikely(!out_buf)) { PFATAL("alloc"); }

              /* Tail */
              memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                      temp_len - insert_at);

              /* Inserted part */
              memcpy(out_buf + insert_at, ptr, extra_len);
              temp_len += extra_len;

              break;

            } else {

              r -= (r_cmp << 1);

            }

          }

          /* Splicing otherwise if we are still here.
             Overwrite bytes with a randomly selected chunk from another
             testcase or insert that chunk. */

          /* Pick a random queue entry and seek to it. */

          u32 tid;
          do {

            tid = rand_below(afl, afl->queued_items);

          } while (tid == afl->current_entry || afl->queue_buf[tid]->len < 4);

          /* Get the testcase for splicing. */
          struct queue_entry *target = afl->queue_buf[tid];
          u32                 new_len = target->len;
          u8                 *new_buf = queue_testcase_get(afl, target);

          if ((temp_len >= 2 && r % 2) || temp_len + HAVOC_BLK_XL >= MAX_FILE) {

            /* overwrite mode */

            u32 copy_from, copy_to, copy_len;

            copy_len = choose_block_len(afl, new_len - 1);
            if (copy_len > temp_len) copy_len = temp_len;

            copy_from = rand_below(afl, new_len - copy_len + 1);
            copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                     " SPLICE_OVERWRITE-%u-%u-%u-%s", copy_from, copy_to,
                     copy_len, target->fname);
            strcat(afl->mutation, afl->m_tmp);
#endif
            memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

          } else {

            /* insert mode */

            u32 clone_from, clone_to, clone_len;

            clone_len = choose_block_len(afl, new_len);
            clone_from = rand_below(afl, new_len - clone_len + 1);
            clone_to = rand_below(afl, temp_len + 1);

            u8 *temp_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                       temp_len + clone_len + 1);
            if (unlikely(!temp_buf)) { PFATAL("alloc"); }

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                     " SPLICE_INSERT-%u-%u-%u-%s", clone_from, clone_to,
                     clone_len, target->fname);
            strcat(afl->mutation, afl->m_tmp);
#endif
            /* Head */

            memcpy(temp_buf, out_buf, clone_to);

            /* Inserted part */

            memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

            /* Tail */
            memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = temp_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;

          }

          break;

          // end of default

      }

    }

    if (common_fuzz_stuff(afl, out_buf, temp_len)) { goto abandon_entry; }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (afl->queued_items != havoc_queued) {

      if (perf_score <= afl->havoc_max_mult * 100) {

        afl->stage_max *= 2;
        perf_score *= 2;

      }

      havoc_queued = afl->queued_items;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  if (!splice_cycle) {

    afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;

  } else {

    afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;

  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (afl->use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      afl->ready_for_splicing_count > 1 && afl->queue_cur->len >= 4) {

    struct queue_entry *target;
    u32                 tid, split_at;
    u8                 *new_buf;
    s32                 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {

      in_buf = orig_in;
      len = afl->queue_cur->len;

    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do {

      tid = rand_below(afl, afl->queued_items);

    } while (tid == afl->current_entry || afl->queue_buf[tid]->len < 4);

    /* Get the testcase */
    afl->splicing_with = tid;
    target = afl->queue_buf[tid];
    new_buf = queue_testcase_get(afl, target);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, (s64)target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) { goto retry_splicing; }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + rand_below(afl, l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    afl->in_scratch_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), len);
    memcpy(afl->in_scratch_buf, in_buf, split_at);
    memcpy(afl->in_scratch_buf + split_at, new_buf, len - split_at);
    in_buf = afl->in_scratch_buf;
    afl_swap_bufs(AFL_BUF_PARAM(in), AFL_BUF_PARAM(in_scratch));

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    memcpy(out_buf, in_buf, len);

    goto custom_mutator_stage;

  }

#endif                                                     /* !IGNORE_FINDS */

  ret_val = 0;

/* we are through with this queue entry - for this iteration */
abandon_entry:

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      !afl->queue_cur->was_fuzzed && !afl->queue_cur->disabled) {

    --afl->pending_not_fuzzed;
    afl->queue_cur->was_fuzzed = 1;
    afl->reinit_table = 1;
    if (afl->queue_cur->favored) { --afl->pending_favored; }

  }

  ++afl->queue_cur->fuzz_level;
  orig_in = NULL;
  return ret_val;

#undef FLIP_BIT

}

/* MOpt mode */
static u8 mopt_common_fuzzing(afl_state_t *afl, MOpt_globals_t MOpt_globals) {

  if (!MOpt_globals.is_pilot_mode) {

    if (swarm_num == 1) {

      afl->key_module = 2;
      return 0;

    }

  }

  u32 len, temp_len;
  u32 i;
  u32 j;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0, cur_ms_lv, prev_cksum,
      _prev_cksum;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((afl->queue_cur->fuzz_level || !afl->queue_cur->favored) &&
        rand_below(afl, 100) < SKIP_TO_NEW_PROB) {

      return 1;

    }

  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             afl->queued_items > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 && !afl->queue_cur->fuzz_level) {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

  if (afl->not_on_tty) {

    ACTF("Fuzzing test case #%u (%u total, %llu crashes saved)...",
         afl->current_entry, afl->queued_items, afl->saved_crashes);
    fflush(stdout);

  }

  /* Map the test case into memory. */
  orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);
  len = afl->queue_cur->len;

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      afl->queue_cur->exec_cksum = 0;

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (res == FSRV_RUN_ERROR) {

        FATAL("Unable to execute target application");

      }

    }

    if (afl->stop_soon || res != afl->crash_mode) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (unlikely(!afl->non_instrumented_mode && !afl->queue_cur->trim_done &&
               !afl->disable_trim)) {

    u32 old_len = afl->queue_cur->len;

    u8 res = trim_case(afl, afl->queue_cur, in_buf);
    orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (unlikely(afl->stop_soon)) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    afl->queue_cur->trim_done = 1;

    len = afl->queue_cur->len;

    /* maybe current entry is not ready for splicing anymore */
    if (unlikely(len <= 4 && old_len > 4)) --afl->ready_for_splicing_count;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    orig_perf = perf_score = calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {

    goto abandon_entry;

  }

  if (unlikely(afl->shm.cmplog_mode &&
               afl->queue_cur->colorized < afl->cmplog_lvl &&
               (u32)len <= afl->cmplog_max_filesize)) {

    if (unlikely(len < 4)) {

      afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    } else {

      if (afl->cmplog_lvl == 3 ||
          (afl->cmplog_lvl == 2 && afl->queue_cur->tc_ref) ||
          !(afl->fsrv.total_execs % afl->queued_items) ||
          get_cur_time() - afl->last_find_time > 300000) {  

        if (input_to_state_stage(afl, in_buf, out_buf, len)) {

          goto abandon_entry;

        }

      }

    }

  }

  /* Go to pacemker fuzzing if MOpt is doing well */

  cur_ms_lv = get_cur_time();
  if (!(afl->key_puppet == 0 &&
        ((cur_ms_lv - afl->last_find_time < (u32)afl->limit_time_puppet) ||
         (afl->last_crash_time != 0 &&
          cur_ms_lv - afl->last_crash_time < (u32)afl->limit_time_puppet) ||
         afl->last_find_time == 0))) {

    afl->key_puppet = 1;
    goto pacemaker_fuzzing;

  }

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (likely(afl->skip_deterministic || afl->queue_cur->was_fuzzed ||
             afl->queue_cur->passed_det)) {

    goto havoc_stage;

  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this main instance. */

  if (unlikely(afl->main_node_max &&
               (afl->queue_cur->exec_cksum % afl->main_node_max) !=
                   afl->main_node_id - 1)) {

    goto havoc_stage;

  }

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  /* Get a clean cksum. */

  if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

  prev_cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

  for(u32 i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] == NULL){
        continue;
      }
      if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
      }
      if(afl->proc_list[i]->activated == 1){
        u64 tmp_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE, HASH_CONST);
        prev_cksum ^= tmp_result;
      }
    }
  _prev_cksum = prev_cksum;

  /* Now flip bits. */

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT1-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!afl->non_instrumented_mode && (afl->stage_cur & 7) == 7) {

      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      for(u32 i = 0; i<MAX_PROC_CNT; i++){
      if(afl->proc_list[i] == NULL){
        break;
      }
      if(proc_in_blacklist(afl, afl->proc_list[i])){
          continue;
      }
      if(afl->proc_list[i]->activated == 1){
        u64 tmp_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE, HASH_CONST);
        cksum ^= tmp_result;
      }
    }

      if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != _prev_cksum) {

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

      }

    }                                       /* if (afl->stage_cur & 7) == 7 */

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;

  /* Two walking bits. */

  afl->stage_name = "bitflip 2/1";
  afl->stage_short = "flip2";
  afl->stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT2-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP2] += afl->stage_max;

  /* Four walking bits. */

  afl->stage_name = "bitflip 4/1";
  afl->stage_short = "flip4";
  afl->stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT4-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP4] += afl->stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
         flag first and last byte as doing something. */

  eff_map = afl_realloc(AFL_BUF_PARAM(eff), EFF_ALEN(len));
  if (unlikely(!eff_map)) { PFATAL("alloc"); }
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {

    eff_map[EFF_APOS(len - 1)] = 1;
    ++eff_cnt;

  }

  /* Walking byte. */

  afl->stage_name = "bitflip 8/8";
  afl->stage_short = "flip8";
  afl->stage_max = len;

  orig_hit_cnt = new_hit_cnt;
  prev_cksum = _prev_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur;

    out_buf[afl->stage_cur] ^= 0xFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT8-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(afl->stage_cur)]) {

      u64 cksum;

      /* If in non-instrumented mode or if the file is very short, just flag
         everything without wasting time on checksums. */

      if (!afl->non_instrumented_mode && len >= EFF_MIN_LEN) {

        cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

        for(u32 i = 0; i<MAX_PROC_CNT; i++){
          if(afl->proc_list[i] == NULL){
            break;
          }
          if(proc_in_blacklist(afl, afl->proc_list[i])){
            continue;
          }
          if(afl->proc_list[i]->activated == 1){
            u64 tmp_result = hash64(afl->proc_list[i]->trace_bits, MAP_SIZE, HASH_CONST);
            cksum ^= tmp_result;
          }
        }

      } else {

        cksum = ~prev_cksum;

      }

      if (cksum != prev_cksum) {

        eff_map[EFF_APOS(afl->stage_cur)] = 1;
        ++eff_cnt;

      }

    }

    out_buf[afl->stage_cur] ^= 0xFF;

  }                                                   /* for afl->stage_cur */

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != (u32)EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    afl->blocks_eff_select += EFF_ALEN(len);

  } else {

    afl->blocks_eff_select += eff_cnt;

  }

  afl->blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP8] += afl->stage_max;

  /* Two walking bytes. */

  if (len < 2) { goto skip_bitflip; }

  afl->stage_name = "bitflip 16/8";
  afl->stage_short = "flip16";
  afl->stage_cur = 0;
  afl->stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT16-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP16] += afl->stage_max;

  if (len < 4) { goto skip_bitflip; }

  /* Four walking bytes. */

  afl->stage_name = "bitflip 32/8";
  afl->stage_short = "flip32";
  afl->stage_cur = 0;
  afl->stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT32-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP32] += afl->stage_max;

skip_bitflip:

  if (afl->no_arith) { goto skip_arith; }

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  afl->stage_name = "arith 8/8";
  afl->stage_short = "arith8";
  afl->stage_cur = 0;
  afl->stage_max = 2 * len * ARITH_MAX;

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= 2 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = j;
        out_buf[i] = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH8+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = -j;
        out_buf[i] = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH8_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      out_buf[i] = orig;

    }

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) { goto skip_arith; }

  afl->stage_name = "arith 16/8";
  afl->stage_short = "arith16";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH16+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH16_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian comes next. Same deal. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH16+BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH16_BE+%u+%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      *(u16 *)(out_buf + i) = orig;

    }

  }                                               /* for i = 0; i < len - 1 */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH16] += afl->stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) { goto skip_arith; }

  afl->stage_name = "arith 32/8";
  afl->stage_short = "arith32";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH32+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH32_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian next. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH32+BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH32_BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      *(u32 *)(out_buf + i) = orig;

    }

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH32] += afl->stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  afl->stage_name = "interest 8/8";
  afl->stage_short = "int8";
  afl->stage_cur = 0;
  afl->stage_max = len * sizeof(interesting_8);

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= sizeof(interesting_8);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        --afl->stage_max;
        continue;

      }

      afl->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_INTERESTING8-%u-%u", afl->queue_cur->fname, i, j);
#endif
      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      out_buf[i] = orig;
      ++afl->stage_cur;

    }

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST8] += afl->stage_max;

  /* Setting 16-bit integers, both endians. */

  if (afl->no_arith || len < 2) { goto skip_interest; }

  afl->stage_name = "interest 16/8";
  afl->stage_short = "int16";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= sizeof(interesting_16);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      afl->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING16-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING16BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    *(u16 *)(out_buf + i) = orig;

  }                                               /* for i = 0; i < len - 1 */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST16] += afl->stage_max;

  if (len < 4) { goto skip_interest; }

  /* Setting 32-bit integers, both endians. */

  afl->stage_name = "interest 32/8";
  afl->stage_short = "int32";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= sizeof(interesting_32) >> 1;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      afl->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING32-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING32BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    *(u32 *)(out_buf + i) = orig;

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST32] += afl->stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!afl->extras_cnt) { goto skip_user_extras; }

  /* Overwrite with user-supplied extras. */

  afl->stage_name = "user extras (over)";
  afl->stage_short = "ext_UO";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < afl->extras_cnt; ++j) {

      /* Skip extras probabilistically if afl->extras_cnt > AFL_MAX_DET_EXTRAS.
         Also skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((afl->extras_cnt > afl->max_det_extras &&
           rand_below(afl, afl->extras_cnt) >= afl->max_det_extras) ||
          afl->extras[j].len > len - i ||
          !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->extras[j].len;
      memcpy(out_buf + i, afl->extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UO] += afl->stage_max;

  /* Insertion of user-supplied extras. */

  afl->stage_name = "user extras (insert)";
  afl->stage_short = "ext_UI";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->extras_cnt; ++j) {

      if (len + afl->extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->extras[j].data, afl->extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_EXTRAS_insert-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }                                                  /* for i = 0; i <= len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UI] += afl->stage_max;

skip_user_extras:

  if (!afl->a_extras_cnt) { goto skip_extras; }

  afl->stage_name = "auto extras (over)";
  afl->stage_short = "ext_AO";
  afl->stage_cur = 0;
  afl->stage_max = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS) * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    u32 min_extra_len = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS);
    for (j = 0; j < min_extra_len; ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if ((afl->a_extras[j].len) > (len - i) ||
          !memcmp(afl->a_extras[j].data, out_buf + i, afl->a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->a_extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->a_extras[j].len;
      memcpy(out_buf + i, afl->a_extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_AUTO_EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i,
               j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AO] += afl->stage_max;

  /* Insertion of auto extras. */

  afl->stage_name = "auto extras (insert)";
  afl->stage_short = "ext_AI";
  afl->stage_cur = 0;
  afl->stage_max = afl->a_extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->a_extras_cnt; ++j) {

      if (len + afl->a_extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->a_extras[j].data, afl->a_extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->a_extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_AUTO_EXTRAS_insert-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->a_extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }                                                  /* for i = 0; i <= len */

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRAS_AI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AI] += afl->stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!afl->queue_cur->passed_det) { mark_as_det_done(afl, afl->queue_cur); }

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:
pacemaker_fuzzing:

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    afl->stage_name = MOpt_globals.havoc_stagename;
    afl->stage_short = MOpt_globals.havoc_stagenameshort;
    afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                     perf_score / afl->havoc_div / 100;

  } else {

    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE,
             MOpt_globals.splice_stageformat, splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = MOpt_globals.splice_stagenameshort;
    afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

  }

  s32 temp_len_puppet;

  {

    if (afl->key_puppet == 1) {

      if (unlikely(afl->orig_hit_cnt_puppet == 0)) {

        afl->orig_hit_cnt_puppet = afl->queued_items + afl->saved_crashes;
        afl->last_limit_time_start = get_cur_time();
        afl->SPLICE_CYCLES_puppet =
            (rand_below(
                 afl, SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) +
             SPLICE_CYCLES_puppet_low);

      }

    }                                            /* if afl->key_puppet == 1 */

    {

#ifndef IGNORE_FINDS
    havoc_stage_puppet:
#endif

      afl->stage_cur_byte = -1;

      /* The havoc stage mutation code is also invoked when splicing files; if
         the splice_cycle variable is set, generate different descriptions and
         such. */

      if (!splice_cycle) {

        afl->stage_name = MOpt_globals.havoc_stagename;
        afl->stage_short = MOpt_globals.havoc_stagenameshort;
        afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                         perf_score / afl->havoc_div / 100;

      } else {

        perf_score = orig_perf;
        snprintf(afl->stage_name_buf, STAGE_BUF_SIZE,
                 MOpt_globals.splice_stageformat, splice_cycle);
        afl->stage_name = afl->stage_name_buf;
        afl->stage_short = MOpt_globals.splice_stagenameshort;
        afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

      }

      if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

      temp_len = len;

      orig_hit_cnt = afl->queued_items + afl->saved_crashes;

      havoc_queued = afl->queued_items;

      u32 r_max, r;

      r_max = 16 + ((afl->extras_cnt + afl->a_extras_cnt) ? 2 : 0);

      if (unlikely(afl->expand_havoc && afl->ready_for_splicing_count > 1)) {

        /* add expensive havoc cases here, they are activated after a full
           cycle without any finds happened */

        ++r_max;

      }

      for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;
           ++afl->stage_cur) {

        u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

        afl->stage_cur_val = use_stacking;

        for (i = 0; i < operator_num; ++i) {

          MOpt_globals.cycles_v3[i] = MOpt_globals.cycles_v2[i];

        }

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_HAVOC-%u",
                 afl->queue_cur->fname, use_stacking);
#endif

        for (i = 0; i < use_stacking; ++i) {

          switch (r = (select_algorithm(afl, r_max))) {

            case 0:
              /* Flip a single bit somewhere. Spooky! */
              FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
              MOpt_globals.cycles_v2[STAGE_FLIP1]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT1");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 1:
              if (temp_len < 2) { break; }
              temp_len_puppet = rand_below(afl, (temp_len << 3) - 1);
              FLIP_BIT(out_buf, temp_len_puppet);
              FLIP_BIT(out_buf, temp_len_puppet + 1);
              MOpt_globals.cycles_v2[STAGE_FLIP2]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT2");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 2:
              if (temp_len < 2) { break; }
              temp_len_puppet = rand_below(afl, (temp_len << 3) - 3);
              FLIP_BIT(out_buf, temp_len_puppet);
              FLIP_BIT(out_buf, temp_len_puppet + 1);
              FLIP_BIT(out_buf, temp_len_puppet + 2);
              FLIP_BIT(out_buf, temp_len_puppet + 3);
              MOpt_globals.cycles_v2[STAGE_FLIP4]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT4");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 3:
              if (temp_len < 4) { break; }
              out_buf[rand_below(afl, temp_len)] ^= 0xFF;
              MOpt_globals.cycles_v2[STAGE_FLIP8]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 4:
              if (temp_len < 8) { break; }
              *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) ^= 0xFFFF;
              MOpt_globals.cycles_v2[STAGE_FLIP16]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT16");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 5:
              if (temp_len < 8) { break; }
              *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) ^= 0xFFFFFFFF;
              MOpt_globals.cycles_v2[STAGE_FLIP32]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT32");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 6:
              out_buf[rand_below(afl, temp_len)] -=
                  1 + rand_below(afl, ARITH_MAX);
              out_buf[rand_below(afl, temp_len)] +=
                  1 + rand_below(afl, ARITH_MAX);
              MOpt_globals.cycles_v2[STAGE_ARITH8]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 7:
              /* Randomly subtract from word, random endian. */
              if (temp_len < 8) { break; }
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
                *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

              }

              /* Randomly add to word, random endian. */
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE+-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

              }

              MOpt_globals.cycles_v2[STAGE_ARITH16]++;
              break;

            case 8:
              /* Randomly subtract from dword, random endian. */
              if (temp_len < 8) { break; }
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE_-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

              }

              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE+-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

              }

              MOpt_globals.cycles_v2[STAGE_ARITH32]++;
              break;

            case 9:
              /* Set byte to interesting value. */
              if (temp_len < 4) { break; }
              out_buf[rand_below(afl, temp_len)] =
                  interesting_8[rand_below(afl, sizeof(interesting_8))];
              MOpt_globals.cycles_v2[STAGE_INTEREST8]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 10:
              /* Set word to interesting value, randomly choosing endian. */
              if (temp_len < 8) { break; }
              if (rand_below(afl, 2)) {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    interesting_16[rand_below(afl,
                                              sizeof(interesting_16) >> 1)];

              } else {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    SWAP16(interesting_16[rand_below(
                        afl, sizeof(interesting_16) >> 1)]);

              }

              MOpt_globals.cycles_v2[STAGE_INTEREST16]++;
              break;

            case 11:
              /* Set dword to interesting value, randomly choosing endian. */

              if (temp_len < 8) { break; }

              if (rand_below(afl, 2)) {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    interesting_32[rand_below(afl,
                                              sizeof(interesting_32) >> 2)];

              } else {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    SWAP32(interesting_32[rand_below(
                        afl, sizeof(interesting_32) >> 2)]);

              }

              MOpt_globals.cycles_v2[STAGE_INTEREST32]++;
              break;

            case 12:

              /* Just set a random byte to a random value. Because,
                 why not. We use XOR with 1-255 to eliminate the
                 possibility of a no-op. */

              out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
              MOpt_globals.cycles_v2[STAGE_RANDOMBYTE]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 13: {

              /* Delete bytes. We're making this a bit more likely
                 than insertion (the next option) in hopes of keeping
                 files reasonably small. */

              u32 del_from, del_len;

              if (temp_len < 2) { break; }

              /* Don't delete too much. */

              del_len = choose_block_len(afl, temp_len - 1);

              del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL-%u%u", del_from,
                       del_len);
              strcat(afl->mutation, afl->m_tmp);
#endif
              memmove(out_buf + del_from, out_buf + del_from + del_len,
                      temp_len - del_from - del_len);

              temp_len -= del_len;
              MOpt_globals.cycles_v2[STAGE_DELETEBYTE]++;
              break;

            }

            case 14:

              if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

                /* Clone bytes (75%) or insert a block of constant bytes (25%).
                 */

                u8  actually_clone = rand_below(afl, 4);
                u32 clone_from, clone_to, clone_len;
                u8 *new_buf;

                if (likely(actually_clone)) {

                  clone_len = choose_block_len(afl, temp_len);
                  clone_from = rand_below(afl, temp_len - clone_len + 1);

                } else {

                  clone_len = choose_block_len(afl, HAVOC_BLK_XL);
                  clone_from = 0;

                }

                clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE_%s-%u-%u-%u",
                         actually_clone ? "clone" : "insert", clone_from,
                         clone_to, clone_len);
                strcat(afl->mutation, afl->m_tmp);
#endif
                new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                      temp_len + clone_len);
                if (unlikely(!new_buf)) { PFATAL("alloc"); }

                /* Head */

                memcpy(new_buf, out_buf, clone_to);

                /* Inserted part */

                if (actually_clone) {

                  memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

                } else {

                  memset(new_buf + clone_to,
                         rand_below(afl, 2)
                             ? rand_below(afl, 256)
                             : out_buf[rand_below(afl, temp_len)],
                         clone_len);

                }

                /* Tail */
                memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                       temp_len - clone_to);

                out_buf = new_buf;
                afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
                temp_len += clone_len;
                MOpt_globals.cycles_v2[STAGE_Clone75]++;

              }

              break;

            case 15: {

              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                 bytes (25%). */

              u32 copy_from, copy_to, copy_len;

              if (temp_len < 2) { break; }

              copy_len = choose_block_len(afl, temp_len - 1);

              copy_from = rand_below(afl, temp_len - copy_len + 1);
              copy_to = rand_below(afl, temp_len - copy_len + 1);

              if (likely(rand_below(afl, 4))) {

                if (likely(copy_from != copy_to)) {

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " OVERWRITE_COPY-%u-%u-%u", copy_from, copy_to,
                           copy_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

                }

              } else {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " OVERWRITE_FIXED-%u-%u-%u", copy_from, copy_to,
                         copy_len);
                strcat(afl->mutation, afl->m_tmp);
#endif
                memset(out_buf + copy_to,
                       rand_below(afl, 2) ? rand_below(afl, 256)
                                          : out_buf[rand_below(afl, temp_len)],
                       copy_len);

              }

              MOpt_globals.cycles_v2[STAGE_OverWrite75]++;
              break;

            }                                                    /* case 15 */

            default: {

              /* Values 16 and 17 can be selected only if there are any extras
                 present in the dictionaries. */

              r -= 16;

              if (r == 0 && (afl->extras_cnt || afl->a_extras_cnt)) {

                /* Overwrite bytes with an extra. */

                if (!afl->extras_cnt ||
                    (afl->a_extras_cnt && rand_below(afl, 2))) {

                  /* No user-specified extras or odds in our favor. Let's use an
                    auto-detected one. */

                  u32 use_extra = rand_below(afl, afl->a_extras_cnt);
                  u32 extra_len = afl->a_extras[use_extra].len;

                  if (extra_len > (u32)temp_len) break;

                  u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " AUTO_EXTRA_OVERWRITE-%u-%u", insert_at, extra_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                         extra_len);

                } else {

                  /* No auto extras or odds in our favor. Use the dictionary. */

                  u32 use_extra = rand_below(afl, afl->extras_cnt);
                  u32 extra_len = afl->extras[use_extra].len;

                  if (extra_len > (u32)temp_len) break;

                  u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " EXTRA_OVERWRITE-%u-%u", insert_at, extra_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                         extra_len);

                }

                MOpt_globals.cycles_v2[STAGE_OverWriteExtra]++;

                break;

              }

              /* Insert an extra. */

              else if (r == 1 && (afl->extras_cnt || afl->a_extras_cnt)) {

                u32 use_extra, extra_len,
                    insert_at = rand_below(afl, temp_len + 1);
                u8 *ptr;

                /* Insert an extra. Do the same dice-rolling stuff as for the
                  previous case. */

                if (!afl->extras_cnt ||
                    (afl->a_extras_cnt && rand_below(afl, 2))) {

                  use_extra = rand_below(afl, afl->a_extras_cnt);
                  extra_len = afl->a_extras[use_extra].len;
                  ptr = afl->a_extras[use_extra].data;
#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " AUTO_EXTRA_INSERT-%u-%u", insert_at, extra_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif

                } else {

                  use_extra = rand_below(afl, afl->extras_cnt);
                  extra_len = afl->extras[use_extra].len;
                  ptr = afl->extras[use_extra].data;
#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " EXTRA_INSERT-%u-%u", insert_at, extra_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif

                }

                if (temp_len + extra_len >= MAX_FILE) break;

                out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
                if (unlikely(!out_buf)) { PFATAL("alloc"); }

                /* Tail */
                memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                        temp_len - insert_at);

                /* Inserted part */
                memcpy(out_buf + insert_at, ptr, extra_len);

                temp_len += extra_len;
                MOpt_globals.cycles_v2[STAGE_InsertExtra]++;
                break;

              } else {

                if (unlikely(afl->ready_for_splicing_count < 2)) break;

                u32 tid;
                do {

                  tid = rand_below(afl, afl->queued_items);

                } while (tid == afl->current_entry ||

                         afl->queue_buf[tid]->len < 4);

                /* Get the testcase for splicing. */
                struct queue_entry *target = afl->queue_buf[tid];
                u32                 new_len = target->len;
                u8                 *new_buf = queue_testcase_get(afl, target);

                if ((temp_len >= 2 && rand_below(afl, 2)) ||
                    temp_len + HAVOC_BLK_XL >= MAX_FILE) {

                  /* overwrite mode */

                  u32 copy_from, copy_to, copy_len;

                  copy_len = choose_block_len(afl, new_len - 1);
                  if (copy_len > temp_len) copy_len = temp_len;

                  copy_from = rand_below(afl, new_len - copy_len + 1);
                  copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " SPLICE_OVERWRITE-%u-%u-%u-%s", copy_from, copy_to,
                           copy_len, target->fname);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

                } else {

                  /* insert mode */

                  u32 clone_from, clone_to, clone_len;

                  clone_len = choose_block_len(afl, new_len);
                  clone_from = rand_below(afl, new_len - clone_len + 1);
                  clone_to = rand_below(afl, temp_len + 1);

                  u8 *temp_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                             temp_len + clone_len + 1);
                  if (unlikely(!temp_buf)) { PFATAL("alloc"); }

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " SPLICE_INSERT-%u-%u-%u-%s", clone_from, clone_to,
                           clone_len, target->fname);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  /* Head */

                  memcpy(temp_buf, out_buf, clone_to);

                  /* Inserted part */

                  memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

                  /* Tail */
                  memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                         temp_len - clone_to);

                  out_buf = temp_buf;
                  afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
                  temp_len += clone_len;

                }

                MOpt_globals.cycles_v2[STAGE_Splice]++;
                break;

              }

            }  // end of default:

          }                                    /* switch select_algorithm() */

        }                                      /* for i=0; i < use_stacking */

        ++*MOpt_globals.pTime;

        u64 temp_total_found = afl->queued_items + afl->saved_crashes;

        if (common_fuzz_stuff(afl, out_buf, temp_len)) {

          goto abandon_entry_puppet;

        }

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
        if (unlikely(!out_buf)) { PFATAL("alloc"); }
        temp_len = len;
        memcpy(out_buf, in_buf, len);

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (afl->queued_items != havoc_queued) {

          if (perf_score <= afl->havoc_max_mult * 100) {

            afl->stage_max *= 2;
            perf_score *= 2;

          }

          havoc_queued = afl->queued_items;

        }

        if (unlikely(afl->queued_items + afl->saved_crashes >
                     temp_total_found)) {

          u64 temp_temp_puppet =
              afl->queued_items + afl->saved_crashes - temp_total_found;
          afl->total_puppet_find = afl->total_puppet_find + temp_temp_puppet;

          if (MOpt_globals.is_pilot_mode) {

            for (i = 0; i < operator_num; ++i) {

              if (MOpt_globals.cycles_v2[i] > MOpt_globals.cycles_v3[i]) {

                MOpt_globals.finds_v2[i] += temp_temp_puppet;

              }

            }

          } else {

            for (i = 0; i < operator_num; i++) {

              if (afl->core_operator_cycles_puppet_v2[i] >
                  afl->core_operator_cycles_puppet_v3[i])

                afl->core_operator_finds_puppet_v2[i] += temp_temp_puppet;

            }

          }

        }                                                             /* if */

      } /* for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;

           ++afl->stage_cur) { */

      new_hit_cnt = afl->queued_items + afl->saved_crashes;

      if (MOpt_globals.is_pilot_mode) {

        if (!splice_cycle) {

          afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
          afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;

        } else {

          afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
          afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;

        }

      }

#ifndef IGNORE_FINDS

      /************
       * SPLICING *
       ************/

    retry_splicing_puppet:

      if (afl->use_splicing &&
          splice_cycle++ < (u32)afl->SPLICE_CYCLES_puppet &&
          afl->ready_for_splicing_count > 1 && afl->queue_cur->len >= 4) {

        struct queue_entry *target;
        u32                 tid, split_at;
        u8                 *new_buf;
        s32                 f_diff, l_diff;

        /* First of all, if we've modified in_buf for havoc, let's clean that
           up... */

        if (in_buf != orig_in) {

          in_buf = orig_in;
          len = afl->queue_cur->len;

        }

        /* Pick a random queue entry and seek to it. Don't splice with yourself.
         */

        do {

          tid = rand_below(afl, afl->queued_items);

        } while (tid == afl->current_entry || afl->queue_buf[tid]->len < 4);

        afl->splicing_with = tid;
        target = afl->queue_buf[tid];

        /* Read the testcase into a new buffer. */
        new_buf = queue_testcase_get(afl, target);

        /* Find a suitable splicin g location, somewhere between the first and
           the last differing byte. Bail out if the difference is just a single
           byte or so. */

        locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

        if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {

          goto retry_splicing_puppet;

        }

        /* Split somewhere between the first and last differing byte. */

        split_at = f_diff + rand_below(afl, l_diff - f_diff);

        /* Do the thing. */

        len = target->len;
        afl->in_scratch_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), len);
        memcpy(afl->in_scratch_buf, in_buf, split_at);
        memcpy(afl->in_scratch_buf + split_at, new_buf, len - split_at);
        in_buf = afl->in_scratch_buf;
        afl_swap_bufs(AFL_BUF_PARAM(in), AFL_BUF_PARAM(in_scratch));

        out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
        if (unlikely(!out_buf)) { PFATAL("alloc"); }
        memcpy(out_buf, in_buf, len);

        goto havoc_stage_puppet;

      }                                                  /* if splice_cycle */

#endif                                                     /* !IGNORE_FINDS */

      ret_val = 0;

    abandon_entry:
    abandon_entry_puppet:

      if ((s64)splice_cycle >= afl->SPLICE_CYCLES_puppet) {

        afl->SPLICE_CYCLES_puppet =
            (rand_below(
                 afl, SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) +
             SPLICE_CYCLES_puppet_low);

      }

      afl->splicing_with = -1;

      /* Update afl->pending_not_fuzzed count if we made it through the
         calibration cycle and have not seen this entry before. */
      /*
        // TODO FIXME: I think we need this plus need an -L -1 check
        if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
            (afl->queue_cur->was_fuzzed == 0 || afl->queue_cur->fuzz_level == 0)
        && !afl->queue_cur->disabled) {

          if (!afl->queue_cur->was_fuzzed) {

            --afl->pending_not_fuzzed;
            afl->queue_cur->was_fuzzed = 1;
            if (afl->queue_cur->favored) { --afl->pending_favored; }

          }

        }

      */

      orig_in = NULL;

      if (afl->key_puppet == 1) {

        if (unlikely(
                afl->queued_items + afl->saved_crashes >
                ((afl->queued_items + afl->saved_crashes) * limit_time_bound +
                 afl->orig_hit_cnt_puppet))) {

          afl->key_puppet = 0;
          afl->orig_hit_cnt_puppet = 0;
          afl->last_limit_time_start = 0;

        }

      }

      if (unlikely(*MOpt_globals.pTime > MOpt_globals.period)) {

        afl->total_pacemaker_time += *MOpt_globals.pTime;
        *MOpt_globals.pTime = 0;
        new_hit_cnt = afl->queued_items + afl->saved_crashes;

        if (MOpt_globals.is_pilot_mode) {

          afl->swarm_fitness[afl->swarm_now] =
              (double)(afl->total_puppet_find - afl->temp_puppet_find) /
              ((double)(afl->tmp_pilot_time) / afl->period_pilot_tmp);

        }

        afl->temp_puppet_find = afl->total_puppet_find;
        for (i = 0; i < operator_num; ++i) {

          if (MOpt_globals.is_pilot_mode) {

            double temp_eff = 0.0;

            if (MOpt_globals.cycles_v2[i] > MOpt_globals.cycles[i]) {

              temp_eff =
                  (double)(MOpt_globals.finds_v2[i] - MOpt_globals.finds[i]) /
                  (double)(MOpt_globals.cycles_v2[i] - MOpt_globals.cycles[i]);

            }

            if (afl->eff_best[afl->swarm_now][i] < temp_eff) {

              afl->eff_best[afl->swarm_now][i] = temp_eff;
              afl->L_best[afl->swarm_now][i] = afl->x_now[afl->swarm_now][i];

            }

          }

          MOpt_globals.finds[i] = MOpt_globals.finds_v2[i];
          MOpt_globals.cycles[i] = MOpt_globals.cycles_v2[i];

        }                                    /* for i = 0; i < operator_num */

        if (MOpt_globals.is_pilot_mode) {

          afl->swarm_now = afl->swarm_now + 1;
          if (afl->swarm_now == swarm_num) {

            afl->key_module = 1;
            for (i = 0; i < operator_num; ++i) {

              afl->core_operator_cycles_puppet_v2[i] =
                  afl->core_operator_cycles_puppet[i];
              afl->core_operator_cycles_puppet_v3[i] =
                  afl->core_operator_cycles_puppet[i];
              afl->core_operator_finds_puppet_v2[i] =
                  afl->core_operator_finds_puppet[i];

            }

            double swarm_eff = 0.0;
            afl->swarm_now = 0;
            for (i = 0; i < swarm_num; ++i) {

              if (afl->swarm_fitness[i] > swarm_eff) {

                swarm_eff = afl->swarm_fitness[i];
                afl->swarm_now = i;

              }

            }

            if (afl->swarm_now < 0 || afl->swarm_now > swarm_num - 1) {

              PFATAL("swarm_now error number  %d", afl->swarm_now);

            }

          }                               /* if afl->swarm_now == swarm_num */

          /* adjust pointers dependent on 'afl->swarm_now' */
          afl->mopt_globals_pilot.finds =
              afl->stage_finds_puppet[afl->swarm_now];
          afl->mopt_globals_pilot.finds_v2 =
              afl->stage_finds_puppet_v2[afl->swarm_now];
          afl->mopt_globals_pilot.cycles =
              afl->stage_cycles_puppet[afl->swarm_now];
          afl->mopt_globals_pilot.cycles_v2 =
              afl->stage_cycles_puppet_v2[afl->swarm_now];
          afl->mopt_globals_pilot.cycles_v3 =
              afl->stage_cycles_puppet_v3[afl->swarm_now];

        } else {

          for (i = 0; i < operator_num; i++) {

            afl->core_operator_finds_puppet[i] =
                afl->core_operator_finds_puppet_v2[i];
            afl->core_operator_cycles_puppet[i] =
                afl->core_operator_cycles_puppet_v2[i];

          }

          afl->key_module = 2;

          afl->old_hit_count = new_hit_cnt;

        }                                                  /* if pilot_mode */

      }         /* if (unlikely(*MOpt_globals.pTime > MOpt_globals.period)) */

    }                                                              /* block */

  }                                                                /* block */

  return ret_val;

}

#undef FLIP_BIT

u8 core_fuzzing(afl_state_t *afl) {

  return mopt_common_fuzzing(afl, afl->mopt_globals_core);

}

u8 pilot_fuzzing(afl_state_t *afl) {

  return mopt_common_fuzzing(afl, afl->mopt_globals_pilot);

}

void pso_updating(afl_state_t *afl) {

  afl->g_now++;
  if (afl->g_now > afl->g_max) { afl->g_now = 0; }
  afl->w_now =
      (afl->w_init - afl->w_end) * (afl->g_max - afl->g_now) / (afl->g_max) +
      afl->w_end;
  int tmp_swarm, i, j;
  u64 temp_operator_finds_puppet = 0;
  for (i = 0; i < operator_num; ++i) {

    afl->operator_finds_puppet[i] = afl->core_operator_finds_puppet[i];

    for (j = 0; j < swarm_num; ++j) {

      afl->operator_finds_puppet[i] =
          afl->operator_finds_puppet[i] + afl->stage_finds_puppet[j][i];

    }

    temp_operator_finds_puppet =
        temp_operator_finds_puppet + afl->operator_finds_puppet[i];

  }

  for (i = 0; i < operator_num; ++i) {

    if (afl->operator_finds_puppet[i]) {

      afl->G_best[i] = (double)((double)(afl->operator_finds_puppet[i]) /
                                (double)(temp_operator_finds_puppet));

    }

  }

  for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {

    double x_temp = 0.0;
    for (i = 0; i < operator_num; ++i) {

      afl->probability_now[tmp_swarm][i] = 0.0;
      afl->v_now[tmp_swarm][i] =
          afl->w_now * afl->v_now[tmp_swarm][i] +
          RAND_C * (afl->L_best[tmp_swarm][i] - afl->x_now[tmp_swarm][i]) +
          RAND_C * (afl->G_best[i] - afl->x_now[tmp_swarm][i]);
      afl->x_now[tmp_swarm][i] += afl->v_now[tmp_swarm][i];
      if (afl->x_now[tmp_swarm][i] > v_max) {

        afl->x_now[tmp_swarm][i] = v_max;

      } else if (afl->x_now[tmp_swarm][i] < v_min) {

        afl->x_now[tmp_swarm][i] = v_min;

      }

      x_temp += afl->x_now[tmp_swarm][i];

    }

    for (i = 0; i < operator_num; ++i) {

      afl->x_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i] / x_temp;
      if (likely(i != 0)) {

        afl->probability_now[tmp_swarm][i] =
            afl->probability_now[tmp_swarm][i - 1] + afl->x_now[tmp_swarm][i];

      } else {

        afl->probability_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i];

      }

    }

    if (afl->probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
        afl->probability_now[tmp_swarm][operator_num - 1] > 1.01) {

      FATAL("ERROR probability");

    }

  }

  afl->swarm_now = 0;
  afl->key_module = 0;

}

/* larger change for MOpt implementation: the original fuzz_one was renamed
   to fuzz_one_original. All documentation references to fuzz_one therefore
   mean fuzz_one_original */

u8 fuzz_one(afl_state_t *afl) {

  int key_val_lv_1 = 0;
  int key_val_lv_2 = 0;

#ifdef _AFL_DOCUMENT_MUTATIONS

  u8 path_buf[PATH_MAX];
  if (afl->do_document == 0) {

    snprintf(path_buf, PATH_MAX, "%s/mutations", afl->out_dir);
    afl->do_document = mkdir(path_buf, 0700);  // if it exists we do not care
    afl->do_document = 1;

  } else {

    afl->do_document = 2;
    afl->stop_soon = 2;

  }

#endif // _AFL_DOCUMENT_MUTATIONS

  // if limit_time_sig == -1 then both are run after each other

  /* 5.16 修改，使用http-mutator整合在main中 */
  /*

  if (afl->limit_time_sig <= 0) { key_val_lv_1 = fuzz_one_original(afl); }

  if (afl->limit_time_sig != 0) {

    if (afl->key_module == 0) {

      key_val_lv_2 = pilot_fuzzing(afl);

    } else if (afl->key_module == 1) {

      key_val_lv_2 = core_fuzzing(afl);

    } else if (afl->key_module == 2) {

      pso_updating(afl);

    }

  }
  

  return (key_val_lv_1 | key_val_lv_2);
  */


  if (afl->no_grammar_mode == 0 && afl->last_find_time != 0 && get_cur_time() - afl->last_find_time > 300000 && get_cur_time() - afl->last_type_start_time > 300000 ) {
    afl->favored_seed_type = (afl->favored_seed_type == SEED_TYPE_JSON) ? SEED_TYPE_RAW : SEED_TYPE_JSON;
    afl->last_type_start_time = get_cur_time();
    // FILE* fp = fopen("seed_type.txt", "a+");
    // fprintf(fp, "time: %llu, change to seed_type %s\n", get_cur_time(), afl->favored_seed_type == SEED_TYPE_JSON ? "SEED_TYPE_JSON": "SEED_TYPE_RAW");
    // fclose(fp);
  }

  if(afl->queue_cur->seed_type == SEED_TYPE_JSON)
  {
    key_val_lv_1 = fuzz_one_http(afl); 
  }
  else
  {
    if (afl->limit_time_sig <= 0) { key_val_lv_1 = fuzz_one_original(afl); }

    if (afl->limit_time_sig != 0) {

      if (afl->key_module == 0) {

        key_val_lv_2 = pilot_fuzzing(afl);

      } else if (afl->key_module == 1) {

        key_val_lv_2 = core_fuzzing(afl);

      } else if (afl->key_module == 2) {

        pso_updating(afl);

      }

    }
    

    return (key_val_lv_1 | key_val_lv_2);
  }
  




  return key_val_lv_1;

}

