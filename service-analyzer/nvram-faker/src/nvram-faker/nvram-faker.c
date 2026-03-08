
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <fcntl.h>

#define ASUSWRT

// Function declarations

char * nvram_get(const char * key);
int nvram_set_default_builtin();
int nvram_set_default();
int nvram_set_default_image();
int nvram_clear();
int nvram_close();
int nvram_unset(const char * key);
int nvram_set(const char * key, const char * val);
int nvram_set_int(const char * key, const int val);
int nvram_list_add(const char * key, const char * val);
int nvram_set_default_table(const char * *tbl);
int nvram_reset();
int nvram_list_exist(const char * key, const char * val, int magic);
int nvram_list_del(const char * key, const char * val);
int nvram_get_int(const char * key);
int nvram_getall(char * buf, size_t len);
int nvram_get_buf(const char * key, char * buf, size_t len);
int nvram_match(const char * key, const char * val);
int nvram_invmatch(const char * key, const char * val);
int nvram_read(const char * key, char * buf, size_t sz);
char * nvram_safe_get(const char * key);
int nvram_get_state(const char * key);
int nvram_init();
int nvram_load();
int nvram_commit();
int nvram_restore(char * path);
int nvram_backup(char * path);
int nvram_get_nvramspace();
int foreach_nvram_from(const char * file, void (*fp)(const char * , const char * , void *), void *data);
char * nvram_nget(const char * fmt, ...);
int nvram_nset(const char * val, const char * fmt, ...);
int nvram_nset_int(const int val, const char * fmt, ...);
int nvram_nmatch(const char * val, const char * fmt, ...);
char * nvram_default_get(const char * key, const char * val);
int nvram_flag_set(int unk);
int nvram_flag_reset(int unk);
int nvram_master_init();
int nvram_slave_init();
int nvram_getall_adv(int unk, char * buf, size_t len);
char * nvram_get_adv(int unk, const char * key);
int nvram_set_adv(int unk, const char * key, const char * val);
int nvram_commit_adv();
int nvram_unlock_adv();
int nvram_lock_adv();
int nvram_check();
int nvram_state(int unk1, void *unk2, void *unk3);
int nvram_getf(const char * key, char * fmt, ...);
int nvram_setf(const char * key, const char * fmt, ...);
char * nvram_bufget(int idx, const char * key);
int nvram_bufset(int idx, const char * key, const char * val);

char * artblock_get(const char * key);
char * artblock_fast_get(const char * key);
char * artblock_safe_get(const char * key);
int artblock_set(const char * key, const char * val);

int apmib_init();
int apmib_reinit();
int apmib_update(const int key);
int apmib_get(const int key, void *buf);
int apmib_set(const int key, void *val);

int WAN_ith_CONFIG_GET(char * buf, const char * fmt, ...);
int WAN_ith_CONFIG_SET_AS_STR(const char * val, const char * fmt, ...);
int WAN_ith_CONFIG_SET_AS_INT(const int val, const char * fmt, ...);

int acos_nvram_init();
char * acos_nvram_get(const char * key);
int acos_nvram_read(const char * key, char * buf, size_t sz);
int acos_nvram_set(const char * key, const char * val);
int acos_nvram_loaddefault();
int acos_nvram_unset(const char * key);
int acos_nvram_commit();
int acosNvramConfig_init(char * mount);
char * acosNvramConfig_exist(const char * key);
char * acosNvramConfig_get(const char * key);
int acosNvramConfig_read(const char * key, char * buf, size_t sz);
int acosNvramConfig_set(const char * key, const char * val);
int acosNvramConfig_write(const char * key, const char * val);
int acosNvramConfig_unset(const char * key);
int acosNvramConfig_match(const char * key, const char * val);
int acosNvramConfig_invmatch(const char * key, const char * val);
int acosNvramConfig_save();
int acosNvramConfig_save_config();
int acosNvramConfig_loadFactoryDefault(const char * key);
int acosNvramConfig_readAsInt(char * k, int *r);
int acosNvramConfig_writeAsInt(char * k, int *r);

int envram_commit();
int envram_default();
int envram_load();
int envram_safe_load();
int envram_match(const char * key, const char * val);
int envram_get(const char * key, char * buf);
int envram_get_func(const char * key, char * buf);
int envram_getf(const char * key, const char * fmt, ...);
int envram_set(const char * key, const char * val);
int envram_set_func(const char * key, const char * val);
int envram_setf(const char * key, const char * fmt, ...);
int envram_unset(const char * key);

int isspace(int c);
char * rstrip(char * s);
char * lskip(const char * s);
char * find_char_or_comment(const char * s, unsigned char c);
char * strncpy0(char * dest, const char * src, size_t size);
char * replace_char(char * key, unsigned char oldchar, unsigned char newchar);
void dump_key(const char * key);
char * read_key(const char * key);
int write_key(const char * key, const char * val);


int ini_parse_file(FILE *file, int (*handler)(void *, const char * , const char * , const char * ), void *user);
int ini_parse(const char * filename, int (*handler)(void *, const char * , const char * , const char * ), void *user);

// Data declarations

unsigned char temp[512];


char * replace_char(char * key, unsigned char oldchar, unsigned char newchar)
{
  char *ptr; 

  for ( ptr = strchr((const char *)key, oldchar); ptr; ptr = strchr(ptr, oldchar) )
    *ptr = newchar;
  return key;
}

void dump_key(const char * key)
{
  FILE *fp; 

  fp = fopen("/MISSING_NVRAMS", "a+");
  if ( fp )
  {
    fprintf(fp, "%s\n", (const char *)key);
    fclose(fp);
  }
}

char * read_key(const char * key)
{
  unsigned char TMP[257]; 
  unsigned char KEY_PATH[513]; 
  unsigned char value[2049]; 
  size_t bufsize; 
  FILE *fp; 

  if ( key )
  {
    memset(TMP, 0, sizeof(TMP));
    memset(KEY_PATH, 0, sizeof(KEY_PATH));
    snprintf((char *)TMP, 0x100u, "%s", (const char *)key);
    replace_char(TMP, 0x2Fu, 0x5Fu);
    snprintf((char *)KEY_PATH, 0x200u, "%s/%s", "/gh_nvram", (const char *)TMP);
    fflush((FILE *)stdout);
    if ( access((const char *)KEY_PATH, 0) )
    {
      fprintf((FILE *)stderr, "\x1B[22;31m%s=Unknown\n\x1B[22;00m", (const char *)key);
      dump_key(key);
      fflush((FILE *)stderr);
    }
    fp = fopen((const char *)KEY_PATH, "r");
    if ( fp )
    {
      memset(value, 0, sizeof(value));
      bufsize = fread(value, 1u, 0x800u, fp);
      fclose(fp);
      if ( bufsize )
        return (char * )strdup((const char *)value);
      else
        return "";
    }
    else
    {
      return "";
    }
  }
  else
  {
    fwrite("[nvram-faker] NULL argument\n", 1u, 0x1Cu, (FILE *)stderr);
    return "";
  }
}

int write_key(const char * key, const char * val)
{
  unsigned char TMP[256]; 
  unsigned char KEY_PATH[512]; 
  FILE *fp; 

  if ( !key || !*key )
    return 0;
  memset(TMP, 0, sizeof(TMP));
  memset(KEY_PATH, 0, sizeof(KEY_PATH));
  snprintf((char *)TMP, 0x100u, "%s", (const char *)key);
  replace_char(TMP, 0x2Fu, 0x5Fu);
  snprintf((char *)KEY_PATH, 0x200u, "%s/%s", "/gh_nvram", (const char *)TMP);
  fp = fopen((const char *)KEY_PATH, "w+");
  if ( !fp )
    return 0;
  fputs((const char *)val, fp);
  fclose(fp);
  if ( access("/gh_nvram.ini", 0) )
    fp = fopen("/gh_nvram.ini", "w");
  else
    fp = fopen("/gh_nvram.ini", "a");
  fprintf(fp, "%s\n", (const char *)KEY_PATH);
  fclose(fp);
  return 1;
}

char * nvram_get(const char * key)
{
  if ( access("/gh_nvram", 0) )
    return 0;
  else
    return read_key(key);
}

int nvram_set_default_builtin()
{
  return 1;
}

int nvram_set_default()
{
  return nvram_set_default_builtin();
}

int nvram_set_default_image()
{
  return nvram_set_default_builtin();
}

int nvram_clear()
{
  char * v0; // r4
  char * key; 
  unsigned char KEYBUF[512]; 
  size_t len; 
  size_t size; 
  FILE *fp; 

  len = 0;
  key = KEYBUF;
  if ( !access("/gh_nvram.ini", 0) )
  {
    fp = fopen("/gh_nvram.ini", "r");
    while ( 1 )
    {
      size = getline(&key, &len, fp);
      if ( size == -1 )
        break;
      v0 = key;
      v0[strcspn((const char *)key, "\n")] = 0;
      if ( !access((const char *)key, 0) )
        remove((const char *)key);
    }
    fclose(fp);
  }
  return 1;
}
// 1B7C: using guessed type int __fastcall getline(_DWORD, _DWORD, _DWORD);

int nvram_close()
{
  return 1;
}

int nvram_unset(const char * key)
{
  unsigned char KEY_PATH[512]; 

  if ( access("/gh_nvram", 0) )
    return 0;
  if ( !key || !*key )
    return 0;
  snprintf((char *)KEY_PATH, 0x200u, "%s/%s", "/gh_nvram", (const char *)key);
  return !access((const char *)KEY_PATH, 0) && write_key(KEY_PATH, "") != 0;
}
// 4048: using guessed type unsigned char byte_4048[4];

int nvram_set(const char * key, const char * val)
{
  if ( access("/gh_nvram", 0) )
    return 0;
  else
    return write_key(key, val);
}

int nvram_set_int(const char * key, const int val)
{
  unsigned char charval[512]; 

  snprintf((char *)charval, 0x200u, "%d", val);
  return nvram_set(key, charval);
}

int nvram_list_add(const char * key, const char * val)
{
  return nvram_set(key, val);
}

int nvram_set_default_table(const char * *tbl)
{
  int v1; // r3
  size_t i; 

  for ( i = 0; tbl[i]; i += v1 )
  {
    nvram_set(tbl[i], tbl[i + 1]);
    if ( !tbl[i + 2] || tbl[i + 2] == 1 )
      v1 = 3;
    else
      v1 = 2;
  }
  return 1;
}
// 0: using guessed type int dword_0;

int nvram_reset()
{
  if ( nvram_clear() == 1 )
    return nvram_set_default();
  else
    return 0;
}

int nvram_list_exist(const char * key, const char * val, int magic)
{
  return 1;
}
// 0: using guessed type int dword_0;

int nvram_list_del(const char * key, const char * val)
{
  return 1;
}

int nvram_get_int(const char * key)
{
  char * ret; 

  ret = nvram_get(key);
  return atoi((const char *)ret);
}

int nvram_getall(char * buf, size_t len)
{
  char * v3; // r4
  char * key; 
  unsigned char KEYVALBUF[3072]; 
  unsigned char KEYBUF[512]; 
  size_t size; 
  char * value; 
  size_t read; 
  FILE *fp; 
  size_t keyvallen; 
  size_t offset; 

  offset = 0;
  keyvallen = 0;
  key = KEYBUF;
  if ( !buf || !len )
    return 0;
  if ( !access("/gh_nvram.ini", 0) )
  {
    fp = fopen("/gh_nvram.ini", "r");
    while ( 1 )
    {
      read = getline(&key, &size, fp);
      if ( read == -1 )
        break;
      v3 = key;
      v3[strcspn((const char *)key, "\n")] = 0;
      if ( !access((const char *)key, 0) )
      {
        value = read_key(key);
        memset(KEYVALBUF, 0, sizeof(KEYVALBUF));
        snprintf((char *)KEYVALBUF, 0xC00u, "%s=%s", (const char *)key, (const char *)value);
        keyvallen = strlen((const char *)KEYVALBUF);
        if ( len < offset + keyvallen )
          return 0;
        memcpy(&buf[offset], KEYVALBUF, keyvallen);
        offset += len;
        buf[offset++] = 0;
      }
    }
    fclose(fp);
  }
  return 1;
}
// 1B7C: using guessed type int __fastcall getline(_DWORD, _DWORD, _DWORD);

int nvram_get_buf(const char * key, char * buf, size_t len)
{
  char * val; 

  if ( !buf || !len )
    return 0;
  val = nvram_get(key);
  *buf = 0;
  memcpy(buf, val, len);
  return 1;
}

int nvram_match(const char * key, const char * val)
{
  int v2; // r3
  size_t v3; // r4
  size_t v4; // r0
  char * result; 

  result = nvram_get(key);
  if ( !result )
    return 0;
  v3 = strlen((const char *)val);
  v2 = 0;
  if ( v3 == strlen((const char *)result) )
  {
    v4 = strlen((const char *)val);
    if ( !strncmp((const char *)result, (const char *)val, v4) )
      return 1;
  }
  return v2;
}

int nvram_invmatch(const char * key, const char * val)
{
  return nvram_match(key, val) == 0;
}

int nvram_read(const char * key, char * buf, size_t sz)
{
  char * result; 

  if ( !buf )
    return 0;
  result = nvram_get(key);
  if ( !result )
    return 0;
  strncpy((char *)buf, (const char *)result, sz);
  return 1;
}

char * nvram_safe_get(const char * key)
{
  return nvram_get(key);
}

int nvram_get_state(const char * key)
{
  return nvram_get_int(key);
}

int nvram_init()
{
  initialize_ini();
  return 0;
}

int nvram_load()
{
  initialize_ini();
  return 0;
}

int nvram_commit()
{
  return 1;
}

int nvram_restore(char * path)
{
  return strlen((const char *)path);
}

int nvram_backup(char * path)
{
  return strlen((const char *)path);
}

int nvram_get_nvramspace()
{
  return 2048;
}

int foreach_nvram_from(
        const char * file,
        void (*fp)(const char * , const char * , void *),
        void *data)
{
  char * tmp; 
  char * val; 
  char * vala; 
  FILE *f; 

  if ( !fp )
    return 0;
  f = fopen((const char *)file, "r");
  if ( !f )
    return 0;
  memset(temp, 0, sizeof(temp));
  while ( fgets((char *)temp, 512, f) == (char *)temp )
  {
    val = (char * )strchr((const char *)temp, 61);
    if ( val )
    {
      *val = 0;
      vala = val + 1;
      tmp = (char * )strchr((const char *)vala, 10);
      if ( tmp )
        *tmp = 0;
      if ( data )
        fp(temp, vala, data);
      else
        fp(temp, vala, NULL);
    }
  }
  fclose(f);
  return 1;
}

char * nvram_nget(const char * fmt, ...)
{
  va_list varg_r1; 

  va_start(varg_r1, fmt);
  memset(temp, 0, sizeof(temp));
  vsnprintf((char *)temp, 0x200u, (const char *)fmt, varg_r1);
  return nvram_get(temp);
}

int nvram_nset(const char * val, const char * fmt, ...)
{
  va_list varg_r2; 

  va_start(varg_r2, fmt);
  memset(temp, 0, sizeof(temp));
  vsnprintf((char *)temp, 0x200u, (const char *)fmt, varg_r2);
  return nvram_set(temp, val);
}

int nvram_nset_int(const int val, const char * fmt, ...)
{
  return 1;
}

int nvram_nmatch(const char * val, const char * fmt, ...)
{
  va_list varg_r2; 

  va_start(varg_r2, fmt);
  memset(temp, 0, sizeof(temp));
  vsnprintf((char *)temp, 0x200u, (const char *)fmt, varg_r2);
  return nvram_match(temp, val);
}

char * nvram_default_get(const char * key, const char * val)
{
  char * ret; 

  ret = nvram_get(key);
  if ( ret )
    return ret;
  if ( val && nvram_set(key, val) )
    return nvram_get(key);
  return 0;
}

char * artblock_get(const char * key)
{
  return nvram_get(key);
}

char * artblock_fast_get(const char * key)
{
  return nvram_get(key);
}

char * artblock_safe_get(const char * key)
{
  return nvram_get(key);
}

int artblock_set(const char * key, const char * val)
{
  return 1;
}

int nvram_flag_set(int unk)
{
  return 1;
}

int nvram_flag_reset(int unk)
{
  return 1;
}

int nvram_master_init()
{
  return 0;
}

int nvram_slave_init()
{
  return 0;
}

int apmib_init()
{
  initialize_ini();
  return 1;
}

int apmib_reinit()
{
  initialize_ini();
  return 1;
}

int apmib_update(const int key)
{
  return 1;
}

int apmib_get(const int key, void *buf)
{
  char * res; 

  memset(temp, 0, sizeof(temp));
  snprintf((char *)temp, 0x200u, "%d", key);
  res = nvram_get(temp);
  if ( res )
    snprintf((char *)buf, 0x200u, "%s", (const char *)res);
  return 1;
}

int apmib_set(const int key, void *val)
{
  memset(temp, 0, sizeof(temp));
  snprintf((char *)temp, 0x200u, "%d", key);
  return nvram_set(temp, (const char * )val);
}

int WAN_ith_CONFIG_GET(char * buf, const char * fmt, ...)
{
  va_list varg_r2; 

  va_start(varg_r2, fmt);
  vsnprintf((char *)temp, 0x200u, (const char *)fmt, varg_r2);
  return nvram_read(temp, buf, 0x40u);
}

int WAN_ith_CONFIG_SET_AS_STR(const char * val, const char * fmt, ...)
{
  return nvram_nset(val, fmt);
}

int WAN_ith_CONFIG_SET_AS_INT(const int val, const char * fmt, ...)
{
  return nvram_nset_int(val, fmt);
}

int acos_nvram_init()
{
  return nvram_init();
}

char * acos_nvram_get(const char * key)
{
  return nvram_get(key);
}

int acos_nvram_read(const char * key, char * buf, size_t sz)
{
  return nvram_read(key, buf, sz);
}

int acos_nvram_set(const char * key, const char * val)
{
  return nvram_set(key, val);
}

int acos_nvram_loaddefault()
{
  return 1;
}

int acos_nvram_unset(const char * key)
{
  return nvram_unset(key);
}

int acos_nvram_commit()
{
  return 1;
}

int acosNvramConfig_init(char * mount)
{
  return nvram_init();
}

char * acosNvramConfig_exist(const char * key)
{
  return nvram_get(key);
}

char * acosNvramConfig_get(const char * key)
{
  return nvram_get(key);
}

int acosNvramConfig_read(const char * key, char * buf, size_t sz)
{
  return nvram_read(key, buf, sz);
}

int acosNvramConfig_set(const char * key, const char * val)
{
  return nvram_set(key, val);
}

int acosNvramConfig_write(const char * key, const char * val)
{
  return nvram_set(key, val);
}

int acosNvramConfig_unset(const char * key)
{
  return nvram_unset(key);
}

int acosNvramConfig_match(const char * key, const char * val)
{
  return nvram_match(key, val);
}

int acosNvramConfig_invmatch(const char * key, const char * val)
{
  return nvram_match(key, val) == 0;
}

int acosNvramConfig_save()
{
  return 1;
}

int acosNvramConfig_save_config()
{
  return 1;
}

int acosNvramConfig_loadFactoryDefault(const char * key)
{
  return 1;
}

int nvram_getall_adv(int unk, char * buf, size_t len)
{
  return nvram_getall(buf, len) != 1;
}

char * nvram_get_adv(int unk, const char * key)
{
  return nvram_get(key);
}

int nvram_set_adv(int unk, const char * key, const char * val)
{
  return nvram_set(key, val);
}

int nvram_commit_adv()
{
  return 1;
}

int nvram_unlock_adv()
{
  return 1;
}

int nvram_lock_adv()
{
  return 1;
}

int nvram_check()
{
  return 1;
}

int nvram_state(int unk1, void *unk2, void *unk3)
{
  return 0;
}

int envram_commit()
{
  return 0;
}

int envram_default()
{
  return 0;
}

int envram_load()
{
  return nvram_init() == 0;
}

int envram_safe_load()
{
  return nvram_init() == 0;
}

int envram_match(const char * key, const char * val)
{
  return nvram_match(key, val) == 0;
}

int envram_get(const char * key, char * buf)
{
  return nvram_read(key, buf, 0x40u) == 0;
}

int envram_get_func(const char * key, char * buf)
{
  return envram_get(key, buf);
}

int envram_getf(const char * key, const char * fmt, ...)
{
  char * val; 
  va_list varg_r2; 

  va_start(varg_r2, fmt);
  val = nvram_get(key);
  if ( !val )
    return 0;
  vsscanf(val, fmt, varg_r2);
  free(val);
  return 1;
}

int nvram_getf(const char * key, char * fmt, ...)
{
  return envram_get(key, fmt);
}

int envram_set(const char * key, const char * val)
{
  return nvram_set(key, val) == 0;
}

int envram_set_func(const char * key, const char * val)
{
  return envram_set(key, val);
}

int envram_setf(const char * key, const char * fmt, ...)
{
  va_list varg_r2; 

  va_start(varg_r2, fmt);
  vsnprintf((char *)temp, 0x200u, (const char *)fmt, varg_r2);
  return nvram_set(key, temp) == 0;
}

int nvram_setf(const char * key, const char * fmt, ...)
{
  return envram_setf(key, fmt);
}

int envram_unset(const char * key)
{
  return 0;
}

int acosNvramConfig_readAsInt(char * k, int *r)
{
  return 0;
}

int acosNvramConfig_writeAsInt(char * k, int *r)
{
  return 0;
}

char * nvram_bufget(int idx, const char * key)
{
  return nvram_safe_get(key);
}

int nvram_bufset(int idx, const char * key, const char * val)
{
  return nvram_set(key, val);
}

int isspace(int c)
{
  return c == 32 || c == 10 || c == 9;
}

char * rstrip(char * s)
{
  char * p; 

  for ( p = &s[strlen((const char *)s)]; p > s; *p = 0 )
  {
    if ( !isspace(*--p) )
      break;
  }
  return s;
}

char * lskip(const char * s)
{
  while ( *s && isspace(*s) )
    ++s;
  return (char * )s;
}

char * find_char_or_comment(const char * s, unsigned char c)
{
  int was_whitespace; 

  for ( was_whitespace = 0; *s && c != *s && (!was_whitespace || *s != 59); was_whitespace = isspace(*s++) )
    ;
  return (char * )s;
}

char * strncpy0(char * dest, const char * src, size_t size)
{
  strncpy((char *)dest, (const char *)src, size);
  dest[size - 1] = 0;
  return dest;
}

int ini_parse_file(
        FILE *file,
        int (*handler)(void *, const char * , const char * , const char * ),
        void *user)
{
  char * v4; // r0
  unsigned char prev_name[50]; 
  unsigned char section[50]; 
  char * value; 
  char * name; 
  char * line; 
  int error; 
  int lineno; 
  char * end; 
  char * start; 

  memset(section, 0, sizeof(section));
  memset(prev_name, 0, sizeof(prev_name));
  lineno = 0;
  error = 0;
  line = (char * )malloc(0x7D0u);
  if ( !line )
    return -2;
  while ( fgets((char *)line, 2000, file) )
  {
    ++lineno;
    start = line;
    if ( lineno == 1 && *start == 239 && start[1] == 187 && start[2] == 191 )
      start += 3;
    v4 = rstrip(start);
    start = lskip(v4);
    if ( *start != 59 && *start != 35 )
    {
      if ( prev_name[0] && *start && start > line )
      {
        if ( !handler(user, section, prev_name, start) && !error )
          error = lineno;
      }
      else if ( *start == 91 )
      {
        end = find_char_or_comment(start + 1, 0x5Du);
        if ( *end == 93 )
        {
          *end = 0;
          strncpy0(section, start + 1, 0x32u);
          prev_name[0] = 0;
        }
        else if ( !error )
        {
          error = lineno;
        }
      }
      else if ( *start && *start != 59 )
      {
        end = find_char_or_comment(start, 0x3Du);
        if ( *end != 61 )
          end = find_char_or_comment(start, 0x3Au);
        if ( *end == 61 || *end == 58 )
        {
          *end = 0;
          name = rstrip(start);
          value = lskip(end + 1);
          end = find_char_or_comment(value, 0);
          if ( *end == 59 )
            *end = 0;
          rstrip(value);
          strncpy0(prev_name, name, 0x32u);
          if ( !handler(user, section, name, value) && !error )
            error = lineno;
        }
        else if ( !error )
        {
          error = lineno;
        }
      }
    }
  }
  free(line);
  return error;
}

int ini_parse(
        const char * filename,
        int (*handler)(void *, const char * , const char * , const char * ),
        void *user)
{
  int error; 
  FILE *file; 

  file = fopen((const char *)filename, "r");
  if ( !file )
    return -1;
  error = ini_parse_file(file, handler, user);
  fclose(file);
  return error;
}


// asuswrt-merlin

#ifdef ASUSWRT
char * jffs_nvram_get(const char *name);
int jffs_nvram_set(const char *name, const char *value);
int jffs_nvram_unset(const char *name);
int large_nvram(const char *name);
void jffs_nvram_init();
int jffs_nvram_getall(int len_nvram, char *buf, int count);
char *var_nvram_get(const char *name);
int var_nvram_set(const char *name, const char *value);
int var_nvram_unset(const char *name);
int is_var_nvram(const char *name);
void var_nvram_init();
int var_nvram_getall(char *buf, size_t n);

char *nvram_get_r(const char *name, char *buf, size_t buflen);
char *nvram_pf_get(const char *prefix, const char *name);
int nvram_pf_set(const char *prefix, const char *name, const char *value);
int nvram_get_int(const char *key);
int nvram_pf_get_int(const char *prefix, const char *key);
int nvram_set_int(const char *key, int value);
int nvram_pf_set_int(const char *prefix, const char *key, int value);
int nvram_pf_match(char *prefix, char *name, char *match);
int nvram_pf_invmatch(char *prefix, char *name, char *invmatch);
double nvram_get_double(const char *key);
int nvram_set_double(const char *key, double value);
int nvram_get_hex(const char *key);
int nvram_set_hex(const char *key, int value);
int nvram_valid_get_int(const char *key, int min, int max, int def);
char *nvram_split_get(const char *key, char *buffer, int maxlen, int maxinst);
int nvram_split_set(const char *key, char *value, int size, int maxinst);

int set_enc_nvram(char *name, char *input, char *output);
int enc_nvram(char *name, char *input, char *output);
int dec_nvram(char *name, char *input, char *output);
int start_enc_nvram(void);
int init_enc_nvram(void);
int invalid_nvram_get_name(char *name);
int invalid_nvram_get_program(char *name);
int invalid_program_check(void);

char tmpbuf[0x4000];

int enc_nvram(char *name, char *input, char *output) {
  strlcpy(output, input, 4096);
  return 1;
}

int dec_nvram(char *name, char *input, char *output) {
  strlcpy(output, input, 4096);
  return 1;
}

char *nvram_get_r(const char *name, char *buf, size_t buflen)
{
	char *v = nvram_get(name);

	if (v && buf) {
		strlcpy(buf, v, buflen);
		return buf;
	}

	return v;
}

char *nvram_pf_get(const char *prefix, const char *name)
{
	char tmp[128], *t = tmp, *v;
	size_t size;

	if (!prefix || !name || *name == '\0')
		return NULL;

	size = strlen(prefix) + strlen(name) + 1;
	if (size > sizeof(tmp)) {
		t = malloc(size);
		if (!t)
			return NULL;
	}

	v = nvram_get(strlcat_r(prefix, name, tmp, sizeof(tmp)));

	if (t != tmp)
		free(t);

	return v;
}

int nvram_pf_set(const char *prefix, const char *name, const char *value)
{
	char tmp[128], *t = tmp;
	size_t size;
	int r;

	if (!prefix || !name || *name == '\0')
		return -EINVAL;

	size = strlen(prefix) + strlen(name) + 1;
	if (size > sizeof(tmp)) {
		t = malloc(size);
		if (!t)
			return -ENOMEM;
	}

	r = nvram_set(strlcat_r(prefix, name, tmp, sizeof(tmp)), value);

	if (t != tmp)
		free(t);

	return r;
}

int nvram_pf_get_int(const char *prefix, const char *key)
{
	return atoi(nvram_pf_safe_get(prefix, key));
}

int nvram_pf_set_int(const char *prefix, const char *key, int value)
{
	char nvramstr[16];

	snprintf(nvramstr, sizeof(nvramstr), "%d", value);
	return nvram_pf_set(prefix, key, nvramstr);
}

int nvram_pf_match(char *prefix, char *name, char *match)
{
	const char *value = nvram_pf_get(prefix, name);
	return (value && !strcmp(value, match));
}

int nvram_pf_invmatch(char *prefix, char *name, char *invmatch)
{
	const char *value = nvram_pf_get(prefix, name);
	return (value && strcmp(value, invmatch));
}

double nvram_get_double(const char *key)
{
	return atof(nvram_safe_get(key));
}

int nvram_set_double(const char *key, double value)
{
	char nvramstr[33];

	snprintf(nvramstr, sizeof(nvramstr), "%.9g", value);
	return nvram_set(key, nvramstr);
}

int nvram_get_hex(const char *key)
{
	return strtol(nvram_safe_get(key), NULL, 16);
}

int nvram_set_hex(const char *key, int value)
{
	char nvramstr[16];

	snprintf(nvramstr, sizeof(nvramstr), "%x", value);
	return nvram_set(key, nvramstr);
}

int nvram_valid_get_int(const char *key, int min, int max, int def)
{
	int ret = nvram_get_int(key);
	return (min <= ret && ret <= max) ? ret : def;
}

char *nvram_split_get(const char *key, char *buffer, int maxlen, int maxinst)
{
	char nvname[64];
	int i;

	strlcpy(buffer, nvram_safe_get(key), maxlen);

	for (i=1; i <= maxinst; ++i) {
		snprintf(nvname, sizeof (nvname), "%s%d", key, i);
		strlcat(buffer, nvram_safe_get(nvname), maxlen);
	}

	return buffer;
}

int nvram_split_set(const char *key, char *value, int size, int maxinst)
{
	char nvname[64];
	char *piece, *ptr;
	int valuelen, i;

	piece = malloc(size + 1);
	if (piece == NULL)
		return -1;
	piece[size] = '\0';

	valuelen = strlen(value);
	ptr = value;

	strncpy(piece, ptr, size);
	nvram_set(key, piece);
	ptr += size;

	if (valuelen <= size) {
		free(piece);
		return 1;
	}

	for (i=1; i <= maxinst; ++i) {
		strncpy(piece, ptr, size);

		snprintf(nvname, sizeof (nvname), "%s%d", key, i);
		nvram_set(nvname, piece);

		ptr += size;
		if (ptr >= value + valuelen) {
			free(piece);
			return i;
		}
	}

	free(piece);

	return i;
}

#endif // ASUSWRT