# $CC -fPIC -shared ./nvram.c ./nvram.h -o ./libnvram_fuzz.so
# $CC -fPIC -shared ./nvram.c ./libnvram_fuzz.h -o ./libnvram_fuzz.so
$CC -fPIC -Wall -shared -o ./libnvram_fuzz.so ./nvram.c ./redqueen.c ./orig_strfunc.c ./libnvram_fuzz.h
