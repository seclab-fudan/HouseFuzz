#export LD_PRELOAD="./libfuzz_nvram.so"
gcc -fPIC -shared -o libnvram_fuzz.so ./nvram.c
#gcc ./test_nvram.c -g -L. -lfuzz_nvram -o ./test_nvram
cp ./libnvram_fuzz.so /lib/
