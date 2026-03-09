#!/bin/bash
rm /redqueen_lock
rm /redqueen_shmem
for id in `ipcs -m | grep 0x | awk '{print $2}'`
do
    ipcrm -m $id
done
