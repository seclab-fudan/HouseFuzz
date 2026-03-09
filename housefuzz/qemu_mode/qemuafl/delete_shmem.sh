for id in `ipcs -m | grep "^0x" | cut -d " " -f2`
do
    ipcrm -m $id
done
