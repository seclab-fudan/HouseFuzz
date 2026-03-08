#!/bin/bash

STRACE_ARGS="-D /ghqemu/QEMU_LOG_%d -strace"
TRACE_ARGS="-trace translate_block"
HACK_ARGS="-hackbind -hackproc -hacksysinfo -hackhouse"

QEMU_ARGS="$HACK_ARGS $STRACE_ARGS $TRACE_ARGS"
# Fine-grained recording for the first 100 PIDs
# if [ $$ -lt 500 ]; then
CHILD_QEMU_ARGS="$QEMU_ARGS"
# else
#     CHILD_QEMU_ARGS="$HACK_ARGS $STRACE_ARGS"
# fi

# QEMU_ARGS="-hackbind -hackproc -hacksysinfo -hackhouse"
ENVS="-E LD_PRELOAD=libnvram-faker.so -E PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

QEMU=/qemu-wrapper
CHROOT=/fs

# START_PID=${START_PID:-$(cat /proc/sys/kernel/ns_last_pid)}
# START_PID=${START_PID:-0}
# echo $START_PID > /proc/sys/kernel/ns_last_pid

mkdir -p $CHROOT/ghqemu

if [ -z $CHROOT ]; then
    exec $QEMU $QEMU_ARGS \
        -execve "$QEMU $CHILD_QEMU_ARGS " \
        $ENVS \
        "$@"
else
    exec chroot $CHROOT \
        $QEMU $QEMU_ARGS \
        -execve "$QEMU $CHILD_QEMU_ARGS " \
        $ENVS \
        "$@"
fi