#!/bin/bash

#set -x

ps="sec0w"

while [[ 1 ]]; do
    line=`adb shell ps | grep $ps`
    if [[ $? == "0" ]]; then
        pid=`echo "$line" | awk '{print $2}'`
        echo "$ps pid is $pid"
        break
    fi
    sleep 0.05
done

adb shell strace -p $pid

ps="dirtyc0w"

while [[ 1 ]]; do
    line=`adb shell ps | grep $ps`
    if [[ $? == "0" ]]; then
        pid=`echo "$line" | awk '{print $2}'`
        echo "$ps pid is $pid"
        break
    fi
    sleep 0.05
done

adb shell strace -p $pid
