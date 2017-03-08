#!/bin/bash

#set -x

function strace_ps() {
	local ps="$1"

	while [[ 1 ]]; do
		line=`adb shell ps | grep $ps`
		if [[ $? == "0" ]]; then
			local pid=`echo "$line" | awk '{print $2}'`
			echo "$ps pid is $pid"
			break
		fi
		#sleep 0.05
	done
	adb shell strace -v -f -p $pid
}

adb root
adb remount
adb push strace /system/bin/ 
adb shell setenforce 0

strace_ps "logd" > logd.log &
strace_ps "krmain" > krmain.log &
strace_ps "sec0w64" > sec0w64.log & 
strace_ps "dirtyc0w64" > dirtyc0w64.log &

sleep 100