1.下载kingroot，root手机成功

2.重新刷机，在破解过程中提取ps输出的log，查看破解过程中都有哪些进程执行了。详细间ps.log

3.分析ps.log，可知，kingroot会启动后台进程，此时没有root，直到用户点击root手机后，才开始尝试root
```
    com.kingroot.kinguser(pid 8540, ppid zygote)
    com.kingroot.kinguser:service(pid 6450, ppid zygote)
    krs_100213(pid xxx, ppid 1， 多个进程)
    /data/user/0/com.kingroot.kinguser/applib/ktools(pid 6696, ppid 1)
```

4.尝试root时，会从云端直接拉下来一堆二进制文件，放在/data/data/com.kingroot.kinguser下面，然后顺序启动下面的进程，详细间ps.log
```
   krmain(pid 9876, ppid 8540, 就是com.kingroot.kinguser)
   sec0w64(pid 9978, ppid 9960, 就是krs_100213中的一个)
   dirtyc0w64(pid 10015, ppid同样是9960)
   kd(pid 10805, ppid 10150,就是dirtyc0w64)
   su_check
```

5.其中，在dirtyc0w结束时，就成功启动了一个root的sh(pid 10028, ppid 1)，这个，已经被应用root成功了。

6.然后这个sh就拉起很多很多东西：比如
```
root      10028 1     10440  1020  0022b680 7c8eb1c8 S /system/bin/sh
root      10069 10028 1760   248   0023b6b4 0004931c S /dev/_krpr
root      10132 10069 1772   240   002cd688 0004060c S /dev/_krpr
root      10149 10132 10512  760   0022b680 89eab1c8 S /system/bin/sh
root      10150 10149 10512  1188  0022b680 781811c8 S /system/bin/sh
root      10398 10150 1580   248   0023b6b4 00081fac S krdemv1068
root      10459 10398 1580   104   0023b6b4 00081fac S krdemv1068
root      10460 10459 1580   536   00000000 0002baec R krdemv1068
root      10791 1     6072   356   ffffffff 00072144 S kr_worker/61:0
```

7.上面之后，就多出一个kr_worker的内核线程了，这个内核线程可以乱开东西。

8.继续分析ps.log，sec0w64执行过程中，logd无故退出过一次， 在dirtyc0w64 root成功过程中，又杀了一次， pid变化 326 10004 10090
```
logd      326   1     20220  3136  ffffffff 833751c8 S /system/bin/logd
logd      10004 1     19200  1556  ffffffff 83bf0524 R /system/bin/logd
logd      10090 1     20224  1552  ffffffff 838a51c8 S /system/bin/logd

```


到此，严重怀疑本次root利用了logd相关的漏洞。
===========================================================================

9.本来想静态分析的，发现很困难。dirtyc0w等应用符号表拿掉了，而且加了壳，看不清真实的入口。OK，反正我们是手机厂商，内核随便编译，采用动态分析法。

10.首先想到的是strace跟踪它的所有系统调用，但是由于root的过程非常快，手动敲键盘完全跟不上，所以写简本监控程序，见trace.sh

11.刷了一个user root的版本，把strace丢进去，然后在host端执行脚本监控，重新root手机，得到一堆trace.log。

12.使用logd过滤得到的trace.log，发现破解的核心系统调用
```
socket(PF_LOCAL, SOCK_SEQPACKET, 0)     = 3
connect(3, {sa_family=AF_LOCAL, sun_path="/dev/socket/logdr"}, 110) = 0
write(3, "dumpAndClose start=x\0/proc\0/proc"..., 50) = 50
close(3)                                = 0
openat(AT_FDCWD, "/proc/self/attr/current", O_RDONLY) = 3
read(3, "u:r:untrusted_app:s0\0", 24)   = 21
nanosleep({1, 0}, 0x7ff392c060)         = 0
```
这里得到关键字符串"/dev/socket/logdr"还有"dumpAndClose"，去源代码中搜索对应的字符串
```
$ ag dumpAndClose
core/liblog/log_read.c:601:52:               (logger_list->mode & O_NONBLOCK) ? "dumpAndClose" : "stream");
core/logd/LogReader.cpp:94:26:    if (strncmp(buffer, "dumpAndClose", 12) == 0) {
core/logd/tests/logd_test.cpp:454:36:        static const char ask[] = "dumpAndClose lids=0,1,2,3";

$ ag logdr
core/liblog/log_read.c:590:41:        int sock = socket_local_client("logdr",
core/rootdir/init.rc:518:12:    socket logdr seqpacket 0666 logd logd
core/logd/LogReader.cpp:181:39:    static const char socketName[] = "logdr";
core/logd/main.cpp:176:41:    // LogReader listens on /dev/socket/logdr. When a client
core/logd/tests/logd_test.cpp:443:35:    int fd = socket_local_client("logdr",
extras/tests/fstest/perm_checker.conf:103:13:/dev/socket/logdr 666 666 logd logd logd logd
```
13.剩下的fix，就有点看运气了。首先确定了这个方法只能root Android L，没有办法root Android M。所以Google应该已经fix掉了。一开始我怀疑是liblog代码的问题，对比了一下M和L差异，感觉不是log_read.c的问题，然后对了logd/main.cpp，变化太大了，不好找。然后对比到init.rc，果然logd的启动参数有变化，google已经有patch了，其实init拉起logd时，把group加上即可。
```diff
Author: Jeff Vander Stoep <jeffv@google.com>  2015-07-24 06:18:36
Committer: Jeffrey Vander Stoep <jeffv@google.com>  2015-07-25 00:22:06
Parent: ed2fe57c2509d0d784ba7dbce1deef21afb2a612 (Use single tree for multiple storage views.)
Child:  1d0fe13a9e720a88766b38070195670183274e30 (am 3f62a020: logd: allow logd to write to /dev/cpuset files)
Child:  10a239b971d737b15a5d0652a441994e5c02ad88 (Give secondary users read-only physical cards.)
Child:  cc451785fe4426566f6c4a6a5156d4fb40bcc22d (Fix incorrectly sized buffer.)
Branches: remotes/m/sanfrancisco, remotes/smartisan/surabaya-rom
Follows: 
Precedes: 

    logd: allow logd to write to /dev/cpuset files
    
    Required by logd on devices with USE_CPUSETS defined.
    
    Make /dev/cpuset/background, /dev/cpuset/foreground and
    /dev/cpuset/task writeable by system gid. Add logd to system
    group for writing to cpuset files and to root group to avoid
    regressions. When dropping privs, also drop supplementary groups.
    
    Bug: 22699101
    Change-Id: Icc01769b18b5e1f1649623da8325a8bfabc3a3f0

-------------------------------- logd/main.cpp --------------------------------
index 9b889838..a3241d05 100644
@@ -103,6 +103,10 @@ static int drop_privs() {
         return -1;
     }
 
+    if (setgroups(0, NULL) == -1) {
+        return -1;
+    }
+
     if (setgid(AID_LOGD) != 0) {
         return -1;
     }

------------------------------- rootdir/init.rc -------------------------------
index 7af2b770..2ac182be 100644
@@ -145,9 +145,9 @@ on init
     chown system system /dev/cpuset/tasks
     chown system system /dev/cpuset/foreground/tasks
     chown system system /dev/cpuset/background/tasks
-    chmod 0644 /dev/cpuset/foreground/tasks
-    chmod 0644 /dev/cpuset/background/tasks
-    chmod 0644 /dev/cpuset/tasks
+    chmod 0664 /dev/cpuset/foreground/tasks
+    chmod 0664 /dev/cpuset/background/tasks
+    chmod 0664 /dev/cpuset/tasks
 
 
     # qtaguid will limit access to specific data based on group memberships.
@@ -523,6 +523,7 @@ service logd /system/bin/logd
     socket logd stream 0666 logd logd
     socket logdr seqpacket 0666 logd logd
     socket logdw dgram 0222 logd logd
+    group root system
 
 service logd-reinit /system/bin/logd --reinit
     oneshot
```

14.可以继续往下分析logd是怎么被干掉的，还有进程究竟是怎么拿到root权限。

```
TODO
```

