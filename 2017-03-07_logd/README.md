1. 下载kingroot，root手机成功

2. 重新刷机，在破解过程中提取ps输出的log，查看破解过程中都有哪些进程执行了。详细间ps.log

3. 分析ps.log，可知，kingroot会启动后台进程，此时没有root，直到用户点击root手机后，才开始尝试root
```
    com.kingroot.kinguser(pid 8540, ppid zygote)
    com.kingroot.kinguser:service(pid 6450, ppid zygote)
    krs_100213(pid xxx, ppid 1， 多个进程)
    /data/user/0/com.kingroot.kinguser/applib/ktools(pid 6696, ppid 1)
```

4. 尝试root时，会从云端直接拉下来一堆二进制文件，放在/data/data/com.kingroot.kinguser下面，然后顺序启动下面的进程，详细间ps.log
```
   krmain(pid 9876, ppid 8540, 就是com.kingroot.kinguser)
   sec0w64(pid 9978, ppid 9960, 就是krs_100213中的一个)
   dirtyc0w64(pid 10015, ppid同样是9960)
   kd(pid 10805, ppid 10150,就是dirtyc0w64)
   su_check
```

5. 其中，在dirtyc0w结束时，就成功启动了一个root的sh(pid 10028, ppid 1)，这个，已经被应用root成功了。

6. 然后这个sh就拉起很多很多东西：比如
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

7. 上面之后，就多出一个kr_worker的内核线程了，这个内核线程可以乱开东西。

8. 继续分析ps.log，sec0w64执行过程中，logd无故退出过一次， 在dirtyc0w64 root成功过程中，又杀了一次， pid变化 326 10004 10090
```
logd      326   1     20220  3136  ffffffff 833751c8 S /system/bin/logd
logd      10004 1     19200  1556  ffffffff 83bf0524 R /system/bin/logd
logd      10090 1     20224  1552  ffffffff 838a51c8 S /system/bin/logd

```

到此，严重怀疑本次root利用了logd相关的漏洞。
===========================================================================

9. 本来想静态分析的，发现很困难。dirtyc0w等应用符号表拿掉了，而且加了壳，看不清真实的入口。OK，反正我们是手机厂商，内核随便编译，采用动态分析法。

10. 首先想到的是strace跟踪它的所有系统调用，但是由于root的过程非常快，手动敲键盘完全跟不上，所以写简本监控程序，见trace.sh

11. 刷了一个user root的版本，把strace丢进去，然后在host端执行脚本监控，重新root手机，得到trace.log。

12. 使用logd过滤trace.log，发现破解的核心系统调用
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
```
13. TODO