#!/bin/bash

# 使用示例： 
# sh start_memleak.sh ./memleak_test &

# $$ 表示脚本运行的当前进程ID号，使用示例中的 memleak_test 启动时，就会继承这个进程ID
# 启动内存泄露检测工具 memleak 时，就可以预先知道测试程序 memleak_test 的进程ID
sudo ./memleak $$ &

# $@ 表示传给脚本的所有参数的列表，即使用示例中的 ./test/memleak_test
exec "$@"