// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe.skel.h"

// 回调函数，用于打印libbpf的错误和调试信息到stderr
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 全局变量，用于通知主循环停止执行
static volatile sig_atomic_t stop;

// SIGINT（Ctrl+C）的信号处理函数
static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct kprobe_bpf *skel;
	int err;

	// 设置libbpf的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 打开、加载和验证BPF应用程序
	skel = kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 将BPF程序附加到kprobe（内核探针）
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 设置SIGINT信号处理函数
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	// 显示成功启动的消息以及查看BPF程序输出的提示
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	// 主循环：打印点以指示程序正在运行，直到接收到SIGINT信号
	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	// 清除资源
	kprobe_bpf__destroy(skel);
	return -err;
}
