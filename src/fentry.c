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
#include "fentry.skel.h"

// 定义BPF程序的打印回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 定义一个volatile变量用于在信号处理函数中通知主循环退出
static volatile sig_atomic_t stop;

// 信号处理函数，设置stop标志以通知主循环退出
void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct fentry_bpf *skel;
	int err;

	// 设置libbpf的错误和调试信息回调函数
	libbpf_set_print(libbpf_print_fn);

	// 打开、加载和验证BPF程序
	skel = fentry_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 将BPF程序附加到tracepoint
	err = fentry_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 设置SIGINT信号的处理函数为sig_int
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	// 输出提示信息，告知用户如何查看BPF程序的输出
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	// 主循环，等待SIGINT信号通知退出
	while (!stop) {
		fprintf(stderr, ".");		// 输出一个点用于表示程序在运行
		sleep(1);
	}

cleanup:
	fentry_bpf__destroy(skel);
	return -err;
}
