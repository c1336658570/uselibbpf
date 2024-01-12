// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"

// 回调函数，用于打印libbpf错误和调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	// 创建BPF程序的上下文
	struct minimal_bpf *skel;
	int err;

	// 设置libbpf错误和调试信息的回调函数
	/*
	 * libbpf_set_print()为所有 libbpf 日志提供了一个自定义回调。这非常有用，特别是在开发期间，
	 * 因为它允许捕获有用的 libbpf 调试日志。默认情况下，如果出现错误，libbpf 将只记录错误级别的消息。
	 * 而且，调试日志有助于获得关于正在发生的事情的额外上下文，更快地调试问题。
	 */
	libbpf_set_print(libbpf_print_fn);

	// 打开BPF程序，创建BPF程序的上下文
	skel = minimal_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 确保BPF程序仅处理来自我们进程的write()系统调用
	skel->bss->my_pid = getpid();

	// 加载并验证BPF程序
	err = minimal_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 附加tracepoint处理程序
	/*
	 * 将现在已经在内核中等待的handle_tp BPF 程序附加到相应的内核跟踪点。这将“激活”BPF 程序，
	 * 内核将开始在内核上下文中执行我们的定制 BPF 代码，以响应每次 write ()系统调用！
	 */
	err = minimal_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 打印提示信息
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	// 循环触发BPF程序
	for (;;) {
		// 触发我们的BPF程序
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	// 销毁BPF程序的上下文。清除所有资源(包括内核和用户空间中的资源)。
	minimal_bpf__destroy(skel);
	return -err;
}
