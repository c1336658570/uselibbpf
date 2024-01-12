// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Hosein Bakhtiari */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "minimal_ns.skel.h"

// 回调函数，用于打印libbpf的错误和调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct minimal_ns_bpf *skel;
	int err;
	struct stat sb;

	// 设置libbpf的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 打开BPF应用程序
	skel = minimal_ns_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 确保BPF程序只处理来自我们进程的write()系统调用
	if (stat("/proc/self/ns/pid", &sb) == -1) {
		fprintf(stderr, "Failed to acquire namespace information");
		return 1;
	}
	skel->bss->dev = sb.st_dev;
	skel->bss->ino = sb.st_ino;
	skel->bss->my_pid = getpid();

	// 加载并验证BPF程序
	err = minimal_ns_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 附加跟踪点处理程序
	err = minimal_ns_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		// 打印.表示还活着
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	// 清理资源
	minimal_ns_bpf__destroy(skel);
	return -err;
}
