// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

// 回调函数，用于输出 libbpf 的错误信息和调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 全局函数，确保编译器不会内联它
int uprobed_add(int a, int b)
{
	return a + b;
}

int uprobed_sub(int a, int b)
{
	return a - b;
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err, i;
	/*
	// 大括号括起来的是一个代码块，最后一个表达式的结果是代码块的结果
	// 使用memset清零结构体变量的内存
	// 创建一个结构体的临时对象，然后将其作为大括号的结果，赋值给NAME
	#define LIBBPF_OPTS(TYPE, NAME, ...)					    \
		struct TYPE NAME = ({ 						    \
			memset(&NAME, 0, sizeof(struct TYPE));			    \
			(struct TYPE) {						    \
				.sz = sizeof(struct TYPE),			    \
				__VA_ARGS__					    \
			};							    \
		})
	*/
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	// 设置 libbpf 的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 打开、加载和验证 BPF 应用程序
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// 附加 tracepoint 处理程序
	uprobe_opts.func_name = "uprobed_add";		// 要附加的函数名称。
	uprobe_opts.retprobe = false;							// 是否为返回探针，即在函数返回时触发
	// uprobe/uretprobe 期望要附加的函数的相对偏移。
	// 如果我们提供了函数名，libbpf 会自动为我们找到偏移。
	// 5个参数， prog：指向 BPF 程序的指针，表示要附加的 BPF 程序
	// pid：目标进程的 PID，表示要附加 uprobes 的进程
	// binary_path：字符串，表示 uprobes 所在二进制文件的路径
	// func_offset：size_t，表示 uprobes 所在函数的偏移量
	// opts：指向 struct bpf_uprobe_opts 结构体的指针，包含 uprobes 的附加选项
	// 成功时，返回指向附加的 BPF 链接的指针，失败时，返回NULL，并设错误码
	// 该函数内部调用了libbpf_err_ptr，它会将errno设置为-errno，并返回NULL
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(skel->progs.uprobe_add,
								 0 /* self pid */, "/proc/self/exe",
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	// 我们还可以将 uprobe/uretprobe 附加到使用相同二进制可执行文件的任何现有或未来进程；
	// 为此，我们需要将 PID 指定为 -1
	// -1 是用于指定 PID（进程ID）的参数，表示将 uretprobe 附加到所有进程，而不仅仅是当前的进程。
	// 具体来说，-1 表示将 uretprobe 附加到所有具有相同二进制可执行文件的进程。
	uprobe_opts.func_name = "uprobed_add";			// 要附加的函数名称。
	uprobe_opts.retprobe = true;								// 是否为返回探针，即在函数返回时触发
	// 5个参数， prog：指向 BPF 程序的指针，表示要附加的 BPF 程序
	// pid：目标进程的 PID，表示要附加 uprobes 的进程
	// binary_path：字符串，表示 uprobes 所在二进制文件的路径
	// func_offset：size_t，表示 uprobes 所在函数的偏移量
	// opts：指向 struct bpf_uprobe_opts 结构体的指针，包含 uprobes 的附加选项
	// 成功时，返回指向附加的 BPF 链接的指针，失败时，返回NULL，并设错误码
	// 该函数内部调用了libbpf_err_ptr，它会将errno设置为-errno，并返回NULL
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_add, -1 /* self pid */, "/proc/self/exe",
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	// 让 libbpf 自动执行对 uprobe_sub/uretprobe_sub 的附加操作。
	// 注意：我们在 BPF 程序的 SEC 部分提供路径和符号信息
	err = uprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (i = 0;; i++) {
		// 触发我们的 BPF 程序
		fprintf(stderr, ".");
		uprobed_add(i, i + 1);
		uprobed_sub(i * i, i);
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
