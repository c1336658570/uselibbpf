// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <linux/limits.h>
#include "usdt.skel.h"

static volatile sig_atomic_t exiting;		// 用于信号处理的退出标志
static jmp_buf env;											// 保存 setjmp 的环境

// SIGINT 信号处理函数，设置退出标志
static void sig_int(int signo)
{
	exiting = 1;
}

// libbpf 的打印回调函数，输出到 stderr
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 触发 USDT 事件的函数
static void usdt_trigger()
{
	setjmp(env);		// 调用 setjmp 保存当前环境，以备长跳转
}

int main(int argc, char **argv)
{
	struct usdt_bpf *skel;
	int err;

	// 设置 libbpf 打印回调函数
	libbpf_set_print(libbpf_print_fn);

	skel = usdt_bpf__open();			// 打开
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->my_pid = getpid();		// 设置 BPF 中的 my_pid 变量为当前进程的 PID

	err = usdt_bpf__load(skel);		// 加载
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	/*
	 * Manually attach to libc.so we find.
	 * We specify pid here, so we don't have to do pid filtering in BPF program.
	 */
	// 手动附加到我们找到的libc.so。
	// 我们在这里指定了pid，这样我们就不用在BPF程序中做pid过滤了
	// prog：指向BPF程序的指针，该程序将与USDT关联。
	// pid：目标进程的PID（Process ID），即希望与之关联BPF程序的进程。
	// binary_path：目标二进制文件的路径，这是一个包含USDT定义的二进制文件。
	// usdt_provider：USDT提供者的名称，通常与目标二进制文件中的提供者名称匹配。
	// usdt_name：USDT的名称，用于指定目标二进制文件中的具体USDT点。
	// opt：一个结构体，包含一些附加的USDT选项，例如cookie等。
	skel->links.usdt_manual_attach = bpf_program__attach_usdt(
		skel->progs.usdt_manual_attach, getpid(), "libc.so.6", "libc", "setjmp", NULL);
	if (!skel->links.usdt_manual_attach) {
		err = errno;
		fprintf(stderr, "Failed to attach BPF program `usdt_manual_attach`\n");
		goto cleanup;
	}
	// 自动附加到系统中的 libc.so，不指定 PID，将在 BPF 程序中进行 PID 过滤
	err = usdt_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 设置 SIGINT 信号处理函数
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	// 输出提示信息
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!exiting) {
		// 触发 BPF 程序
		usdt_trigger();
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	// 清理资源
	usdt_bpf__destroy(skel);
	return -err;
}
