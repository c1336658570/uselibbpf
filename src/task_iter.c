// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Meta */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "task_iter.h"
#include "task_iter.skel.h"

// 使用bpf迭代器
// BPF 迭代器使用内核的 seq_file 来传递数据至用户空间。该数据可以是一个格式化的字符串或原始数据。
// 在格式化字符串的情况下，你可以使用 bpftool iter 子命令来创建并通过 bpf_link 将一个 BPF 
// 迭代器固定在 BPF 文件系统（bpffs）的路径上。然后你可以使用 cat <path> 来打印结果，
// 例如 cat /proc/net/netlink 这种方式。

// 程序运行时配置结构体
static struct env {
	bool verbose;		// 是否启用详细输出
} env;

// libbpf 打印回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	// 如果是调试信息且未启用详细输出，则忽略
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

// 用于标识程序是否退出的全局变量
static volatile bool exiting = false;

// Ctrl-C 信号处理函数，设置退出标志
static void sig_handler(int sig)
{
	exiting = true;
}

// 将任务状态码转换为字符串表示
static const char *get_task_state(__u32 state)
{
	/* Taken from:
	 * https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L85
	 * There are a lot more states not covered here but these are common ones.
	 */
	/* 从 Linux 内核头文件中获取任务状态码对应的字符串表示 */
	switch (state) {
	case 0x0000: return "RUNNING";
	case 0x0001: return "INTERRUPTIBLE";
	case 0x0002: return "UNINTERRUPTIBLE";
	case 0x0200: return "WAKING";
	case 0x0400: return "NOLOAD";
	case 0x0402: return "IDLE";
	case 0x0800: return "NEW";
	default: return "<unknown>";
	}
}

int main(int argc, char **argv)
{
	struct task_iter_bpf *skel;
	struct task_info buf;         // 用于存储读取的任务信息
	int iter_fd;                  // 迭代器文件描述符
	ssize_t ret;                  // 读取返回值
	int err;                  		// 错误码

	// 设置 libbpf 的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 设置 SIGINT 和 SIGTERM 的信号处理函数
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开、加载和验证 BPF 应用程序
	skel = task_iter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	// 附加追踪点
	err = task_iter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 创建 BPF 迭代器并获取其文件描述符 
	// bpf_link__fd函数参数：
	// link：一个指向 bpf_link 结构的指针，表示要操作的 eBPF 链接。
	// 返回值：一个整数，表示与给定 eBPF 链接关联的文件描述符。如果发生错误，将返回负数。
	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_tasks));
	if (iter_fd < 0) {
		err = -1;
		fprintf(stderr, "Failed to create iter\n");
		goto cleanup;
	}

	// 循环读取任务信息
	while (true) {
		ret = read(iter_fd, &buf, sizeof(struct task_info));
		if (ret < 0) {
			if (errno == EAGAIN)		// 如果是 EAGAIN，表示暂时没有数据，继续循环
				continue;
			err = -errno;
			break;									// 其他错误，跳出循环
		}
		if (ret == 0)							// 读取到 EOF，跳出循环
			break;
		// 输出任务信息到控制台
		if (buf.kstack_len <= 0) {
			printf("Error getting kernel stack for task. Task Info. Pid: %d. Process Name: %s. Kernel Stack Error: %d. State: %s\n",
			       buf.pid, buf.comm, buf.kstack_len, get_task_state(buf.state));
		} else {
			printf("Task Info. Pid: %d. Process Name: %s. Kernel Stack Len: %d. State: %s\n",
			       buf.pid, buf.comm, buf.kstack_len, get_task_state(buf.state));
		}
	}

cleanup:
	// 清理资源
	close(iter_fd);
	task_iter_bpf__destroy(skel);

	return err < 0 ? -err : 0;			// 返回错误码，如果是负值则取相反数
}
