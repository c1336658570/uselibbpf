// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Hosein Bakhtiari */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;						// 用于存储目标进程的PID
unsigned long long dev;		// 用于存储设备ID
unsigned long long ino;		// 用于存储inode号

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	struct bpf_pidns_info ns;

	// 获取当前进程的命名空间信息（包括PID）
	bpf_get_ns_current_pid_tgid(dev, ino, &ns, sizeof(ns));

	// 如果进程的PID不是目标PID，返回0（过滤事件）
	if (ns.pid != my_pid)
		return 0;

	// 打印一条消息，指示BPF程序由指定的进程ID触发
	bpf_printk("BPF triggered from PID %d.\n", ns.pid);

	return 0;
}
