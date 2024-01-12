// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 定义BPF程序的许可证信息
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义全局变量，用于存储目标进程的PID
int my_pid = 0;

// 定义BPF程序的入口点，响应系统调用write的进入事件
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	// 获取当前进程ID（Process ID）
	int pid = bpf_get_current_pid_tgid() >> 32;

	// 打印BPF触发的消息，包含PID信息
	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
