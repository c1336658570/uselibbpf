// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义Kprobe，用于跟踪do_unlinkat系统调用的入口
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	// 获取当前进程的PID（进程ID）
	pid_t pid;
	// 用于存储文件名的指针
	const char *filename;

	// 通过bpf_get_current_pid_tgid()获取PID，并右移32位获取实际的PID值	
	pid = bpf_get_current_pid_tgid() >> 32;
	// 通过BPF_CORE_READ宏获取filename的值
	filename = BPF_CORE_READ(name, name);
	// 打印Kprobe进入事件的跟踪信息，包括PID和文件名
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
	// 获取当前进程的PID（进程ID）
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	// 打印Kretprobe退出事件的跟踪信息，包括PID和系统调用的返回值
	bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}
