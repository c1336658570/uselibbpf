// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * "fentry" 是一个使用 fentry 和 fexit BPF 程序进行跟踪的示例。它将 fentry 和 fexit 
 * 跟踪附加到 do_unlinkat() 函数上，该函数在删除文件时被调用，并将返回值、PID 和文件名记录到跟踪管道中。
 * 与 kprobes 相比，其重要区别在于改进了性能和可用性。在此示例中，更好的可用性体现在能够直接解引用指针参数，
 * 就像在普通的 C 语言中一样，而无需使用各种读取帮助程序。
 * fexit 和 kretprobe 程序之间的主要区别在于 fexit 具有对输入参数和返回结果的访问权限，而 kretprobe 只能访问结果。
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义BPF程序，附加到 do_unlinkat，进入do_unlinkat执行
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
	// 获取当前进程的PID（进程ID）
	pid_t pid;

	// 通过bpf_get_current_pid_tgid()获取PID，并右移32位获取实际的PID值
	pid = bpf_get_current_pid_tgid() >> 32;
	// 打印跟踪信息，包括PID和文件名
	bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
	return 0;
}

// 定义BPF程序，用于跟踪do_unlinkat系统调用的退出，附加到do_unlinkat_exit，离开do_unlinkat执行
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	// 打印跟踪信息，包括PID、文件名和系统调用的返回值
	bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
	return 0;
}
