// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * uprobed" 是处理用户空间进入和退出（返回）探针的一个示例，它在 libbpf 术语中使用 uprobe 和 uretprobe。
 * 它将 uprobe 和 uretprobe BPF 程序附加到其自身的函数（uprobed_add() 和 uprobed_sub()），
 * 并使用 bpf_printk() 宏记录输入参数和返回结果。用户空间函数每秒触发一次。
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";		// 定义BPF程序的许可证信息

// BPF程序入口点，用于处理uprobed_add函数的进入事件
SEC("uprobe")
int BPF_KPROBE(uprobe_add, int a, int b)
{
	bpf_printk("uprobed_add ENTRY: a = %d, b = %d", a, b);		// 打印 uprobed_add 函数的进入信息
	return 0;			// 返回0表示成功
}

// BPF程序入口点，用于处理uprobed_add函数的返回事件
SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_add, int ret)
{
	bpf_printk("uprobed_add EXIT: return = %d", ret);		// 打印 uprobed_add 函数的返回信息
	return 0;
}

// BPF程序入口点，用于处理/proc/self/exe:uprobed_sub函数的进入事件
// 而两个斜杠//的作用是指定使用自动解析的方式获取当前进程的路径。具体来说，//告诉BPF系统在解析路径时使用自动解析规则，而不是显式提供的路径。
SEC("uprobe//proc/self/exe:uprobed_sub")	// self表示当前进程，也可以替换为进程PID，exe是个软链接，链接到可执行文件，cat /proc/14579/exe
int BPF_KPROBE(uprobe_sub, int a, int b)
{
	bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);		// 打印 uprobed_sub 函数的进入信息
	return 0;
}

// BPF程序入口点，用于处理/proc/self/exe:uprobed_sub函数的返回事件
SEC("uretprobe//proc/self/exe:uprobed_sub")
int BPF_KRETPROBE(uretprobe_sub, int ret)
{
	bpf_printk("uprobed_sub EXIT: return = %d", ret);		// 打印 uprobed_sub 函数的返回信息
	return 0;
}
