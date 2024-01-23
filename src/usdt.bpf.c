// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

/*
 * "usdt" 是处理 USDT 探针的一个示例。它将 USDT BPF 程序附加到 libc:setjmp 探针上，
 * 该探针在用户空间程序中每秒调用一次 setjmp 时触发，并使用 bpf_printk() 宏记录 USDT 参数。
 */

// 定义要跟踪的进程的PID
pid_t my_pid = 0;

// 定义USDT自动附加函数，该函数将与libc库中的setjmp函数关联
SEC("usdt/libc.so.6:libc:setjmp")
int BPF_USDT(usdt_auto_attach, void *arg1, int arg2, void *arg3)
{
	// 获取当前进程的PID
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	// 如果当前进程的PID不等于指定的PID，则返回
	if (pid != my_pid)
		return 0;

	// 打印USDT自动附加消息，包括setjmp函数的参数信息
	bpf_printk("USDT auto attach to libc:setjmp: arg1 = %lx, arg2 = %d, arg3 = %lx", arg1, arg2, arg3);
	return 0;
}

// 定义USDT手动附加函数，与任何setjmp函数关联
SEC("usdt")
int BPF_USDT(usdt_manual_attach, void *arg1, int arg2, void *arg3)
{
	// 打印USDT手动附加消息，包括setjmp函数的参数信息
	bpf_printk("USDT manual attach to libc:setjmp: arg1 = %lx, arg2 = %d, arg3 = %lx", arg1, arg2, arg3);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
