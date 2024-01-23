// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/*
 * minimal 就是这样 - 一个最小的实际 BPF 应用示例。它不使用或不需要 BPF CO-RE，因此应该在相当旧的内核上运行。
 * 它安装一个跟踪点处理程序。它使用 bpf_printk() BPF 助手与世界进行通信。
 * 要查看其输出，请以 root 身份读取 /sys/kernel/debug/tracing/trace_pipe 文件：
 * 
 * minimal 在具有命名空间的环境（如容器或 WSL2）中不起作用，因为命名空间中进程的感知 pid 不是进程的实际 pid。
 * 若要在命名空间环境中执行， minimal 需要改用 minimal_ns。
 * 
 * sudo ./minimal
 * sudo cat /sys/kernel/debug/tracing/trace_pipe
 */
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
