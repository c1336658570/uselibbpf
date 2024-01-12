// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

/*
 * 使用 eBPF 程序 profile 进行性能分析
 * 
 * 使用 libbpf 和 eBPF 程序进行性能分析。我们将利用内核中的 perf 机制，学习如何捕获函数的执行时间以及如何查看性能数据。
 * 
 * perf 是 Linux 内核中的性能分析工具，允许用户测量和分析内核及用户空间程序的性能，以及获取对应的调用堆栈。
 * 它利用内核中的硬件计数器和软件事件来收集性能数据。
 * 
 * profile 工具基于 eBPF 实现，利用 Linux 内核中的 perf 事件进行性能分析。profile 工具会定期对每个处理器进行采样，
 * 以便捕获内核函数和用户空间函数的执行。它可以显示栈回溯的以下信息：
 * 地址：函数调用的内存地址
 * 符号：函数名称
 * 文件名：源代码文件名称
 * 行号：源代码中的行号
 * 这些信息有助于开发人员定位性能瓶颈和优化代码。更进一步，可以通过这些对应的信息生成火焰图，以便更直观的查看性能数据。
 * 
 * profile 工具由两个部分组成，内核态中的 eBPF 程序和用户态中的 profile 符号处理程序。
 * profile 符号处理程序负责加载 eBPF 程序，以及处理 eBPF 程序输出的数据。
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义了一个类型为 BPF_MAP_TYPE_RINGBUF 的 eBPF maps 。Ring Buffer 是一种高性能的循环缓冲区，
// 用于在内核和用户空间之间传输数据。max_entries 设置了 Ring Buffer 的最大大小。
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);			// 映射类型为环形缓冲区
	__uint(max_entries, 256 * 1024);				// 256K
} events SEC(".maps");

// 定义了一个名为 profile 的 eBPF 程序，它将在 perf 事件触发时执行。
SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;			// 获取当前进程的 PID
	int cpu_id = bpf_get_smp_processor_id();				// 获取当前 CPU ID
	struct stacktrace_event *event;									// 定义事件结构体指针
	int cp;

	// 从环形缓冲区中预留空间
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;			// 如果预留失败，返回 1 表示错误

	// 填充事件结构体的各个字段
	event->pid = pid;								// 记录进程 PID
	event->cpu_id = cpu_id;					// 记录 CPU ID

	// 获取当前进程的名称（命令行）
	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;		// 如果获取失败，将 comm 字段置为空字符串

	// 获取内核栈信息，包括栈大小和栈内容。将结果存储在 event->kstack，并将其大小存储在 event->kstack_sz。
	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	// 获取用户栈信息，包括栈大小和栈内容。传递 BPF_F_USER_STACK 标志以获取用户空间栈信息。
	// 将结果存储在 event->ustack，并将其大小存储在 event->ustack_sz。
	event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	// 提交事件到环形缓冲区
	bpf_ringbuf_submit(event, 0);

	return 0;
}
