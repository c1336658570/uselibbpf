// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Meta */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "task_iter.h"

/*
 * "task_iter" 是使用 BPF 迭代器的一个示例。该示例迭代主机上的所有任务，并获取它们的 PID、进程名称、
 * 内核堆栈和它们的状态。注意：你可以使用 BlazeSym 对内核堆栈跟踪进行符号化（就像在 profile 示例中一样），
 * 但为简单起见，该代码已被省略。
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 使用bpf迭代器
// BPF 迭代器使用内核的 seq_file 来传递数据至用户空间。该数据可以是一个格式化的字符串或原始数据。
// 在格式化字符串的情况下，你可以使用 bpftool iter 子命令来创建并通过 bpf_link 将一个 BPF 
// 迭代器固定在 BPF 文件系统（bpffs）的路径上。然后你可以使用 cat <path> 来打印结果，
// 例如 cat /proc/net/netlink 这种方式。

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);		// 映射类型为 PERCPU_ARRAY
	__uint(max_entries, 1);											// 最大条目数为 1
	__type(key, __u32);													// 键类型为无符号 32 位整数
	__type(value, struct task_info);						// 值类型为 task_info 结构体
} task_info_buf SEC(".maps");

// 定义一个特殊的结构体 task_struct___post514，用于保存任务状态信息
struct task_struct___post514 {
	unsigned int __state;											// 任务状态（用于 5.14 版本及之后的内核）
} __attribute__((preserve_access_index));		// 保留访问索引
/**
 *  __attribute__((preserve_access_index)) 主要用于保留对结构体字段的直接访问，以
 * 确保 BPF 程序能够正确地访问结构体的字段。
 * 
 * 在 BPF 程序中，由于内核版本或结构体定义的变化，字段的偏移可能会发生变化。
 * 为了确保 BPF 程序在不同内核版本中都能正确运行，__attribute__((preserve_access_index)) 
 * 会告诉编译器不要对结构体的字段进行优化，以便在运行时通过索引直接访问字段。这样，即使结构体的布局发生变化，
 * BPF 程序也能够正确地获取字段的值。
 */

// 定义另一个特殊的结构体 task_struct___pre5.14，用于保存任务状态信息
struct task_struct___pre514 {
	long state;																// 任务状态（用于 5.14 版本之前的内核）
} __attribute__((preserve_access_index));		// 保留访问索引

// 获取任务的状态
static __u32 get_task_state(void *arg)
{
	/*
	用于检查给定结构体是否存在指定的字段。
	使用 __builtin_preserve_field_info 内置函数，该函数用于保留字段的信息。在这里，field 是要检查的字段。
	__builtin_preserve_field_info 函数的第一个参数是待检查的字段名。BPF_FIELD_EXISTS 是预定义的一个标志，表示检查字段是否存在。
	#define bpf_core_field_exists(field) __builtin_preserve_field_info(field, BPF_FIELD_EXISTS)
	*/

	// bpf_core_field_exists 函数是 BPF 编程中的一个宏，用于在 BPF 程序中检查给定结构体中是否存在指定的字段。
	if (bpf_core_field_exists(struct task_struct___pre514, state)) {
		struct task_struct___pre514 *task = arg;

		return task->state;
	} else {
		struct task_struct___post514 *task = arg;

		return task->__state;
	}
}

// 定义一个全局变量 zero 并初始化为 0
static __u32 zero = 0;

// 迭代器
SEC("iter/task")
int get_tasks(struct bpf_iter__task *ctx)
{
	// BPF迭代器的使用
	// meta代表元数据
	struct seq_file *seq = ctx->meta->seq;		// 获取 seq_file 结构体指针
	struct task_struct *task = ctx->task;			// 获取任务结构体指针
	struct task_info *t;											// 定义任务信息结构体指针
	long res;																	// 用于存储返回结果

	if (!task)		// 如果任务结构体为空，则返回
		return 0;

	// 通过映射查找任务信息
	t = bpf_map_lookup_elem(&task_info_buf, &zero);
	if (!t)				// 如果找不到任务信息，则返回
		return 0;

	// 填充任务信息结构体
	t->pid = task->tgid;
	t->tid = task->pid;
	t->state = get_task_state(task);

	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, task->comm);		// 读取任务名

	// 获取任务内核栈信息
	res = bpf_get_task_stack(task, t->kstack, sizeof(__u64) * MAX_STACK_LEN, 0);
	t->kstack_len = res <= 0 ? res : res / sizeof(t->kstack[0]);

	// 将任务信息写入 seq_file
	bpf_seq_write(seq, t, sizeof(struct task_info));
	return 0;
}
