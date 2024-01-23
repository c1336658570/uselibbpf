// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleakv1.h"

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)		// 内核堆栈
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)		// 用户堆栈

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // 进程 ID(调用malloc的进程的pid)
	__type(value, u64); // malloc分配内存的大小（malloc的参数）
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); 		// malloc分配内存返回的地址（malloc返回值）
	__type(value, struct alloc_info);		// 分配信息结构体
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); 	// 堆栈ID(stack id)
	__type(value, union combined_alloc_info);		// 联合体，包含总分配信息
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

/* value： stack id 对应的堆栈的深度
 * max_entries: 最大允许存储多少个stack_id（每个stack id都对应一个完整的堆栈）
 * 这2个值可以根据应用层的使用场景,在应用层的ebpf中open之后load之前动态设置
 */
// value：当前栈的所有指令地址
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32); 	// 堆栈ID(stack id)
	//__type(value, xxx);       memleakv1_bpf__open 之后再动态设置
	//__uint(max_entries, xxx); memleakv1_bpf__open 之后再动态设置
} stack_traces SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 监听 malloc 函数进入的 uprobes
SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	// 更新分配大小映射表
	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

	// bpf_printk("malloc_enter size=%d\n", size);
	return 0;
}

// 监听 malloc 函数退出的 uretprobes
SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit, void * address)
{
	const u64 addr = (u64)address;
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_info info;

	// 查找对应进程的分配大小
	const u64 * size = bpf_map_lookup_elem(&sizes, &pid);
	if (NULL == size) {
		return 0;
	}

	// 初始化分配信息结构体
	__builtin_memset(&info, 0, sizeof(info));
	info.size = *size;

	// 删除分配大小映射表中的记录
	bpf_map_delete_elem(&sizes, &pid);

	// 如果地址不为空，获取堆栈 ID
	if (NULL != address) {
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

		// 更新分配信息映射表
		bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

		// 更新总分配信息映射表
		union combined_alloc_info add_cinfo = {
			.total_size = info.size,
			.number_of_allocs = 1
		};

		union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info.stack_id);
		if (NULL == exist_cinfo) {
			bpf_map_update_elem(&combined_allocs, &info.stack_id, &add_cinfo, BPF_NOEXIST);
		}
		else {
			__sync_fetch_and_add(&exist_cinfo->bits, add_cinfo.bits);		// 原子操作
		}
	}

	// bpf_printk("malloc_exit address=%p\n", address);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void * address)
{
	const u64 addr = (u64)address;

	// 查找对应分配的信息
	const struct alloc_info * info = bpf_map_lookup_elem(&allocs, &addr);
	if (NULL == info) {
		return 0;
	}

	// 查找对应堆栈 ID 的总分配信息
	union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info->stack_id);
	if (NULL == exist_cinfo) {
		return 0;
	}

	// 准备用于减法操作的总分配信息
	const union combined_alloc_info sub_cinfo = {
		.total_size = info->size,
		.number_of_allocs = 1
	};

	// 执行减法操作
	__sync_fetch_and_sub(&exist_cinfo->bits, sub_cinfo.bits);

	// 删除分配信息映射表中的记录
	bpf_map_delete_elem(&allocs, &addr);

	// bpf_printk("free_enter address=%p\n", address);
	return 0;
}
