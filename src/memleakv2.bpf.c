// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleakv2.h"

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // pid
	__type(value, u64); // size for alloc
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* alloc return address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* stack id */
	__type(value, union combined_alloc_info);
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

/* value： stack id 对应的堆栈的深度
 * max_entries: 最大允许存储多少个stack_id（每个stack id都对应一个完整的堆栈）
 * 这2个值可以根据应用层的使用场景,在应用层的ebpf中open之后load之前动态设置
 */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32); /* stack id */
	//__type(value, xxx);       memleak_bpf__open 之后再动态设置
	//__uint(max_entries, xxx); memleak_bpf__open 之后再动态设置
} stack_traces SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

	// bpf_printk("malloc_enter size=%d\n", size);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit, void * address)
{
	const u64 addr = (u64)address;
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_info info;

	const u64 * size = bpf_map_lookup_elem(&sizes, &pid);
	if (NULL == size) {
		return 0;
	}

	__builtin_memset(&info, 0, sizeof(info));
	info.size = *size;

	bpf_map_delete_elem(&sizes, &pid);

	if (NULL != address) {
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

		bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

		union combined_alloc_info add_cinfo = {
			.total_size = info.size,
			.number_of_allocs = 1
		};

		union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info.stack_id);
		if (NULL == exist_cinfo) {
			bpf_map_update_elem(&combined_allocs, &info.stack_id, &add_cinfo, BPF_NOEXIST);
		}
		else {
			__sync_fetch_and_add(&exist_cinfo->bits, add_cinfo.bits);
		}
	}

	// bpf_printk("malloc_exit address=%p\n", address);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void * address)
{
	const u64 addr = (u64)address;

	const struct alloc_info * info = bpf_map_lookup_elem(&allocs, &addr);
	if (NULL == info) {
		return 0;
	}

	union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info->stack_id);
	if (NULL == exist_cinfo) {
		return 0;
	}

	const union combined_alloc_info sub_cinfo = {
		.total_size = info->size,
		.number_of_allocs = 1
	};

	__sync_fetch_and_sub(&exist_cinfo->bits, sub_cinfo.bits);

	bpf_map_delete_elem(&allocs, &addr);

	// bpf_printk("free_enter address=%p\n", address);
	return 0;
}
