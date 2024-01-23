// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleak.h"

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // pid
	__type(value, u64); // 用户态指针变量 memptr
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

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

/* 通用的内存分配 uprobe的处理逻辑
 * 内存分配接口(malloc, calloc等)进入后就会被调用
 * size: 分配内存的大小, 比如 malloc 的第一个参数
 */
static int gen_alloc_enter(size_t size)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

	// bpf_printk("malloc_enter size=%d\n", size);
	return 0;
}

/* 通用的内存分配 uretprobe的处理逻辑
 * 内存分配接口(malloc, calloc等)返回时就会被调用
 * ctx: struct pt_regs 指针, 参考 BPF_KRETPROBE 的宏展开
 * address: 分配成功的内存指针, 比如 malloc 的返回值
 */
static int gen_alloc_exit2(void *ctx, u64 address)
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

	if (0 != address) {
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

/* 把 gen_alloc_exit2 接口中的2个参数精简为1个参数 
 * 参考 BPF_KRETPROBE 的宏展开过程
 */
static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));		// PT_REGS_RC是获取函数返回值的宏，具体看bpf_tracing.h
}

/* 通用的内存释放 uprobe的处理逻辑
 * 内存释放接口(free, munmap等)进入后就会被调用
 * address: 需要释放的内存指针, 比如 free 的第一个参数
 */
static int gen_free_enter(const void *address)
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

/////////////////////////////////////////////////////////////////////

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void * address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit)
{
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *memptr64;
	void *addr;

	memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

    //通过 bpf_probe_read_user 读取保存在用户态指针变量(memptr64)中的 分配成功的内存指针
	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}