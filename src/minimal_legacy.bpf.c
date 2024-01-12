/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 创建一个包含 1 个条目的数组，而不是全局变量，不适用于旧内核
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, pid_t);
} my_pid_map SEC(".maps");

// sys_enter_write跟踪点触发的BPF程序入口点
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	// 访问映射中唯一条目的索引
	u32 index = 0;
	// 从上下文中提取进程ID
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	// 在BPF映射中查找与键（索引）关联的值
	pid_t *my_pid = bpf_map_lookup_elem(&my_pid_map, &index);

	// 如果条目不存在或存储的进程ID与当前进程ID不匹配，返回1（过滤事件）
	if (!my_pid || *my_pid != pid)
		return 1;

	// 打印一条消息，指示BPF程序由指定的进程ID触发
	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
