#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#define u64	      long long int
#define TASK_COMM_LEN 16
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//对应的cpu和在这个cpu内这个进程的id
struct cpu_info {
	u64 cpu_id;
	u64 process_id;
};

struct process_info {
	u64 tid;
	u64 cpu_id;
	u64 pid; // 进程的PID
	u64 start_t; //进程开始的时间
	u64 used_t; //已经使用的CPU时间
	u64 total_t; //每个cpu占用的总时间
	u64 occ; //占用率
	char comm[TASK_COMM_LEN];
	// long unsigned int resident;
	// long unsigned int shared;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct process_info);
} pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
} cpu_map SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	u64 prev_pid = ctx->prev_pid;
	u64 next_pid = ctx->next_pid; //获取当前进程的pid;
	u64 tid = bpf_get_current_pid_tgid();
	u64 id = (u32)tid;
	//u64 id = bpf_get_current_pid_tgid();
	//u64 tid = (u32)id;
	u32 cpu_id = bpf_get_smp_processor_id(); // 获取当前 CPU ID

	// 构建键
	struct cpu_info prev_key = { .cpu_id = cpu_id, .process_id = prev_pid };
	struct cpu_info next_key = { .cpu_id = cpu_id, .process_id = next_pid };

	//在当前cpu上查找进程的信息

	struct process_info *prev_info, *prev_space;
	prev_info = bpf_ringbuf_reserve(&rb, sizeof(*prev_info), 0);
	// prev_info = bpf_map_lookup_elem(&pid_map, &prev_pid);
	//  if (!prev_info) {
	// 	return 0;
	//  } //错误处理
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct process_info *next_info = bpf_map_lookup_elem(&pid_map, &next_pid);
	// struct process_info *next_info =
	// 	bpf_ringbuf_reserve(&pid_map, sizeof(*next_info), next_pid);
	// if (!next_info) {
	// 	return 0;
	// }
	u64 cur_time = bpf_ktime_get_ns(); //获取当前时间戳

	//如果前一个进程存在，cur_time为其结束时间，可以计算其本次占用时间
	if (prev_info) {
		// 计算时间差，用当前时间（后一个进程的切入时间即前一个进程切出时间）减去前一个进程的切入时间
		u64 diff = cur_time - prev_info->start_t;
		prev_info->used_t = (prev_info->used_t) + diff; //已经使用过的时间叠加
		prev_info->tid = tid;
		bpf_probe_read_str(&prev_info->comm, sizeof(prev_info->comm), task->comm);
		prev_info->pid = id;
		prev_info->cpu_id = cpu_id;
		//prev_space->cpu_id = prev_info->cpu_id;
		//prev_space->pid = prev_info->pid;
		//bpf_probe_read_str(&prev_space->comm, sizeof(prev_info->comm), prev_info->comm);
		//prev_space->tid = prev_info->tid;
		//prev_space->used_t = prev_info->used_t;
		//bpf_get_current_comm(&prev_info->comm, sizeof(prev_info->comm));

		bpf_ringbuf_submit(prev_info, 0);
		//bpf_ringbuf_output(&rb, prev_info, sizeof(*prev_info), 0);
	} // 如果是系统启动的第一个调度进程，则prev_info会为空，这里先不处理了

	// 处理后一个被调度的进程，cur_time为其开始时间
	if (!next_info) // 没有找到next_info，说明是第一次遇到该项，需要建一个初始化为0加进去
	{
		struct process_info new_info = {};
		new_info.cpu_id = cpu_id;
		new_info.pid = next_pid;
		new_info.start_t = cur_time;
		new_info.occ = 0;
		// 更新新的信息
		bpf_map_update_elem(&pid_map, &next_key, &new_info, BPF_ANY);
	} else // 找到了更新其start时间
	{
		next_info->start_t = cur_time;
	}

	return 0;
}