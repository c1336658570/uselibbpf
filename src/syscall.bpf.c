#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义BPF程序的许可证信息
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct syscall_event {
  pid_t pid;                        // pid
  long int nr;                        // 系统调用号
  char comm[TASK_COMM_LEN];				// 进程名称
  u64 runtime;                    // 系统调用运行时间
};

// 定义全局变量，用于存储目标进程的PID
int pid_target = 0;

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} start_time SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct syscall_event);
} perfcpu_event SEC(".maps");

// 定义BPF程序的入口点，响应系统调用的进入事件
SEC("tp/raw_syscalls/sys_enter")
int handle_enter(struct trace_event_raw_sys_enter *ctx) {
	u64 start_tm;

  // 获取当前进程ID（Process ID）
	int pid = bpf_get_current_pid_tgid() >> 32;

	// pid过滤
	if (pid_target && pid != pid_target) {
		return 0;
  }
  // 设置启动系统调用时间
  start_tm = bpf_ktime_get_ns();


  bpf_map_update_elem(&start_time, &pid, &start_tm, BPF_ANY);

	return 0;
}

// 定义BPF程序的出口点，响应系统调用的退出事件
SEC("tp/raw_syscalls/sys_exit")
int handle_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 *start_ts;
  struct syscall_event *event;

	// 获取当前进程ID（Process ID）
	int pid = bpf_get_current_pid_tgid() >> 32;
  
	if (pid_target && pid != pid_target) {
		return 0;
  }
  
  if (ctx->ret < 0) {
    bpf_map_delete_elem(&start_time, &pid);
    return 0;
  }

  int zero = 0;
  event = bpf_map_lookup_elem(&perfcpu_event, &zero);

  if (!event) {
    return 0;
  }
  
  event->pid = pid;
  event->nr = ctx->id;

  // 获取当前进程的名称（命令行）
  if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
      event->comm[0] = 0; // 如果获取失败，将 comm 字段置为空字符串
  
  start_ts =  bpf_map_lookup_elem(&start_time, &pid);
  if (!start_ts || !(*start_ts)) { //错误处理
    return 0; 
  }

  u64 end_ts = bpf_ktime_get_ns();
  if (!end_ts ) {
    return 0; 
  }
  //运行时间计算  
  event->runtime = end_ts - *start_ts;

  bpf_map_delete_elem(&start_time, &pid);

  bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 0;
}
