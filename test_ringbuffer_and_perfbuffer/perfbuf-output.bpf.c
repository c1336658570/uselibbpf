#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF perfbuf映射
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} pb SEC(".maps");

// BPF per-CPU数组映射
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event);
} heap SEC(".maps");

// 在sched_process_exec tracepoint上执行的处理函数
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	// 从上下文提取文件名数据的偏移量
  unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
  struct event *e;
  int zero = 0;

	// 在per-CPU数组映射中查找key为零的元素
  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) /* can't happen */
    return 0;

	// 填充'struct event'字段
  e->pid = bpf_get_current_pid_tgid() >> 32;				// 从当前任务的PID/TGID中提取PID
  bpf_get_current_comm(&e->comm, sizeof(e->comm));	// 获取当前任务的命令（进程名）
	// 从上下文中读取文件名
  bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	// 将填充的'struct event'输出到perf缓冲区
  bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}
