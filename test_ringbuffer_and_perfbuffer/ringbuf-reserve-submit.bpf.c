#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);							// 定义BPF环形缓冲区映射
  __uint(max_entries, 256 * 1024 /* 256 KB */);		// 设置最大条目数为256KB
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	// 从tracepoint上下文中提取文件名数据的偏移量
  unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
  struct event *e;

	// 尝试从环形缓冲区中预留空间
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) return 0;

	// 填充'struct event'字段
  e->pid = bpf_get_current_pid_tgid() >> 32;							// 从当前任务的PID/TGID中提取PID
  bpf_get_current_comm(&e->comm, sizeof(e->comm));				// 获取当前任务的命令（进程名）
	// 从上下文中读取文件名
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	// 提交填充的'struct event'到环形缓冲区
  bpf_ringbuf_submit(e, 0);
  return 0;
}
