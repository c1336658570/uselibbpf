// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

/*
 * 使用 libbpf 开发用户态程序并跟踪 exec() 和 exit() 系统调用
 *
 * 利用 eBPF 程序来跟踪内核中的 exec() 系统调用（通过 SEC("tp/sched/sched_process_exec")
 *  handle_exec BPF 程序），这主要对应于新进程的创建（不包括 fork() 部分）。
 * 此外，它还跟踪进程的 exit() 系统调用（通过 SEC("tp/sched/sched_process_exit") 
 * handle_exit BPF 程序），以了解每个进程何时退出。
 * 
 * 这两个 BPF 程序共同工作，允许捕获关于新进程的有趣信息，例如二进制文件的文件名，以及测量进程的生命周期，
 * 并在进程结束时收集有趣的统计信息，例如退出代码或消耗的资源量等。这是深入了解内核内部并观察事物如何真正运作的良好起点。
 * 
 * Bootstrap 还使用 argp API（libc 的一部分）进行命令行参数解析，使得用户可以通过命令行选项配置应用行为。
 * 这种方式提供了灵活性，让用户能够根据实际需求自定义程序行为。
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义一个 BPF 哈希映射，用于存储每个进程（pid）执行 exec 时的开始时间。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

// rb 是一个环形缓冲区类型的 eBPF map，用于存储捕获的事件数据，并将其发送到用户态程序。
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);		// 256KB
} rb SEC(".maps");

/*
 * const volatile 部分很重要，它将变量标记为 BPF 代码和用户空间代码的只读。
 * 作为交换，它在 BPF 程序验证期间使 BPF 验证工具知道 min_duration_ns 变量的具体值。
 * 如果只读值可证明省略了某些代码路径，这将允许 BPF 验证程序删除死代码。对于一些更高级的用例，比
 * 如处理各种兼容性检查和额外的配置，这个属性通常是可取的。
 * 
 * volatile是必要的，以确保Clang不会完全优化变量，忽略用户空间提供的值。
 * 没有它，Clang就可以自由地假设0并完全删除变量，这根本不是我们想要的。
 */
const volatile unsigned long long min_duration_ns = 0;		// 只读全局变量

/*
 * 跟踪 exec ()系统调用(使用SEC("tp/sched/sched_process_exec")，
 * 大致相当于一个新进程的生成(为简单起见，忽略 fork 部分)。
 *
 * 这段代码是一个内核态 eBPF 程序（bootstrap.bpf.c），主要用于跟踪 exec() 和 exit() 系统调用。
 * 它通过 eBPF 程序捕获进程的创建和退出事件，并将相关信息发送到用户态程序进行处理。
 * 
 * 定义了一个名为 handle_exec 的 eBPF 程序，它会在进程执行 exec() 系统调用时触发。
 */
SEC("tp/sched/sched_process_exec")
// 我的系统在/usr/src/linux-source-6.2.0/linux-source-6.2.0/samples/bpf/vmlinux.h下有下面这个参数的结构体定义
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	// 记录 exec() 执行的时间戳和对应的PID（用户态是PID，内核是tgid）
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();			// 获取当前时间的纳秒级别的时间戳
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	// 当指定了最小持续时间时，直接返回，不要向用户态程序发送数据
	if (min_duration_ns)
		return 0;

	// 从BPF 缓冲区预留样本。即分配空间0: 是标志位，通常为 0。在这里，表示预留空间时没有特殊的标志或选项。
	// 成功返回空间地址，失败NULL
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 让task指向当前进程的的task_struct
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	// 从指定的内核数据结构中读取父进程的进程组 ID（tgid），并将其赋值给 e 结构体中的 ppid 字段。
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// 当前进程的 task_struct 结构体中获取进程的命令名（command name）
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// 从 BPF tracepoint 上下文 (ctx) 中读取文件名，并将其存储到结构体 event 的 filename 字段中。
	fname_off = ctx->__data_loc_filename & 0xFFFF;	// 计算文件名的偏移量。__data_loc_filename 字段通常存储了文件名的偏移量。通过按位与操作 & 0xFFFF，提取出低 16 位的偏移量，并将其赋值给 fname_off 变量。
	// 从不安全的内核地址复制一个以 NULL 结尾的字符串到目标地址，成功返回字符串长度包含NULL字符。出错返回负数 
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	// 将这些数据发送到用户态程序进行处理。
	// 如果在 flags 中指定了 BPF_RB_NO_WAKEUP，则不会发送有关新数据可用性的通知。
	// 如果在 flags 中指定了 BPF_RB_FORCE_WAKEUP，则无条件地发送有关新数据可用性的通知。
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// 跟踪 exit () (使用 SEC("tp/sched/sched_process_exit")以知道每个进程何时退出。
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	// 获取退出线程/进程的 PID 和 TID
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	// 忽略子线程线程退出，只处理主线程
	if (pid != tid)
		return 0;

	// 查找之前存储在 exec_start map 中的进程开始执行的时间戳。
	// 如果找到了时间戳，我们将计算进程的生命周期（持续时间），然后从 exec_start map 中删除该记录。
	// 如果未找到时间戳且指定了最小持续时间，则直接返回。
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	// 如果进程未活得足够长，提前返回
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;


	// 从 BPF 环缓冲区预留样本
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/*
	 * bootstrap大量使用 BPF 环缓冲区映射来准备数据并将数据发送回用户空间。
	 * 它使用bpf_ringbuf_reserve()/bpf_ringbuf_submit()组合以获得最佳的可用性和性能。
	 */

	// 让task指向当前进程的的task_struct
	task = (struct task_struct *)bpf_get_current_task();

	// 填充e
	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// 如下是用户空间执行exit函数，所以内核内需要右移8位恢复
	// 进程退出时候的状态码是 16 位，高 8 位存储退出码，低 8 位存储导致进程退出的信号标志位
	// 测试代码在test_exit_code.c中，exit在/usr/src/glibc/glibc-2.35/stdlib/exit.c
	// _exit在/usr/src/glibc/glibc-2.35/sysdeps/unix/sysv/linux/_exit.c中
	// do_exit源码在/usr/src/linux-source-6.2.0/linux-source-6.2.0/kernel/exit.c
	// 139[0000008b]
	// SYSCALL_DEFINE1(exit, int, error_code)
	// {
	// 	 do_exit((error_code&0xff) << 8);
	// }
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));	// 获取当前任务（进程）的名称（comm）。

	// 发送数据至用户空间以供后续处理
	bpf_ringbuf_submit(e, 0);
	return 0;
}
