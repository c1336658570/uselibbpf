#include <stdio.h>
#include <unistd.h>
#include <argp.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "syscall.skel.h"
#include "./syscallnumber.h"
#include <asm/unistd.h>
#include <asm-generic/unistd.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct syscall_event {
  int pid;                        // pid
  long nr;                        // 系统调用号
  char comm[TASK_COMM_LEN];				// 进程名称
  __u64 runtime;                    // 系统调用运行时间
};

static struct env {
	bool verbose;							// 是否启用详细的调试输出
	int pid;									// 指定的pid
} env;

// argp 配置
const char *argp_program_version = "syscall 0.0";
const char *argp_program_bug_address = "<1285719445@qq.com>";
const char argp_program_doc[] = "BPF syscall application.\n"
				"\n"
				"It traces the initiation and termination of process system calls \n"
				"displaying relevant information such as filenames and the duration of system calls\n"
				"\n"
				"USAGE: ./syscall [-p <pid>] [-v]\n";

// 命令行选项
// 选项的长名称，“-name”形式		选项的短名称的 ASCII 码		如果非 0，为选项的参数名
// 如果非 0，为选项的标志。OPTION_ALIAS 表示当前选项是前一个选项的别名			选项说明
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "pid", 0, "Monitor system calls of the specified PID process." },
	{},
};

// argp 解析器回调
// key 参数：表示当前解析到的选项的键值。根据 switch 语句中的不同情况，对不同的选项进行处理。对于短选项（例如 -v），它是字符的 ASCII 值（在这种情况下，'v'）。对于长选项（例如 --verbose），它是在 argp_option 结构体中为这个选项指定的值。还有一些预定义的键值（例如 ARGP_KEY_ARG 或 ARGP_KEY_END），它们表示特定的解析事件而不是特定的选项。
// arg 参数：如果选项带有参数，这个参数表示选项的参数值。在这里，主要用于处理 -d 选项，表示最小持续时间。如果当前处理的参数没有关联值，arg 将为 NULL。
// state 参数：是 argp 解析状态的指针，用于与整个解析过程进行交互。包含了解析过程的一些信息，如程序名、argp 结构等。
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;		// 启用verbose
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {		// 无效pid
			// 处理无效的pid参数
			fprintf(stderr, "Invalid duration: %s\n", arg);
			// 用于输出关于如何使用程序的信息，然后退出程序。
			// state: 指向一个 argp_state 结构的指针，该结构包含了 argp 的解析状态。这通常是在 argp 的解析函数中被传入的。
			argp_usage(state);		// 显示用法信息并退出程序
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);			 // 处理未知的额外参数，显示用法信息并退出程序
		break;
	default:
		return ARGP_ERR_UNKNOWN;		// 处理未知的选项，返回未知错误码
	}
	return 0;
}

// argp 结构
static const struct argp argp = {
	.options = opts,						// 指定要解析的选项，为 0 时没有选项
	.parser = parse_arg,				// 解析选项的函数，为 0 时不解析选项
	.doc = argp_program_doc,		// 程序说明，为 0 时没有程序说明
};

// 回调函数，用于打印libbpf错误和调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}
static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
    stop = 1;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
  const struct syscall_event *event = data;
	
	printf("pid=%-8d  comm=%-16s  syscall_number=%-8ld  syscall_name=%-16s	syscall_runtime_ns=%-8llu\n", event->pid, event->comm, event->nr, syscall_name[event->nr], event->runtime);
}

int main(int argc, char **argv)
{
	// 创建BPF程序的上下文
	struct syscall_bpf *skel;
	int err;

	// 解析命令行参数
	/*
	 * &argp：传递一个指向 argp 结构的指针，该结构定义了命令行选项和参数的信息，以及解析时的回调函数。
	 * argc：是命令行参数的数量，即 main 函数的 argc 参数。
	 * argv：是一个指向包含命令行参数的字符串数组的指针，即 main 函数的 argv 参数。
	 * 0：控制解析的行为的标志。在这里，0 表示默认的行为，即不进行额外的处理。
	 * NULL：可选的环境指针，用于在解析期间传递额外的信息。在这里，没有传递额外的信息，因此为 NULL。
	 * NULL：可选的回调数据指针，用于在回调函数中传递额外的信息。在这里，没有传递额外的信息，因此为 NULL。
	 * err：是一个整数变量，用于存储 argp_parse 函数的返回值，表示解析的结果。如果解析成功，返回值为 0，否则为非零错误码。
	 */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	// 设置libbpf错误和调试信息的回调函数
	libbpf_set_print(libbpf_print_fn);

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}
	if (signal(SIGTERM, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	// 打开BPF程序，创建BPF程序的上下文
	skel = syscall_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 确保BPF程序仅处理来自我们指定进程的系统调用
	skel->bss->pid_target = env.pid;

	// 加载并验证BPF程序
	err = syscall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 附加tracepoint处理程序
	/*
	 * 将现在已经在内核中等待的handle_tp BPF 程序附加到相应的内核跟踪点。这将“激活”BPF 程序，
	 * 内核将开始在内核上下文中执行我们的定制 BPF 代码，以响应每次 write ()系统调用！
	 */
	err = syscall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

  struct perf_buffer *pb = NULL;
  pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8, handle_event, NULL, NULL, NULL);
  
  while (!stop) {
      err = perf_buffer__poll(pb, 100);
		// Ctrl-C 将导致 -EINTR，因为在perf_buffer__poll中会调用libbpf_err，它将errno设置为-errno 
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
  }

cleanup:
	// 销毁BPF程序的上下文。清除所有资源(包括内核和用户空间中的资源)。
	syscall_bpf__destroy(skel);
	return -err;
}