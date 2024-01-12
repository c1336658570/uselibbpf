// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

// sudo ./bootstrap -d 100只显示存在至少100ms 的进程
// 详细模式标志(尝试 sudo ./bootstrap -v) ，启用 libbpf 调试日志。

// 定义了一个 env 结构，用于存储命令行参数
static struct env {
	bool verbose;							// 是否启用详细的调试输出
	long min_duration_ms;			// 报告的最小进程持续时间（毫秒）
} env;

// argp 配置，使用 argp 库来解析命令行参数
const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF bootstrap demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

// 命令行选项
// 选项的长名称，“-name”形式		选项的短名称的 ASCII 码		如果非 0，为选项的参数名
// 如果非 0，为选项的标志。OPTION_ALIAS 表示当前选项是前一个选项的别名			选项说明
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
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
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {		// 无效时间
			// 处理无效的时间参数
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


// libbpf 的错误和调试信息回调
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
// 信号处理函数，处理SIGINT和SIGTERM
static void sig_handler(int sig)
{
	exiting = true;
}

// 处理 BPF 事件的回调
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	// 获取当前时间
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	// 将时间转换为可读的格式（时:分:秒）
	tm = localtime(&t);
	// 使用 strftime 函数，该函数用于将时间信息格式化为字符串，并将结果存储在指定的缓冲区中。
	// %H：%M：%S，时分秒
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// 根据事件类型输出不同格式的信息
	if (e->exit_event) {
		// 如果是进程退出事件
		printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
		// 如果存在持续时间信息，输出毫秒数
		if (e->duration_ns) {
			printf(" (%llums)", e->duration_ns / 1000000);
		}
		printf("\n");
	} else {
		// 如果是进程执行事件
		printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
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

	// 设置 libbpf 的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 处理信号(ctrl + c)
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开 eBPF 脚手架（skeleton）文件
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/**
	 * 初始化min_duration_ns只读全局变量。需要在将 BPF 框架加载到内核之前对它们进行设置。
	 * 因此，我们不需要使用单步 bootstrap_bpf__open_and_load(), 而是需要首先分别bootstrap_bpf__open()框架，
	 * 设置只读变量值，然后引导bootstrap_bpf__load()框架到内核
	 * 
	 * 加载 BPF 框架后，用户空间代码只能读取只读变量的值。BPF 代码也只能读取这些变量。
	 * 如果 BPF 验证程序检测到试图写入此类变量，则 BPF 验证程序将拒绝该 BPF 程序。
	*/

	// 通过最小持续时间参数对 BPF 代码进行参数化，只有超过最小持续时间的进程我们才收集它的退出数据，未设置最小持续时间的话，什么数据都不收集
	// 将最小持续时间参数传递给 eBPF 程序
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	// 加载和验证 BPF 程序
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// 附加跟踪点
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 创建一个环形缓冲区（ring buffer），用于接收 eBPF 程序发送的事件数据
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// 处理事件
	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID",
	       "FILENAME/EXIT CODE");
	while (!exiting) {
		// 使用 ring_buffer__poll() 函数轮询环形缓冲区，处理收到的事件数据
		err = ring_buffer__poll(rb, 100 /* 超时，毫秒 */);
		// Ctrl-C 将导致 -EINTR
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
	// 清理资源
	// 当程序收到 SIGINT 或 SIGTERM 信号时，它会最后完成清理、退出操作，关闭和卸载 eBPF 程序
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
