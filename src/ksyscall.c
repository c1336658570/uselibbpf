#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ksyscall.skel.h"

// 回调函数，用于打印libbpf的错误和调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 用于优雅停止BPF程序的信号标志
static volatile sig_atomic_t stop;

// 信号处理函数，在收到SIGINT（Ctrl+C）时设置停止标志
static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct ksyscall_bpf *skel;
	int err;

	// 设置libbpf的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 打开、加载并验证BPF应用程序
	skel = ksyscall_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 附加跟踪点处理程序
	err = ksyscall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// 为SIGINT（Ctrl+C）设置信号处理程序
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	// 主循环模拟守护进程，定期打印一个点并休眠
	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	// 销毁资源
	ksyscall_bpf__destroy(skel);
	return -err;
}
