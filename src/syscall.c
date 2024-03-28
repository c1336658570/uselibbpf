#include <stdio.h>
#include <unistd.h>
#include <argp.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <time.h>
#include "syscall.skel.h"
#include "./syscallnumber.h"
#include <asm/unistd.h>
#include <asm-generic/unistd.h>
#include <poll.h>
#include <fcntl.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct syscall_event {
	int pid; // pid
	long nr; // 系统调用号
	char comm[TASK_COMM_LEN]; // 进程名称
	__u64 runtime; // 系统调用运行时间
};

static struct env {
	bool verbose; // 是否启用详细的调试输出
	int pid; // 指定的pid
	char threshold[22]; //触发阈值
    time_t tm_s;
} env;

// argp 配置
const char *argp_program_version = "syscall 1.0";
const char *argp_program_bug_address = "<1285719445@qq.com>";
const char argp_program_doc[] =
	"BPF syscall application.\n"
	"\n"
	"It traces the initiation and termination of process system calls \n"
	"You can filter the pid and modify the trigger threshold to display it at an appropriate time. \n"
	"The information it outputs includes  PID command syscall_number, syscall_name and syscall runtime\n"
	"USAGE: ./syscall [-p <pid>] [-s 'some/full xxx' ] [-t time_s] [-v]\n";

// 命令行选项
// 选项的长名称，“-name”形式		选项的短名称的 ASCII 码		如果非 0，为选项的参数名
// 如果非 0，为选项的标志。OPTION_ALIAS 表示当前选项是前一个选项的别名			选项说明
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "pid", 0, "Monitor system calls of the specified PID process." },
	{ "psi", 's', "'some/full xxx(<1000000us)'", 0,
	  "Set the threshold of PSI (Pressure Stall Information)\n to adjust the intensity of triggering\nsuch as: -s 'some 100'\ndefault:some 100000us in 1sec" },
	{ "time", 't', "time_s", 0, "Set the runtime of the BPF program."},
    {}
};

char trig[22] = "some 100000 1000000"; //最大需要22个字符

// argp 解析器回调
// key 参数：表示当前解析到的选项的键值。根据 switch 语句中的不同情况，对不同的选项进行处理。对于短选项（例如 -v），它是字符的 ASCII 值（在这种情况下，'v'）。对于长选项（例如 --verbose），它是在 argp_option 结构体中为这个选项指定的值。还有一些预定义的键值（例如 ARGP_KEY_ARG 或 ARGP_KEY_END），它们表示特定的解析事件而不是特定的选项。
// arg 参数：如果选项带有参数，这个参数表示选项的参数值。处理 -v -p -s 选项，如果当前处理的参数没有关联值，arg 将为 NULL。
// state 参数：是 argp 解析状态的指针，用于与整个解析过程进行交互。包含了解析过程的一些信息，如程序名、argp 结构等。
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true; // 启用verbose
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) { // 无效pid
			// 处理无效的pid参数
			fprintf(stderr, "Invalid duration: %s\n", arg);
			// 用于输出关于如何使用程序的信息，然后退出程序。
			// state: 指向一个 argp_state 结构的指针，该结构包含了 argp 的解析状态。这通常是在 argp 的解析函数中被传入的。
			argp_usage(state); // 显示用法信息并退出程序
		}
		break;
	case 's':
		strcpy(env.threshold, arg);
		char keyword[100];
		int value;
		// 解析输入
		sscanf(env.threshold, "%s %d", keyword, &value);
		// 根据关键字更新全局字符串
		if (strcmp(keyword, "some") == 0) {
			snprintf(trig, sizeof(trig), "some %d 1000000", value);
		} else if (strcmp(keyword, "full") == 0) {
			snprintf(trig, sizeof(trig), "full %d 1000000", value);
		} else {
			argp_usage(state); // 显示用法信息并退出程序
		}
		break;
    case 't':
        env.tm_s = strtol(arg, NULL, 10);
        if (env.tm_s < 0) {
            // 处理无效的pid参数
			fprintf(stderr, "Invalid duration: %s\n", arg);
			// 用于输出关于如何使用程序的信息，然后退出程序。
			// state: 指向一个 argp_state 结构的指针，该结构包含了 argp 的解析状态。这通常是在 argp 的解析函数中被传入的。
			argp_usage(state); // 显示用法信息并退出程序
        }
        break;
	case ARGP_KEY_ARG:
		argp_usage(state); // 处理未知的额外参数，显示用法信息并退出程序
		break;
	default:
		return ARGP_ERR_UNKNOWN; // 处理未知的选项，返回未知错误码
	}
	return 0;
}

// argp 结构
static const struct argp argp = {
	.options = opts, // 指定要解析的选项，为 0 时没有选项
	.parser = parse_arg, // 解析选项的函数，为 0 时不解析选项
	.doc = argp_program_doc, // 程序说明，为 0 时没有程序说明
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
	//打印输出
	printf("pid=%-8d  comm=%-21ssyscall_number=%-8ld  syscall_name=%-16s	syscall_runtime_ns=%-8llu\n",
	       event->pid, event->comm, event->nr, syscall_name[event->nr], event->runtime);
}

// 创建一个timerfd文件描述符
int createTimerfd()
{
	// 使用::timerfd_create函数创建一个定时器文件描述符，时钟类型为CLOCK_MONOTONIC，选项为TFD_NONBLOCK和TFD_CLOEXEC
	// CLOCK_MONOTONIC表示使用单调时钟，不受系统时间调整的影响。
	// TFD_NONBLOCK将文件描述符设置为非阻塞模式，使得对timerfd的读写操作变为非阻塞。
	// TFD_CLOEXEC在exec函数调用时关闭文件描述符，防止子进程继承。
	int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	// 检查timerfd_create是否成功，若失败则输出错误信息并终止程序
	if (timerfd < 0) {
		printf("Failed in timerfd_create");
	}
	return timerfd; // 返回创建的timerfd文件描述符
}

typedef struct time_struct {
	int timerfd;
	void (*func)(int);
} time_struct;

// 从timerfd文件描述符读取数据，处理定时器到期事件
void readTimerfd(int timerfd) {
  // 用于存储从timerfd中读取的数据
  uint64_t howmany;
  // 从timerfd中读取数据，将结果存储在howmany变量中
  // read从fd中读取1个无符号8byte整型（uint64_t，主机字节序，存放当buf中），表示超时的次数。
  // 如果没有超时，read将会阻塞到下一次定时器超时，或者失败（errno设置为EAGAIN，fd设置为非阻塞）。
  // 另外，如果提供的buffer大小 < 8byte，read将返回EINVAL。read成功时，返回值应为8。
  ssize_t n = read(timerfd, &howmany, sizeof(howmany));
  // 检查读取的数据量是否为8字节，若不是则输出错误日志
  if (n != sizeof(howmany)) {
    printf("readTimerfd reads %ld bytes instead of 8",n);
  }
}

void handle_timer(int timerfd) {
    readTimerfd(timerfd);
    stop = 1;
    printf("exit");

}

void set_timer_fd(int timerfd) {
    // 唤醒EventLoop，通过timerfd_settime()函数设置新的定时器到期时间
    struct itimerspec newValue;       // 用于存储新的定时器配置
    struct itimerspec oldValue;       // 用于存储旧的定时器配置

    // 将newValue和oldValue结构体清零
    bzero(&newValue, sizeof(newValue));
    bzero(&oldValue, sizeof(oldValue));

    newValue.it_value.tv_sec = env.tm_s;    // 设置新的定时器到期时间

    // 使用timerfd_settime()函数设置新的定时器到期时间，并将旧的定时器到期时间存储在oldValue中
    int ret = timerfd_settime(timerfd, 0, &newValue, &oldValue);
    // 检查timerfd_settime是否成功，若失败则输出系统错误信息
    if (ret) {
        printf("timerfd_settime()");
    }
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

	struct pollfd fds[2];
	int n;
	//监测是否到达阈值
	fds[0].fd = open("/proc/pressure/memory", O_RDWR | O_NONBLOCK);
	if (fds[0].fd < 0) {
		printf("/proc/pressure/memory open error: %s\n", strerror(errno));
		return 1;
	}
	fds[0].events = POLLPRI;
	char keyword[100];
	int value;
	sscanf(trig, "%s %d", keyword, &value);
	printf("psi threshold: %s \nThe %s threshold is exceeded within 1 second and within %d milliseconds.\n",
	       trig, keyword, value); // 每次都会输出以确认，默认数值为
	if (write(fds[0].fd, trig, strlen(trig) + 1) < 0) {
		printf("/proc/pressure/memory write error: %s\n", strerror(errno));
		return 1;
	}

    int num_pollfd = 1;     // 要监听的文件描述符的个数

    time_struct struct_timer;
    if (env.tm_s > 0) {
        struct_timer.timerfd = createTimerfd();
        struct_timer.func = handle_timer;
        set_timer_fd(struct_timer.timerfd);
        fds[1].fd = struct_timer.timerfd;
        fds[1].events = POLLIN;
        ++num_pollfd;
    }

	printf("waiting for events...\n");
	while (!stop) {
		n = poll(fds, num_pollfd, -1);
		if (n < 0) {
			printf("poll error: %s\n", strerror(errno));
			return 1;
		}
		if (fds[0].revents & POLLERR) {
			printf("got POLLERR, event source is gone\n");
			return 0;
		}
		if (fds[0].revents & POLLPRI) { //到达阈值后的处理
			printf("event triggered!\n");

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
        if (env.tm_s > 0) {
            if (fds[1].revents & POLLIN) {
                fds[1].revents &= ~POLLIN;
                struct_timer.func(struct_timer.timerfd);
            }
        }
	}

cleanup:
	// 销毁BPF程序的上下文。清除所有资源(包括内核和用户空间中的资源)。
	syscall_bpf__destroy(skel);
	return -err;
}