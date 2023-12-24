#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "perfbuf-output.skel.h"

// libbpf打印回调函数，用于控制libbpf日志级别
int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                    va_list args) {
  // 忽略调试级别的libbpf日志
  if (level > LIBBPF_INFO) return 0;
  return vfprintf(stderr, format, args);
}

// 提升内存锁定限制，确保BPF程序可以创建映射
void bump_memlock_rlimit(void) {
  // 创建一个新的rlimit结构体，用于设置新的内存锁定限制
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,  // 当前进程的软限制设置为无限制
      .rlim_max = RLIM_INFINITY,  // 当前进程的硬限制设置为无限制
  };

  // 尝试设置RLIMIT_MEMLOCK的限制，即提升内存锁定的软和硬限制
  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    // 退出程序并返回错误码 1
    exit(1);
  }
}

static volatile bool exiting = false;

// 信号处理函数，用于处理Ctrl-C退出
static void sig_handler(int sig) { exiting = true; }

// 处理事件的回调函数，打印事件信息
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  const struct event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->comm, e->filename);
}

int main(int argc, char **argv) {
  struct perf_buffer *pb = NULL;
  // struct perf_buffer_opts pb_opts = {};
  struct perfbuf_output_bpf *skel;
  int err;

  // 设置libbpf打印回调函数
  libbpf_set_print(libbpf_print_fn);

  // 提升内存锁定限制
  bump_memlock_rlimit();

  // 注册Ctrl-C信号处理函数
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // 加载和验证BPF应用程序
  skel = perfbuf_output_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  // 附加tracepoint
  err = perfbuf_output_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

// 注释部分已经被弃用
#if 0
	/* Set up ring buffer polling */
	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8 /* 32KB per CPU */, &pb_opts);
	if (libbpf_get_error(pb)) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}
#endif
  // 创建性能缓冲区对象，用于接收事件
  pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8, handle_event, NULL, NULL,
                        NULL);

  // 输出表头信息
  printf("%-8s %-5s %-7s %-16s %s\n", "TIME", "EVENT", "PID", "COMM",
         "FILENAME");

  // 循环处理事件，直到接收到退出信号
  while (!exiting) {
    // 轮询性能缓冲区，等待100毫秒
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
    // Ctrl-C会导致返回-EINTR
    if (err == -EINTR) {
      err = 0;
      break;
    }
    // 处理轮询过程中的错误
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  // 释放性能缓冲区和BPF骨架
  perf_buffer__free(pb);
  perfbuf_output_bpf__destroy(skel);

  // 返回错误码，如果错误则取负值
  return err < 0 ? -err : 0;
}
