// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "ringbuf-reserve-submit.skel.h"

// libbpf打印回调函数，用于控制libbpf日志级别
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  // 忽略调试级别的libbpf日志
  if (level > LIBBPF_INFO) {
		return 0;
	}
  return vfprintf(stderr, format, args);
}

// 提升内存锁定限制，确保BPF程序可以创建映射
void bump_memlock_rlimit(void) {
	// 创建一个新的rlimit结构体，用于设置新的内存锁定限制
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,		// 当前进程的软限制设置为无限制
      .rlim_max = RLIM_INFINITY,		// 当前进程的硬限制设置为无限制
  };

	// 尝试设置RLIMIT_MEMLOCK的限制，即提升内存锁定的软和硬限制
  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		// 设置失败时，输出错误消息到标准错误流
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		// 退出程序并返回错误码1
    exit(1);
  }
}

static volatile bool exiting = false;

// 信号处理函数，用于处理Ctrl-C信号
static void sig_handler(int sig) {
	exiting = true;
}

// 处理事件的回调函数，打印事件信息
int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

	// 获取当前时间
  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// 打印事件信息
  printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->comm, e->filename);

  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct ringbuf_reserve_submit_bpf *skel;
  int err;

	// 设置libbpf打印回调函数
  libbpf_set_print(libbpf_print_fn);

	// 提升内存锁定限制
  bump_memlock_rlimit();

	// 注册Ctrl-C信号处理函数
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

	// 加载和验证BPF应用程序
  skel = ringbuf_reserve_submit_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

	// 附加tracepoint 
	err = ringbuf_reserve_submit_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

	// 创建环形缓冲区对象，用于接收事件
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

	// 输出表头信息
	printf("%-8s %-5s %-7s %-16s %s\n", "TIME", "EVENT", "PID", "COMM", "FILENAME");
	// 循环处理事件，直到接收到退出信号
  while (!exiting) {
		// 轮询环形缓冲区，等待事件的到来
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    // Ctrl-C会导致返回-EINTR
    if (err == -EINTR) {
      err = 0;
      break;
    }
		// 处理轮询过程中的错误
    if (err < 0) {
      printf("Error polling ring buffer: %d\n", err);
      break;
    }
  }

cleanup:
	// 释放环形缓冲区和BPF骨架
  ring_buffer__free(rb);
  ringbuf_reserve_submit_bpf__destroy(skel);

	// 返回错误码，如果错误则取负值
  return err < 0 ? -err : 0;
}
