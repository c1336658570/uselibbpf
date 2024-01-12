/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Meta */

#define TASK_COMM_LEN 16
#define MAX_STACK_LEN 127

struct task_info {
	pid_t pid;											// 进程 ID
	pid_t tid;											// 线程 ID
	__u32 state;										// 任务状态
	char comm[TASK_COMM_LEN];				// 进程名

	int kstack_len;									// 内核栈长度

	__u64 kstack[MAX_STACK_LEN];		// 内核栈
};
