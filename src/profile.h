/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

// 定义保存堆栈跟踪信息的数据结构，包括进程ID、CPU ID、进程名称、内核堆栈大小、用户态堆栈大小
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event {
	__u32 pid;											// 进程ID
	__u32 cpu_id;										// CPU ID
	char comm[TASK_COMM_LEN];				// 进程名称
	__s32 kstack_sz;								// 内核堆栈大小
	__s32 ustack_sz;								// 用户态堆栈大小
	stack_trace_t kstack;						// 内核堆栈
	stack_trace_t ustack;						// 用户态堆栈
};

#endif /* __PROFILE_H_ */
