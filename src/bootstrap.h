/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;																// 进程 ID
	int ppid;																// 父进程 ID
	unsigned exit_code;											// 退出码
	unsigned long long duration_ns;					// 进程生命周期持续时间（纳秒）
	char comm[TASK_COMM_LEN];								// 进程名（进程的命令名）
	char filename[MAX_FILENAME_LEN];				// 文件名（相关进程执行的文件名）
	bool exit_event;												// 标识是否为进程退出事件
};

#endif /* __BOOTSTRAP_H */
