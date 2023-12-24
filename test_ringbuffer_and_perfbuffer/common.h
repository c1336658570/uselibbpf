#ifndef __COMMON_H
#define __COMMON_H

// 定义用于表示跟踪条目的结构体
struct trace_entry {
  short unsigned int type;      // 跟踪条目的类型
  unsigned char flags;          // 与跟踪条目关联的标志
  unsigned char preempt_count;  // 抢占计数
  int pid;                      // 与跟踪条目关联的进程ID
};

// sched_process_exec跟踪点的上下文结构体
struct trace_event_raw_sched_process_exec {
  struct trace_entry ent;            // 跟踪条目信息
  unsigned int __data_loc_filename;  // 文件名数据位置
  int pid;                           // 进程ID
  int old_pid;                       // 旧进程ID
  char __data[0];                    // 变长数据数组（文件名内容）
};

#define TASK_COMM_LEN 16      // 任务命令（进程名）的最大长度
#define MAX_FILENAME_LEN 512  // 文件名的最大长度

// 从BPF程序发送到用户空间的示例的定义
struct event {
  int pid;                          // 进程ID
  char comm[TASK_COMM_LEN];         // 任务命令（进程名）
  char filename[MAX_FILENAME_LEN];  // 文件名
};

#endif /* __COMMON_H */
