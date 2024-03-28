#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include "bpf/libbpf.h"
#include "usage_bk.skel.h"

#define TASK_COMM_LEN 16
#define u64	      long long int
const u64 INTERVAL = 5000000000; // 5秒对应的纳秒数
u64 mytime_st = 0; //计时器开始时间
u64 mytime_now = 0;
int flag = 0; //记录输出次数 0/奇数改now 偶数改st

struct mmd //存储各进程信息
{
	u64 tid;
	u64 cpu_id;
	u64 pid; // 进程的PID
	u64 start_t; //进程开始的时间
	u64 used_t; //已经使用的CPU时间
	u64 total_t; //每个cpu占用的总时间
	u64 occ; //占用率
	char comm[TASK_COMM_LEN];
	//long unsigned int resident;
};
int i = 0;
struct mmd my_data[200];

struct event {
	u64 tid;
	u64 cpu_id;
	u64 pid;
	u64 start_t;
	u64 used_t; //已经使用的CPU时间
	u64 total_t;
	u64 occ;
	char comm[TASK_COMM_LEN];
};

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

//取消内核内存限制
void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
	//更新+错误处理
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to relimit OS source");
		exit(1);
	}
}

//处理CTRL-C
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}
//保存在文件里
void save_data_to_file(const struct event *data, int size)
{
	FILE *file;
	char filename[256];
	snprintf(filename, sizeof(filename), "D:/333333/cando/output.txt");

	file = fopen(filename, "a"); // 打开文件，"a" 表示以追加方式打开文件
	if (!file) {
		perror("Failed to open file");
		return;
	}

	for (int i = 0; i < size; i++) {
		fprintf(file, "TID: %lld, PID: %llu, Command: %s, Cputime: %lld\n", data[i].tid,
			data[i].pid, data[i].comm, data[i].occ);
	}

	fclose(file);
}

//排序函数，按照total_time降序排序
void tid_sort(struct mmd data[])
{
	for (int p = 0; p < 199; p++) {
		for (int q = p + 1; q < 200; q++) {
			if (data[p].used_t < data[q].used_t) {
				int temp_pid = data[p].pid;
				int temp_tid = data[p].tid;
				char str[TASK_COMM_LEN];
				strcpy(str, data[p].comm);

				data[p].pid = data[q].pid;
				data[p].tid = data[q].tid;
				strcpy(data[p].comm, data[q].comm);

				data[q].pid = temp_pid;
				data[q].tid = temp_tid;
				strcpy(data[q].comm, str);

				int temp_occ = data[p].occ;
				data[p].occ = data[q].occ;
				data[q].occ = temp_occ;

				//int temp_res = data[p].resident;
				//data[p].resident = data[q].resident;
				//data[q].resident = temp_res;
			}
		}
	}
}

//按tid输出函数
void myprint_tid(struct mmd data[], int w) //p是时间差 用来计算占用率
{
	printf("TID			PID	 		Command	 	Cputime\n");
	for (int n = 0; n < 16; n++) {
		if (data[n].pid != 0 && w != 0) {
			data[n].occ = data[n].used_t / (w * 1000000000);
			for (int x = 0; x < n; x++) {
				if ((data[x].pid == data[n].pid) &&
				    (data[x].cpu_id != data[n].cpu_id)) {
					data[x].occ += data[n].occ;
					break; // 找到相同pid的项且cpu_id不相同，累加后跳出循环
				}
			}
			printf("%10llu	(%5llu) 	%16s	%5lld\n", data[n].tid, data[n].pid,
			       data[n].comm, data[n].occ);
		}
	}
}

//回调处理函数
int ringbuf_event_handler(void *ctx, void *data, size_t data_sz)
{
	const struct event *md = data;
	my_data[i].cpu_id = md->cpu_id;
	my_data[i].pid = md->pid;
	my_data[i].tid = md->tid;
	my_data[i].used_t = md->used_t;
	strcpy(my_data[i].comm, md->comm);
	//my_data[i].resident = md->resident;
	// printf("%10llu	(%5llu) 	%20s	%5lld\n", my_data[i].tid, my_data[i].pid,
	//        my_data[i].comm, my_data[i].used_t);
	time_t timep; //1970年到当前的秒数
	mytime_now = time(&timep); //获取当前时间戳
	u64 time_de = mytime_now - mytime_st;
	if (time_de >= 5) {
		tid_sort(my_data);
		myprint_tid(my_data, time_de);
		flag = 1;
		mytime_st = time(&timep); //修改起始时间，重新开始计时
		time_de = 0;
		i++;
	} else {
		i++;
		flag = 0;
	}
	if (i == 200)
		i = 0;
	return 0;
}

//主逻辑
int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	//通过${apps}.skel.h操作控制交互内核态程序
	struct usage_bk_bpf *skel;
	int err;
	//logs
	libbpf_set_print(libbpf_print_fn);
	//os settings
	bump_memlock_rlimit();
	//Clean handling
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	//---------------------------------------------------------------
	//加载，验证ebpf内核态程序
	skel = usage_bk_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and verify BPF skeleton");
		return -1;
	}

	//挂载
	err = usage_bk_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton");
		goto cleanup; //良好习惯清理资源
	}

	/*-----------------------ringbuffer操作部分--------------------*/
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), ringbuf_event_handler, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	//int a = 10;
	while (1) {
		err = ring_buffer__poll(rb, -1);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	usage_bk_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
