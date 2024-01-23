#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

struct alloc_info {
	__u64 size;
	int stack_id;
};

/* 为了节省内存和方便整形数据的原子操作,把 combined_alloc_info 定义为联合体
 * 其中 total_size 占 40bit, number_of_allocs 占 24bit, 联合体总大小为 64bit
 * 2个combined_alloc_info联合体的 bits 字段相加, 相当于对应的 total_size 相加, 
 * 和对应的 number_of_allocs 相加;
 */
union combined_alloc_info {
	struct {
		__u64 total_size : 40;
		__u64 number_of_allocs : 24;
	};
	__u64 bits;
};

#endif /* __MEMLEAK_H */