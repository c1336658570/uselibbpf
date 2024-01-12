// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

// BPF程序入口函数，处理Traffic Control（流量控制）层的入站流量
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	// 获取数据包的起始和结束位置
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	// 定义数据链路层头部和网络层头部的指针
	struct ethhdr *l2;
	struct iphdr *l3;

	// 检查协议是否为IPv4，如果不是则直接返回
	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	// 解析数据链路层头部
	l2 = data;
	// 检查数据链路层头部是否越界，如果是则返回
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	// 解析网络层头部（IPv4头部）
	l3 = (struct iphdr *)(l2 + 1);
	// 检查网络层头部是否越界，如果是则返回
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	// 打印收到的IPv4数据包信息，包括总长度和TTL值
	bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);

	// 返回Traffic Control层的处理成功标志
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
