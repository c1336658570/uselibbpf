// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#ifndef __SOCKFILTER_H
#define __SOCKFILTER_H

struct so_event {
	__be32 src_addr;			// 源 IP 地址，使用大端序表示
	__be32 dst_addr;			// 目标 IP 地址，使用大端序表示
	union {
		__be32 ports;				// 32 位字段，表示端口信息
		__be16 port16[2];		// 包含两个 16 位字段的数组，用于表示端口信息
	};
	__u32 ip_proto;				// IP 协议号，表示传输层使用的协议，如 TCP 或 UDP
	__u32 pkt_type;				// 包类型，用于表示数据包的类型，可能是广播、单播等
	__u32 ifindex;				// 接口索引，表示数据包经过的网络接口的索引号
};

#endif /* __SOCKFILTER_H */
