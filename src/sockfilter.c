// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "sockfilter.h"
#include "sockfilter.skel.h"

// 全局环境变量结构体
static struct env {
	const char *interface;			// 网络接口名称
} env;

// 命令行参数文档
const char argp_program_doc[] =
	"BPF socket filter demo application.\n"
	"\n"
	"This program watch network packet of specified interface and print out src/dst\n"
	"information.\n"
	"\n"
	"Currently only IPv4 is supported.\n"
	"\n"
	"USAGE: ./sockfilter [-i <interface>]\n";

// 命令行选项
static const struct argp_option opts[] = {
	{ "interface", 'i', "INTERFACE", 0, "Network interface to attach" },
	{},
};

// 解析命令行参数的回调函数
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i':
		env.interface = arg;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

// 命令行解析器
static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

// IP 协议号到字符串的映射数组
static const char *ipproto_mapping[IPPROTO_MAX] = {
	[IPPROTO_IP] = "IP",	   [IPPROTO_ICMP] = "ICMP",	  [IPPROTO_IGMP] = "IGMP",
	[IPPROTO_IPIP] = "IPIP",   [IPPROTO_TCP] = "TCP",	  [IPPROTO_EGP] = "EGP",
	[IPPROTO_PUP] = "PUP",	   [IPPROTO_UDP] = "UDP",	  [IPPROTO_IDP] = "IDP",
	[IPPROTO_TP] = "TP",	   [IPPROTO_DCCP] = "DCCP",	  [IPPROTO_IPV6] = "IPV6",
	[IPPROTO_RSVP] = "RSVP",   [IPPROTO_GRE] = "GRE",	  [IPPROTO_ESP] = "ESP",
	[IPPROTO_AH] = "AH",	   [IPPROTO_MTP] = "MTP",	  [IPPROTO_BEETPH] = "BEETPH",
	[IPPROTO_ENCAP] = "ENCAP", [IPPROTO_PIM] = "PIM",	  [IPPROTO_COMP] = "COMP",
	[IPPROTO_SCTP] = "SCTP",   [IPPROTO_UDPLITE] = "UDPLITE", [IPPROTO_MPLS] = "MPLS",
	[IPPROTO_RAW] = "RAW"
};

// 创建并绑定原始套接字
static int open_raw_sock(const char *name)
{
	/*
	struct sockaddr_ll {
		unsigned short sll_family;   // 地址家族（Address Family），通常为 AF_PACKET，表示这是一个数据链路层地址。
		__be16 sll_protocol;         // 协议类型，比如 ETH_P_IP、ETH_P_IPV6，使用网络字节序
		int sll_ifindex;             // 网络接口的索引号。是一个整数，用于标识特定的网络接口。可以使用该索引号在系统上唯一地识别和定位网络接口。
		unsigned short sll_hatype;   // 硬件地址类型（Hardware Type），例如 ARPHRD_ETHER 表示以太网硬件地址。
		unsigned char sll_pkttype;   // 包类型，例如 PACKET_HOST、PACKET_BROADCAST，PACKET_HOST 表示是主机生成的包，PACKET_BROADCAST 表示是广播包。
		unsigned char sll_halen;     // 硬件地址长度，即 sll_addr 中硬件地址部分的长度。
		unsigned char sll_addr[8];   // 硬件地址信息，硬件地址的具体内容和长度由前面的字段决定。在以太网场景下，通常是 6 个字节（48 位）的 MAC 地址。
	};
	*/
	struct sockaddr_ll sll;
	int sock;

	/*
	 * family：面向链路层取PF_PACKET；type：SOCK_RAW,接收的帧包含MAC头部信息，发送帧时也要自己加上MAC头部信息；
	 * SOCK_DGRAM，收到的帧无MAC头部信息，已经经过处理，发送时也无需添加头部信息;protocol：
	 * 指定要收发的数据包类型，ETH_P_IP、ETH_P_ARP、ETH_P_RARP、ETH_P_ALL.注意传入参数时候，
	 * 要htons转换，比如(ETH_P_ALL）。
	 */

	// ETH_P_IP 0x800 只接收发往本机mac的ip类型的数据帧
	// ETH_P_ARP 0x806 只接受发往本机mac的arp类型的数据帧
	// ETH_P_RARP 0x8035 只接受发往本机mac的rarp类型的数据帧
	// ETH_P_ALL 0x3 接收发往本机mac的所有类型ip arp rarp的数据帧, 接收从本机发出的所有类型的数据帧.(混杂模式打开的情况下,会接收到非发往本地mac的数据帧)

	// 创建原始套接字
	// PF_PACKET 表示该套接字将用于原始数据链路层访问。面向链路层的原始套接字，可以获取链路层的数据包
	// SOCK_RAW 表示这是一个原始套接字，可以直接处理数据链路层的数据包。
	// SOCK_NONBLOCK: 表示将套接字设置为非阻塞模式，这样套接字操作将不会阻塞整个程序。
	// SOCK_CLOEXEC: 表示在进程执行 exec 函数时，套接字会被自动关闭。这是一种提高程序健壮性的做法，确保在执行新程序时不会保留未关闭的套接字。
	// htons(ETH_P_ALL): 是对数据链路层协议类型的指定，htons 函数用于将主机字节序转换为网络字节序。ETH_P_ALL 表示捕获所有类型的数据包，即协议类型为所有值的数据包。
	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	// 初始化套接字地址结构
	// sockaddr_ll结构体表示的是一个与物理设备无关的物理层地址
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;									// AF_PACKET 表示数据链路层地址。
	sll.sll_ifindex = if_nametoindex(name);			// 使用 if_nametoindex 函数获取网络接口名对应的索引号。
	sll.sll_protocol = htons(ETH_P_ALL);				// 设置协议类型为 ETH_P_ALL，表示捕获所有类型的数据包。
	// 绑定原始套接字
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

// libbpf 的打印回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 将整数 IP 地址转换为字符串表示
static inline void ltoa(uint32_t addr, char *dst)
{
	snprintf(dst, 16, "%u.%u.%u.%u", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
		 (addr >> 8) & 0xFF, (addr & 0xFF));
}

// 处理事件的回调函数。一个上下文指针（ctx）、一个指向事件数据的指针（data）以及数据的大小（data_sz）。
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;
	// 存储接口名称、源 IP 地址字符串、目标 IP 地址字符串的数组
	char ifname[IF_NAMESIZE];
	char sstr[16] = {}, dstr[16] = {};

	/*
	PACKET_HOST （默认） - 寻址到本地主机的数据包。
	PACKET_BROADCAST - 物理层广播的数据包。
	PACKET_MULTICAST - 发送到物理层多播地址的数据包。
	PACKET_OTHERHOST - 被（处于混杂模式的）网卡驱动捕获的、发送到其他主机的数据包。
	PACKET_OUTGOING - 来自本地主机的、回环到一个套接字的数据包。
	*/
	// 仅处理主机接收的数据包，过滤掉其他类型的数据包。
	if (e->pkt_type != PACKET_HOST)
		return 0;

	// 确保 IP 协议号在有效范围内
	if (e->ip_proto < 0 || e->ip_proto >= IPPROTO_MAX)
		return 0;

	// 获取接口名称
	if (!if_indextoname(e->ifindex, ifname))
		return 0;

	// 将源、目标 IP 地址转换为字符串表示
	ltoa(ntohl(e->src_addr), sstr);
	ltoa(ntohl(e->dst_addr), dstr);

	// 打印事件信息
	printf("interface: %s\tprotocol: %s\t%s:%d(src) -> %s:%d(dst)\n", ifname,
	       ipproto_mapping[e->ip_proto], sstr, ntohs(e->port16[0]), dstr, ntohs(e->port16[1]));

	return 0;
}

// 退出标志，用于优雅地退出程序
static volatile bool exiting = false;

// 信号处理函数，设置退出标志
static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	/*
	struct sockfilter_bpf {
		// 指向 BPF 对象骨架的指针
		struct bpf_object_skeleton *skeleton;
		// 指向 BPF 对象的指针
		struct bpf_object *obj;
		// 存储 BPF 程序使用的映射（map）结构
		struct {
				struct bpf_map *rb;  // 环形缓冲区（ring buffer）映射
		} maps;
		// 存储 BPF 程序的结构
		struct {
				struct bpf_program *socket_handler;  // 套接字处理程序
		} progs;
		// 存储 BPF 程序链接的结构
		struct {
				struct bpf_link *socket_handler;  // 套接字处理程序的链接
		} links;
	}
	*/
	struct sockfilter_bpf *skel;
	int err, prog_fd, sock;

	// 设置默认网络接口名称为 "lo"
	env.interface = "lo";
	// 解析命令行参数
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return -err;

	// 设置 libbpf 的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 注册 Ctrl-C 信号处理函数
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 加载和验证 BPF 程序
	skel = sockfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// 创建环形缓冲区
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// 创建本地主机的原始套接字
	sock = open_raw_sock(env.interface);
	if (sock < 0) {
		err = -2;
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}

	// 将 BPF 程序附加到原始套接字
	prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	// 处理事件
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// Ctrl-C 会导致返回 -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}

cleanup:
	// 释放资源
	ring_buffer__free(rb);
	sockfilter_bpf__destroy(skel);
	return -err;
}
