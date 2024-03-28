# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/)
LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
# ARCH 捕获主机操作系统 体系结构，该体系结构随后被传递到 BPF 代码编译步骤，以便与低级跟踪 helper 宏一起使用(在 libbpf 的 bpf_tracing.h中)。
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
#使用我们自己的 libbpf API 标头和分发的 Linux UAPI 标头
#libbpf 以避免对系统范围标头的依赖，这些标头可能会丢失或
#过时的
# -I$(OUTPUT)		所有中间文件都将在 .output/子目录，因此该目录被添加到 c 编译器的 include 路径中，以查找 BPF 框架和 libbpf 头文件。
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC)
# 所有用户空间文件都使用调试信息(-g)进行编译，并且没有进行任何优化，以便更容易地进行调试。
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# 这是一个可用的应用程序列表。如果您复制/粘贴minimal或bootstrap并创建自己的副本，只需在这里添加应用程序的名称即可构建。每个应用程序都定义了相应的 make 目标
APPS = syscall minimal minimal_legacy bootstrap uprobe kprobe fentry usdt sockfilter tc ksyscall task_iter memleakv1 pidmm1 usage usage_bk

CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := profile memleakv2 memleak
APPS += $(BZS_APPS)
# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
# 将 libbpf 构建为静态库，并将其 API 头安装到 .output/
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap


$(LIBBLAZESYM_SRC)/target/release/libblazesym.a::
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --release

$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/release/libblazesym.a | $(OUTPUT)
	$(call msg,LIB, $@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/libblazesym.a $@

# Build BPF code
# 将 BPF c 代码(*.BPF.c)构建成一个编译后的对象文件
# -g 是强制要求 Clang 发出 BTF 信息。-o2 对于 BPF 的编译也是必要的。-D__TARGET_ARCH_$(ARCH)定义了bpf_tracing.h 头部处理struct pt_regs 的必要宏。如果你不处理 kprobes 和 struct pt_regs，则可以忽略这一点。最后，我们从生成的.o 文件中去除 DWARF 信息，因为它从来没有被使用过，大多数情况下只是一个 Clang 的编译文件。
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
# bpftool 用于生成相应的 BPF 框架头文件(.skel.h) ，使用的是bpftool gen skeleton 命令:
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(patsubst %,$(OUTPUT)/%.o,$(BZS_APPS)): $(LIBBLAZESYM_OBJ)

$(BZS_APPS): $(LIBBLAZESYM_OBJ)

# Build application binary
# 最后，只使用用户空间.o文件(与 libbpf.a 静态库一起)生成最终的二进制文件。-lelf 和-lz 是 libbpf 的依赖项，需要明确提供给编译器:
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
