```c
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
这三个类型有什么区别？
```

在eBPF（extended Berkeley Packet Filter）中，`SEC`（section）标签用于指定程序在内核中的存储位置。在提供的三个示例中，涉及了不同的eBPF程序类型和它们的应用场景：

1. **`SEC("tp/syscalls/sys_enter_write")`：**
   - 这表示一个Tracepoint程序，用于处理与系统调用 `write` 相关的Tracepoint事件。Tracepoint是一种在内核中插入的轻量级事件跟踪机制，允许用户空间和内核空间之间进行通信。这种类型的eBPF程序通常用于跟踪系统调用的进入点。
2. **`SEC("kprobe/do_unlinkat")`：**
   - 这表示一个Kprobe（Kernel Probe）程序，用于在指定的内核函数 `do_unlinkat` 的入口处插入eBPF代码。Kprobe程序通常用于跟踪、修改或分析特定内核函数的行为。在这里，它会在 `do_unlinkat` 函数的入口处执行eBPF代码。
3. **`SEC("fentry/do_unlinkat")`：**
   - 这表示一个Fentry（Function Entry）程序，同样用于在 `do_unlinkat` 函数的入口处插入eBPF代码。Fentry程序也用于跟踪、修改或分析函数的行为，但通常提供更多的上下文信息，用于更高级的函数跟踪和分析。

总结：

- **Tracepoint程序：** 用于处理与指定Tracepoint事件相关的eBPF代码，通常用于跟踪系统调用或其他内核事件。
- **Kprobe程序：** 在指定内核函数的入口处执行eBPF代码，用于跟踪、修改或分析特定内核函数的行为。
- **Fentry程序：** 在指定函数的入口处执行eBPF代码，提供更多上下文信息，用于更高级的函数跟踪和分析。