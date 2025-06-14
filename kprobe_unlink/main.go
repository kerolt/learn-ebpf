package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" bpf kprobe_unlink.bpf.c

func main() {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf objects: %v", err)
	}
	defer objs.Close()

	// SEC("kprobe/do_unlinkat")
	kp, err := link.Kprobe("do_unlinkat", objs.DoUnlinkat, nil)
	if err != nil {
		log.Fatalf("linking kprobe: %v", err)
	}
	defer kp.Close()

	// SEC("kretprobe/do_unlinkat")
	krep, err := link.Kretprobe("do_unlinkat", objs.DoUnlinkatExit, nil)
	if err != nil {
		log.Fatalf("linking kretprobe: %v", err)
	}
	defer krep.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Println("eBPF 程序已成功加载，开始监控文件删除操作...")
	fmt.Println("请在另一个终端执行文件删除操作，如: rm test.txt")
	fmt.Println("按 Ctrl+C 退出")

	// 启动协程读取内核日志
	go readTraceLog()

	// 等待中断信号
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	fmt.Println("\n正在退出...")
}

// 读取内核跟踪日志
func readTraceLog() {
	file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Printf("无法打开 trace_pipe: %v", err)
		log.Printf("提示: 请确保以 root 权限运行程序")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 只显示我们程序产生的日志
		if strings.Contains(line, "KPROBE ENTRY") || strings.Contains(line, "KPROBE EXIT") {
			fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("读取 trace_pipe 出错: %v", err)
	}
}
