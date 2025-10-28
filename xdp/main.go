package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" bpf xdp.bpf.c

func main() {
	// 解析命令行参数
	ifName := flag.String("ifname", "", "Interface to attach XDP program to")
	flag.Parse()
	if *ifName == "" {
		log.Fatal("missing required -ifname argument")
	}

	// 注册信号处理
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载 eBPF 程序和映射
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf objects: %v", err)
	}
	defer objs.Close()

	// 获取网卡设备
	iface, err := net.InterfaceByName(*ifName)
	if err != nil {
		log.Fatalf("lookup iface %s: %v", *ifName, err)
	}

	// 挂载 xdp 程序
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPass,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach XDP to %s: %v", *ifName, err)
	}
	defer l.Close()

	log.Printf("XDP program attached to iface %s (index %d)", *ifName, iface.Index)

	// 打开 ringbuf 读取器
	rbReader, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer rbReader.Close()

	// 在收到信号时关闭 ringbuf reader，以便 handleEvent 中的阻塞读取返回
	go func() {
		<-stopCh
		if err := rbReader.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %v", err)
		}
		fmt.Println("signal received, closing ringbuf and shutting down...")
	}()

	// 处理 ringbuf 事件（阻塞直到 ringbuf 被关闭）
	log.Println("start handle events")
	handleEvent(rbReader)
}

func handleEvent(rb *ringbuf.Reader) {
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading from ringbuf: %s", err)
			continue
		}

		// TCP头前20字节
		data := record.RawSample
		if len(data) < 20 {
			log.Printf("record too short for TCP header: %d bytes", len(data))
			continue
		}

		var tcp tcphdr
		if err := binary.Read(bytes.NewReader(data[:20]), binary.BigEndian, &tcp); err != nil {
			log.Printf("failed to decode TCP header: %v", err)
			continue
		}

		// 计算头长与可选项
		hLen := tcp.headerLen()
		if hLen < 20 {
			// 异常数据偏移，忽略
			log.Printf("invalid TCP header length: %d", hLen)
			continue
		}
		optEnd := int(hLen)
		if optEnd > len(data) {
			optEnd = len(data)
		}
		options := []byte(nil)
		if optEnd > 20 {
			options = data[20:optEnd]
		}

		log.Printf(`
TCP %d -> %d seq=%d ack=%d flags=[ 
	URG:%t 
	ACK:%t 
	PSH:%t 
	RST:%t 
	SYN:%t
	FIN:%t
] win=%d opts=%dB`,
			tcp.Source, tcp.Dest, tcp.Seq, tcp.AckSeq,
			tcp.urg(), tcp.ack(), tcp.psh(), tcp.rst(), tcp.syn(), tcp.fin(),
			tcp.Window, len(options))
	}
}
