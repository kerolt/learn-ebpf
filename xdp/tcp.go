package main

// tcphdr 映射 TCP 基本 20 字节首部；字段需导出以便 encoding/binary 通过反射写入
type tcphdr struct {
	Source uint16
	Dest   uint16
	Seq    uint32
	AckSeq uint32

	OffRes uint8 // 高 4 位: data offset（单位 4 字节），低 4 位: 保留
	Flags  uint8 // CWR(7) ECE(6) URG(5) ACK(4) PSH(3) RST(2) SYN(1) FIN(0)

	Window uint16
	Check  uint16
	UrgPtr uint16
}

func (h tcphdr) headerLen() uint8 {
	return (h.OffRes >> 4) * 4
}

func (h tcphdr) fin() bool { return h.Flags&0x01 != 0 }
func (h tcphdr) syn() bool { return h.Flags&0x02 != 0 }
func (h tcphdr) rst() bool { return h.Flags&0x04 != 0 }
func (h tcphdr) psh() bool { return h.Flags&0x08 != 0 }
func (h tcphdr) ack() bool { return h.Flags&0x10 != 0 }
func (h tcphdr) urg() bool { return h.Flags&0x20 != 0 }
