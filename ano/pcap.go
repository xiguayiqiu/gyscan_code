package ano

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type PcapVariant int

const (
	PcapStandard PcapVariant = iota
	PcapNSec
	PcapModified
	PcapNokia
	PcapRH61
	PcapSuSE63
)

const (
	PCAP_MAGIC              = 0xA1B2C3D4
	PCAP_SWAPPED_MAGIC      = 0xD4C3B2A1
	PCAP_NSEC_MAGIC         = 0xA1B23C4D
	PCAP_SWAPPED_NSEC_MAGIC = 0x4D3CB2A1
	PCAP_MODIFIED_MAGIC     = 0xA1B2CD34
	PCAP_SWAPPED_MOD_MAGIC  = 0x34CDB2A1
	PCAP_NOKIA_MAGIC        = 0xA1B2C432
)

func (v PcapVariant) String() string {
	switch v {
	case PcapStandard:
		return "pcap"
	case PcapNSec:
		return "nsecpcap"
	case PcapModified:
		return "modpcap"
	case PcapNokia:
		return "nokiapcap"
	case PcapRH61:
		return "rh6_1pcap"
	case PcapSuSE63:
		return "suse6_3pcap"
	default:
		return "unknown"
	}
}

func DetectPcapVariant(magic uint32, verMajor, verMinor uint16) PcapVariant {
	switch magic {
	case PCAP_MAGIC, PCAP_SWAPPED_MAGIC:
		if verMajor == 2 && verMinor == 2 {
			return PcapRH61
		}
		if verMajor == 2 && verMinor == 3 {
			return PcapSuSE63
		}
		return PcapStandard
	case PCAP_NSEC_MAGIC, PCAP_SWAPPED_NSEC_MAGIC:
		return PcapNSec
	case PCAP_MODIFIED_MAGIC, PCAP_SWAPPED_MOD_MAGIC:
		return PcapModified
	case PCAP_NOKIA_MAGIC:
		return PcapNokia
	default:
		return PcapStandard
	}
}

func isSwapped(magic uint32) bool {
	switch magic {
	case PCAP_SWAPPED_MAGIC, PCAP_SWAPPED_NSEC_MAGIC, PCAP_SWAPPED_MOD_MAGIC:
		return true
	default:
		return false
	}
}

func pcapByteOrder(magic uint32) binary.ByteOrder {
	if isSwapped(magic) {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

type PcapHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

type PcapRecord struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
	Data    []byte
}

type PcapWriter struct {
	w io.Writer
}

func NewPcapWriter(w io.Writer) *PcapWriter {
	return &PcapWriter{w: w}
}

func (pw *PcapWriter) WriteHeader() error {
	hdr := PcapHeader{
		MagicNumber:  PCAP_MAGIC,
		VersionMajor: 2,
		VersionMinor: 4,
		SnapLen:      65535,
		Network:      1,
	}
	return binary.Write(pw.w, binary.LittleEndian, hdr)
}

func (pw *PcapWriter) WritePacket(pkt *Packet) error {
	return pw.WritePacketAt(pkt, time.Now())
}

func (pw *PcapWriter) WritePacketAt(pkt *Packet, t time.Time) error {
	data := pkt.Bytes()
	rec := PcapRecord{
		TsSec:   uint32(t.Unix()),
		TsUsec:  uint32(t.Nanosecond() / 1000),
		InclLen: uint32(len(data)),
		OrigLen: uint32(len(data)),
		Data:    data,
	}
	if err := binary.Write(pw.w, binary.LittleEndian, rec.TsSec); err != nil {
		return err
	}
	if err := binary.Write(pw.w, binary.LittleEndian, rec.TsUsec); err != nil {
		return err
	}
	if err := binary.Write(pw.w, binary.LittleEndian, rec.InclLen); err != nil {
		return err
	}
	if err := binary.Write(pw.w, binary.LittleEndian, rec.OrigLen); err != nil {
		return err
	}
	_, err := pw.w.Write(rec.Data)
	return err
}

type PcapReader struct {
	r       io.Reader
	Header  PcapHeader
	Variant PcapVariant
	order   binary.ByteOrder
}

func OpenPcap(path string) (*PcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pr := &PcapReader{r: f}
	if err := binary.Read(pr.r, binary.LittleEndian, &pr.Header); err != nil {
		f.Close()
		return nil, fmt.Errorf("ano: open pcap header: %w", err)
	}
	pr.order = pcapByteOrder(pr.Header.MagicNumber)
	pr.Variant = DetectPcapVariant(pr.Header.MagicNumber, pr.Header.VersionMajor, pr.Header.VersionMinor)
	if isSwapped(pr.Header.MagicNumber) {
		pr.Header.VersionMajor = swap16(pr.Header.VersionMajor)
		pr.Header.VersionMinor = swap16(pr.Header.VersionMinor)
		pr.Header.SnapLen = swap32(pr.Header.SnapLen)
		pr.Header.Network = swap32(pr.Header.Network)
	}
	return pr, nil
}

func NewPcapReader(r io.Reader) (*PcapReader, error) {
	pr := &PcapReader{r: r}
	if err := binary.Read(pr.r, binary.LittleEndian, &pr.Header); err != nil {
		return nil, fmt.Errorf("ano: new pcap reader: %w", err)
	}
	pr.order = pcapByteOrder(pr.Header.MagicNumber)
	pr.Variant = DetectPcapVariant(pr.Header.MagicNumber, pr.Header.VersionMajor, pr.Header.VersionMinor)
	if isSwapped(pr.Header.MagicNumber) {
		pr.Header.VersionMajor = swap16(pr.Header.VersionMajor)
		pr.Header.VersionMinor = swap16(pr.Header.VersionMinor)
		pr.Header.SnapLen = swap32(pr.Header.SnapLen)
		pr.Header.Network = swap32(pr.Header.Network)
	}
	return pr, nil
}

func (pr *PcapReader) ReadPacket() (*PcapRecord, error) {
	var rec PcapRecord
	if err := binary.Read(pr.r, pr.order, &rec.TsSec); err != nil {
		return nil, err
	}
	if err := binary.Read(pr.r, pr.order, &rec.TsUsec); err != nil {
		return nil, err
	}
	if err := binary.Read(pr.r, pr.order, &rec.InclLen); err != nil {
		return nil, err
	}
	if err := binary.Read(pr.r, pr.order, &rec.OrigLen); err != nil {
		return nil, err
	}
	rec.Data = make([]byte, rec.InclLen)
	if _, err := io.ReadFull(pr.r, rec.Data); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (pr *PcapReader) NextPacket() (*Packet, error) {
	rec, err := pr.ReadPacket()
	if err != nil {
		return nil, err
	}
	return ParseEther(rec.Data)
}

func (pr *PcapReader) Close() error {
	if c, ok := pr.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (pr *PcapReader) ReadAll() ([]*Packet, error) {
	var pkts []*Packet
	for {
		pkt, err := pr.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return pkts, err
		}
		pkts = append(pkts, pkt)
	}
	return pkts, nil
}

func swap16(v uint16) uint16 {
	return (v>>8)&0xFF | (v&0xFF)<<8
}

func swap32(v uint32) uint32 {
	return (v>>24)&0xFF | ((v>>8)&0xFF)<<8 | ((v&0xFF)<<8)<<8 | (v&0xFF)<<24
}

func SavePcap(path string, pkts []*Packet) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	pw := NewPcapWriter(f)
	if err := pw.WriteHeader(); err != nil {
		return err
	}
	for _, pkt := range pkts {
		if err := pw.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

func LoadPcap(path string) ([]*Packet, error) {
	pr, err := OpenPcap(path)
	if err != nil {
		return nil, err
	}
	defer pr.Close()
	return pr.ReadAll()
}

func ParseEther(data []byte) (*Packet, error) {
	ether := &Ether{}
	remaining, err := ether.Deserialize(data)
	if err != nil {
		return nil, err
	}
	pkt := Build(ether)
	for len(remaining) > 0 {
		next := ether.Next(remaining)
		if next == nil {
			pkt.Payload = make([]byte, len(remaining))
			copy(pkt.Payload, remaining)
			break
		}
		remaining, err = next.Deserialize(remaining)
		if err != nil {
			pkt.Add(next)
			if len(remaining) > 0 {
				pkt.Payload = make([]byte, len(remaining))
				copy(pkt.Payload, remaining)
			}
			break
		}
		pkt.Add(next)
		ether2, ok := next.(*Ether)
		if ok {
			ether = ether2
			continue
		}
		if len(remaining) > 0 {
			next2 := next.Next(remaining)
			if next2 == nil {
				pkt.Payload = make([]byte, len(remaining))
				copy(pkt.Payload, remaining)
				break
			}
			for next2 != nil {
				remaining, err = next2.Deserialize(remaining)
				if err != nil {
					pkt.Add(next2)
					break
				}
				pkt.Add(next2)
				next2 = next2.Next(remaining)
			}
			if len(remaining) > 0 {
				pkt.Payload = make([]byte, len(remaining))
				copy(pkt.Payload, remaining)
			}
		}
		break
	}
	return pkt, nil
}

type PacketList struct {
	Packets []*Packet
}

func NewPacketList() *PacketList {
	return &PacketList{}
}

func (pl *PacketList) Add(pkt *Packet) {
	pl.Packets = append(pl.Packets, pkt)
}

func (pl *PacketList) Len() int {
	return len(pl.Packets)
}

func (pl *PacketList) Filter(proto string) *PacketList {
	result := NewPacketList()
	for _, pkt := range pl.Packets {
		if pkt.Get(proto) != nil {
			result.Add(pkt)
		}
	}
	return result
}

func (pl *PacketList) Summary() []string {
	var s []string
	for _, pkt := range pl.Packets {
		s = append(s, pkt.Summary())
	}
	return s
}

func (pl *PacketList) Save(filename string) error {
	return SavePcap(filename, pl.Packets)
}

func (pl *PacketList) PrintList() {
	for i, pkt := range pl.Packets {
		fmt.Printf("[%d] %s\n", i+1, pkt.Summary())
	}
}

func (pl *PacketList) Show(idx int) {
	if idx < 1 || idx > len(pl.Packets) {
		fmt.Printf("序号无效，范围: 1-%d\n", len(pl.Packets))
		return
	}
	pkt := pl.Packets[idx-1]
	showPacketDetail(idx, pkt)
}

func (pl *PacketList) ShowRange(start, end int) {
	if start < 1 {
		start = 1
	}
	if end > len(pl.Packets) {
		end = len(pl.Packets)
	}
	if start > end || start > len(pl.Packets) || end < 1 {
		fmt.Printf("序号无效，范围: 1-%d\n", len(pl.Packets))
		return
	}
	fmt.Printf("显示数据包 [%d - %d] / 共 %d 个:\n\n", start, end, len(pl.Packets))
	for i := start; i <= end; i++ {
		showPacketDetail(i, pl.Packets[i-1])
		if i < end {
			fmt.Println("---")
		}
	}
}

func (pl *PacketList) ShowIndices(indices []int) {
	if len(indices) == 0 {
		return
	}
	fmt.Printf("显示 %d 个指定数据包 / 共 %d 个:\n\n", len(indices), len(pl.Packets))
	for i, idx := range indices {
		if idx < 1 || idx > len(pl.Packets) {
			fmt.Printf("=== 序号 %d 无效，跳过 ===\n", idx)
			continue
		}
		showPacketDetail(idx, pl.Packets[idx-1])
		if i < len(indices)-1 {
			fmt.Println("---")
		}
	}
}

func showPacketDetail(idx int, pkt *Packet) {
	rawBytes := pkt.Bytes()
	fmt.Printf("帧 %d: 线路 %d 字节 (%d 位), 捕获 %d 字节 (%d 位)\n",
		idx, len(rawBytes), len(rawBytes)*8, len(rawBytes), len(rawBytes)*8)

	if len(pkt.Layers) == 0 {
		if len(rawBytes) > 0 {
			fmt.Println("    [无解析层]")
			fmt.Println()
			fmt.Println(HexDump(rawBytes))
		}
		return
	}

	var offset int
	for i, l := range pkt.Layers {
		switch v := l.(type) {
		case *Ether:
			showEtherDetail(v, rawBytes, offset)
			offset += 14
		case *IPv4:
			showIPv4Detail(v, rawBytes, offset)
			ihl := int(v.IHL) * 4
			offset += ihl
		case *ARP:
			showARPDetail(v, rawBytes, offset)
			offset += 28
		case *TCP:
			showTCPDetail(v, rawBytes, offset)
			dataOff := (pkt.rawTCPDataOffset())
			if dataOff > 0 {
				offset += dataOff
			} else {
				offset += 20
			}
		case *UDP:
			showUDPDetail(v, rawBytes, offset)
			offset += 8
		case *ICMP:
			showICMPDetail(v, rawBytes, offset)
			offset += 8
		case *TLSRecord:
			showTLSDetail(v, rawBytes, offset)
			offset += 5 + int(v.Length)
		case *Raw:
			showRawDetail(v, rawBytes, offset)
			offset += len(v.Load)
		}
		if i < len(pkt.Layers)-1 {
			fmt.Println()
		}
	}

	if len(pkt.Payload) > 0 {
		fmt.Println()
		fmt.Printf("数据 (%d 字节)\n", len(pkt.Payload))
		fmt.Println(HexDump(pkt.Payload))
	}

	fmt.Println()
	fmt.Println(HexDump(rawBytes))
}

func (p *Packet) rawTCPDataOffset() int {
	for _, l := range p.Layers {
		if tcp, ok := l.(*TCP); ok {
			return int(tcp.DataOff) * 4
		}
	}
	return 0
}

func showEtherDetail(e *Ether, raw []byte, base int) {
	fmt.Println("以太网 II, 源:", MACString(e.Src), "目的:", MACString(e.Dst))
	f := func(off int, label, val string) {
		fmt.Printf("    %-56s [%d..%d]\n", label+": "+val, base+off, base+off+fieldBytes(raw, base+off, label)-1)
	}
	if isBroadcast(e.Dst) {
		f(0, "目的MAC", MACString(e.Dst)+" (广播)")
	} else if isMulticast(e.Dst) {
		f(0, "目的MAC", MACString(e.Dst)+" (组播)")
	} else {
		f(0, "目的MAC", MACString(e.Dst))
	}
	f(6, "源MAC", MACString(e.Src))
	typeName := "未知"
	switch e.Type {
	case 0x0800:
		typeName = "IPv4"
	case 0x0806:
		typeName = "ARP"
	case 0x86DD:
		typeName = "IPv6"
	case 0x8100:
		typeName = "802.1Q VLAN"
	case 0x88CC:
		typeName = "LLDP"
	default:
		typeName = fmt.Sprintf("0x%04x", e.Type)
	}
	f(12, "类型", fmt.Sprintf("%s (0x%04x)", typeName, e.Type))
}

func showIPv4Detail(ip *IPv4, raw []byte, base int) {
	fmt.Printf("互联网协议版本 4, 源: %s, 目的: %s\n", IPBytes(ip.Src), IPBytes(ip.Dst))
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("0100 .... = 版本: %d", ip.Version), base)
	ihlBytes := int(ip.IHL) * 4
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf(".... %04b = 头部长度: %d 字节 (%d)", ip.IHL, ihlBytes, ip.IHL), base)
	ds := raw[base+1]
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("区分服务字段: 0x%02x (DSCP: 0x%02x, ECN: 0x%02x)", ds, ds>>2, ds&0x03), base+1)
	totalLen := ip.Length
	if totalLen == 0 {
		totalLen = 0
	}
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("总长度: %d", totalLen), base+2, base+3)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("标识: 0x%04x (%d)", ip.ID, ip.ID), base+4, base+5)

	fo := ip.FragOff
	flags := (fo >> 13) & 0x07
	offset := fo & 0x1FFF
	flagStr := fmt.Sprintf("0x%x", flags)
	if flags&0x04 != 0 {
		flagStr += " (禁止分片)"
	}
	if flags&0x02 != 0 {
		flagStr += " (更多分片)"
	}
	if flags == 0 {
		flagStr = "0x0"
	}
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("标志: %s", flagStr), base+6, base+7)
	if flags&0x04 != 0 {
		fmt.Printf("    %-56s\n", "    0... .... = 保留位: 未设置")
		fmt.Printf("    %-56s\n", "    .1.. .... = 禁止分片: 已设置")
		fmt.Printf("    %-56s\n", "    ..0. .... = 更多分片: 未设置")
	} else if flags&0x02 != 0 {
		fmt.Printf("    %-56s\n", "    0... .... = 保留位: 未设置")
		fmt.Printf("    %-56s\n", "    .0.. .... = 禁止分片: 未设置")
		fmt.Printf("    %-56s\n", "    ..1. .... = 更多分片: 已设置")
	} else {
		fmt.Printf("    %-56s\n", "    0... .... = 保留位: 未设置")
		fmt.Printf("    %-56s\n", "    .0.. .... = 禁止分片: 未设置")
		fmt.Printf("    %-56s\n", "    ..0. .... = 更多分片: 未设置")
	}
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("分片偏移: %d", offset), base+6, base+7)
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("生存时间: %d", ip.TTL), base+8)
	protoName := ""
	switch ip.Protocol {
	case IP_PROTO_TCP:
		protoName = "TCP"
	case IP_PROTO_UDP:
		protoName = "UDP"
	case IP_PROTO_ICMP:
		protoName = "ICMP"
	case 2:
		protoName = "IGMP"
	default:
		protoName = fmt.Sprintf("未知 (%d)", ip.Protocol)
	}
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("协议: %s (%d)", protoName, ip.Protocol), base+9)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("头部校验和: 0x%04x", ip.Checksum), base+10, base+11)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("源地址: %s", IPBytes(ip.Src)), base+12, base+15)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("目的地址: %s", IPBytes(ip.Dst)), base+16, base+19)
}

func showTCPDetail(tcp *TCP, raw []byte, base int) {
	fmt.Printf("传输控制协议, 源端口: %d, 目的端口: %d, 序号: %d, 确认号: %d, 长度: %d\n",
		tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, 0)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("源端口: %d", tcp.SrcPort), base, base+1)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("目的端口: %d", tcp.DstPort), base+2, base+3)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("序号 (原始): %d", tcp.Seq), base+4, base+7)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("确认号 (原始): %d", tcp.Ack), base+8, base+11)
	do := tcp.DataOff
	if do == 0 {
		do = 5
	}
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("%04b .... = 头部长度: %d 字节 (%d)", do, do*4, do), base+12)
	fmt.Printf("    %-56s\n", "    .... 0000 = 保留")
	ns := (tcp.Flags >> 0) & 1
	cwr := (tcp.Flags >> 7) & 1
	ecn := (tcp.Flags >> 6) & 1
	urg := (tcp.Flags >> 5) & 1
	ack := (tcp.Flags >> 4) & 1
	psh := (tcp.Flags >> 3) & 1
	rst := (tcp.Flags >> 2) & 1
	syn := (tcp.Flags >> 1) & 1
	fin := tcp.Flags & 1
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("标志位: 0x%03x", tcp.Flags), base+13)
	flagLabels := []struct {
		bit  uint8
		name string
	}{
		{cwr, "CWR: 拥塞窗口减小"},
		{ecn, "ECE: ECN 回显"},
		{urg, "URG: 紧急指针"},
		{ack, "ACK: 确认应答"},
		{psh, "PSH: 推送"},
		{rst, "RST: 重置连接"},
		{syn, "SYN: 同步"},
		{fin, "FIN: 结束"},
	}
	_ = ns
	flagOrder := []int{6, 5, 4, 3, 2, 1, 0, 7}
	for _, idx := range flagOrder {
		f := flagLabels[idx]
		if f.bit != 0 {
			fmt.Printf("    %-56s\n", fmt.Sprintf("    .... ...%d = %s: 已设置", idx, f.name))
		}
	}
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("窗口大小: %d", tcp.Window), base+14, base+15)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("校验和: 0x%04x", tcp.Checksum), base+16, base+17)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("紧急指针: %d", tcp.UrgPtr), base+18, base+19)
}

func showUDPDetail(udp *UDP, raw []byte, base int) {
	fmt.Printf("用户数据报协议, 源端口: %d, 目的端口: %d\n", udp.SrcPort, udp.DstPort)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("源端口: %d", udp.SrcPort), base, base+1)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("目的端口: %d", udp.DstPort), base+2, base+3)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("长度: %d", udp.Length), base+4, base+5)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("校验和: 0x%04x", udp.Checksum), base+6, base+7)
}

func showICMPDetail(icmp *ICMP, raw []byte, base int) {
	typeName := "未知"
	switch icmp.Type {
	case 8:
		typeName = "回显 (ping) 请求"
	case 0:
		typeName = "回显 (ping) 应答"
	case 3:
		typeName = "目的不可达"
	case 4:
		typeName = "源端抑制"
	case 5:
		typeName = "重定向"
	case 11:
		typeName = "TTL 超时"
	}
	fmt.Printf("互联网控制消息协议, 类型: %s\n", typeName)
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("类型: %d (%s)", icmp.Type, typeName), base)
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("代码: %d", icmp.Code), base+1)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("校验和: 0x%04x", icmp.Checksum), base+2, base+3)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("标识符 (BE): %d (0x%04x)", icmp.ID, icmp.ID), base+4, base+5)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("序号 (BE): %d (0x%04x)", icmp.Seq, icmp.Seq), base+6, base+7)
}

func showARPDetail(arp *ARP, raw []byte, base int) {
	opName := "请求 (1)"
	if arp.Op == 2 {
		opName = "应答 (2)"
	}
	fmt.Printf("地址解析协议 (%s)\n", opName)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("硬件类型: 以太网 (%d)", arp.HWType), base, base+1)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("协议类型: IPv4 (0x%04x)", arp.ProtoType), base+2, base+3)
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("硬件地址长度: %d", arp.HWLen), base+4)
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("协议地址长度: %d", arp.ProtoLen), base+5)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("操作码: %s", opName), base+6, base+7)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("发送方 MAC: %s", MACString(arp.SrcMAC)), base+8, base+13)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("发送方 IP: %s", IPBytes(arp.SrcIP)), base+14, base+17)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("目标 MAC: %s", MACString(arp.DstMAC)), base+18, base+23)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("目标 IP: %s", IPBytes(arp.DstIP)), base+24, base+27)
}

func showTLSDetail(tls *TLSRecord, raw []byte, base int) {
	ctName := TLSContentTypeNames[tls.ContentType]
	if ctName == "" {
		ctName = fmt.Sprintf("未知 (%d)", tls.ContentType)
	}
	verName := TLSVersionNames[tls.Version]
	if verName == "" {
		verName = fmt.Sprintf("0x%04x", tls.Version)
	}
	fmt.Printf("传输层安全 (%s)\n", ctName)
	fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("内容类型: %s", ctName), base)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("版本: %s (0x%04x)", verName, tls.Version), base+1, base+2)
	fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("长度: %d", tls.Length), base+3, base+4)

	if tls.ContentType == TLS_HANDSHAKE {
		hsName := TLSHandshakeTypeNames[tls.HandshakeType]
		if hsName == "" {
			hsName = fmt.Sprintf("未知 (%d)", tls.HandshakeType)
		}
		fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("握手类型: %s", hsName), base+5)
		fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("长度: %d", tls.Length-4), base+6)
		fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("版本: %s (0x%04x)",
			TLSVersionNames[tls.ClientVersion], tls.ClientVersion), base+9, base+10)
		fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("随机数: %x...", tls.ClientRandom[:8]),
			base+11, base+42)
		sidEnd := base + 42 + len(tls.SessionID)
		if len(tls.SessionID) > 0 {
			fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("会话ID: %x",
				tls.SessionID), base+43, sidEnd)
		} else {
			fmt.Printf("    %-56s [%d]\n", "会话ID 长度: 0", base+43)
		}

		if len(tls.CipherSuites) > 0 {
			csOff := sidEnd + 1
			csEnd := csOff + 1 + len(tls.CipherSuites)*2
			fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("加密套件 (%d 个)",
				len(tls.CipherSuites)), csOff, csEnd)
			for i, cs := range tls.CipherSuites {
				if i >= 8 {
					fmt.Printf("    %-56s\n", fmt.Sprintf("    ... 共 %d 个", len(tls.CipherSuites)))
					break
				}
				fmt.Printf("    %-56s\n", fmt.Sprintf("    加密套件: 0x%04x", cs))
			}
		}

		extOff := sidEnd + 1 + 2 + len(tls.CipherSuites)*2 + 1 + len(tls.CompMethods)
		if len(tls.Extensions) > 0 {
			fmt.Printf("    %-56s [%d..%d]\n", fmt.Sprintf("扩展 (%d 个)",
				len(tls.Extensions)), extOff+2, base+4+int(tls.Length))
			for _, e := range tls.Extensions {
				extName := TLSExtensionNames[e.Type]
				if extName == "" {
					extName = fmt.Sprintf("0x%04x", e.Type)
				}
				if e.Type == TLS_EXT_SERVER_NAME && tls.ServerName != "" {
					fmt.Printf("    %-56s\n", fmt.Sprintf("    %s: %s", extName, tls.ServerName))
				} else {
					fmt.Printf("    %-56s\n", fmt.Sprintf("    %s (%d 字节)", extName, e.Length))
				}
			}
		}
	} else if tls.ContentType == TLS_ALERT {
		fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("告警级别: %d", tls.AlertLevel), base+5)
		fmt.Printf("    %-56s [%d]\n", fmt.Sprintf("告警描述: %d", tls.AlertDesc), base+6)
	}
}

func showRawDetail(r *Raw, raw []byte, base int) {
	fmt.Printf("原始数据包 (%d 字节)\n", len(r.Load))
	fmt.Println(HexDump(r.Load))
}

func fieldBytes(raw []byte, offset int, label string) int {
	switch {
	case strings.Contains(label, "MAC") || strings.Contains(label, "mac"):
		return 6
	case strings.Contains(label, "源地址") || strings.Contains(label, "目的地址") || strings.Contains(label, "IP"):
		return 4
	case strings.Contains(label, "端口") || strings.Contains(label, "窗口") || strings.Contains(label, "紧急"):
		return 2
	case strings.Contains(label, "序号") || strings.Contains(label, "确认号"):
		return 4
	case strings.Contains(label, "校验和") || strings.Contains(label, "操作码") || strings.Contains(label, "硬件类型") || strings.Contains(label, "协议类型"):
		return 2
	case strings.Contains(label, "标识") || strings.Contains(label, "总长度") || strings.Contains(label, "标志") || strings.Contains(label, "分片"):
		return 2
	case strings.Contains(label, "类型"):
		return 2
	case strings.Contains(label, "长度") || strings.Contains(label, "标识符"):
		return 2
	case strings.Contains(label, "版本") || strings.Contains(label, "头部长度") || strings.Contains(label, "服务") || strings.Contains(label, "生存时间") || strings.Contains(label, "协议") || strings.Contains(label, "硬件地址长度") || strings.Contains(label, "协议地址长度"):
		return 1
	}
	return 1
}

func isBroadcast(mac [6]byte) bool {
	for _, b := range mac {
		if b != 0xFF {
			return false
		}
	}
	return true
}

func isMulticast(mac [6]byte) bool {
	return mac[0]&0x01 != 0
}

func LoadPacketList(filename string) (*PacketList, error) {
	pkts, err := LoadPcap(filename)
	if err != nil {
		return nil, err
	}
	return &PacketList{Packets: pkts}, nil
}

func WritePcap(filename string, pkts []*Packet) error {
	return SavePcap(filename, pkts)
}

func ReadPcap(filename string) ([]*Packet, error) {
	return LoadPcap(filename)
}
