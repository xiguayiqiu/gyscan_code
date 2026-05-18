package ano

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type AnalysisResult struct {
	FileName     string
	TotalPackets int
	TimeRange    struct {
		Start time.Time
		End   time.Time
	}
	ProtocolStats map[string]int
	FlowStats     []FlowRecord
	PortStats     []PortRecord
	SizeStats     SizeStats
	IPStats       map[string]int
	TopTalkers    []TrafficRecord
}

type FlowRecord struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	Packets  int
	Bytes    int
}

type PortRecord struct {
	Port     uint16
	Protocol string
	Count    int
}

type SizeStats struct {
	Min     int
	Max     int
	Avg     int
	Total   int
	ByRange map[string]int
}

type TrafficRecord struct {
	IP      string
	Packets int
	Bytes   int
}

type AnalyzeOpts struct {
	TopN      int
	SizeRange bool
}

func DefaultAnalyzeOpts() *AnalyzeOpts {
	return &AnalyzeOpts{
		TopN:      10,
		SizeRange: true,
	}
}

func AnalyzePackets(pkts []*Packet, opts *AnalyzeOpts) *AnalysisResult {
	if opts == nil {
		opts = DefaultAnalyzeOpts()
	}

	result := &AnalysisResult{
		TotalPackets: len(pkts),
		ProtocolStats: make(map[string]int),
		IPStats:       make(map[string]int),
	}

	if len(pkts) == 0 {
		return result
	}

	flowMap := make(map[string]*FlowRecord)
	portMap := make(map[uint16]int)
	ipTraffic := make(map[string]*TrafficRecord)
	var sizes []int
	totalBytes := 0

	for _, pkt := range pkts {
		size := len(pkt.Bytes())
		sizes = append(sizes, size)
		totalBytes += size

		for _, l := range pkt.Layers {
			result.ProtocolStats[l.Tag()]++
		}

		srcIP := ""
		dstIP := ""
		if ip := pkt.Get("IPv4"); ip != nil {
			ipv4 := ip.(*IPv4)
			srcIP = IPBytes(ipv4.Src)
			dstIP = IPBytes(ipv4.Dst)
		}

		if srcIP != "" {
			ipTraffic[srcIP] = addTraffic(ipTraffic[srcIP], 1, size)
		}
		if dstIP != "" {
			ipTraffic[dstIP] = addTraffic(ipTraffic[dstIP], 1, size)
		}

		var proto string
		var srcPort, dstPort uint16

		if tcp := pkt.Get("TCP"); tcp != nil {
			t := tcp.(*TCP)
			proto = "TCP"
			srcPort = t.SrcPort
			dstPort = t.DstPort
		} else if udp := pkt.Get("UDP"); udp != nil {
			u := udp.(*UDP)
			proto = "UDP"
			srcPort = u.SrcPort
			dstPort = u.DstPort
		}

		if proto != "" && srcIP != "" && dstIP != "" {
			key := fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)
			if f, ok := flowMap[key]; ok {
				f.Packets++
				f.Bytes += size
			} else {
				flowMap[key] = &FlowRecord{
					SrcIP:    srcIP,
					DstIP:    dstIP,
					SrcPort:  srcPort,
					DstPort:  dstPort,
					Protocol: proto,
					Packets:  1,
					Bytes:    size,
				}
			}
			portMap[srcPort]++
			portMap[dstPort]++
		}
	}

	sort.Ints(sizes)
	result.SizeStats = SizeStats{
		Min:     sizes[0],
		Max:     sizes[len(sizes)-1],
		Total:   totalBytes,
		ByRange: make(map[string]int),
	}
	if len(sizes) > 0 {
		sum := 0
		for _, s := range sizes {
			sum += s
		}
		result.SizeStats.Avg = sum / len(sizes)
	}

	if opts.SizeRange {
		ranges := []struct {
			label string
			min   int
			max   int
		}{
			{"<64", 0, 63},
			{"64-127", 64, 127},
			{"128-255", 128, 255},
			{"256-511", 256, 511},
			{"512-1023", 512, 1023},
			{"1024-1518", 1024, 1518},
			{">1518", 1519, 1<<31 - 1},
		}
		for _, r := range ranges {
			for _, s := range sizes {
				if s >= r.min && s <= r.max {
					result.SizeStats.ByRange[r.label]++
				}
			}
		}
	}

	flowList := make([]FlowRecord, 0, len(flowMap))
	for _, f := range flowMap {
		flowList = append(flowList, *f)
	}
	sort.Slice(flowList, func(i, j int) bool {
		return flowList[i].Packets > flowList[j].Packets
	})
	if len(flowList) > opts.TopN {
		flowList = flowList[:opts.TopN]
	}
	result.FlowStats = flowList

	type kv struct {
		k uint16
		v int
	}
	var portList []kv
	for p, c := range portMap {
		portList = append(portList, kv{p, c})
	}
	sort.Slice(portList, func(i, j int) bool {
		return portList[i].v > portList[j].v
	})
	for i, kv := range portList {
		if i >= opts.TopN {
			break
		}
		proto := "tcp/udp"
		if svc, ok := ServicePorts[kv.k]; ok {
			proto = svc
		}
		result.PortStats = append(result.PortStats, PortRecord{
			Port: kv.k, Protocol: proto, Count: kv.v,
		})
	}

	var talkers []TrafficRecord
	for _, t := range ipTraffic {
		talkers = append(talkers, *t)
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].Packets > talkers[j].Packets
	})
	if len(talkers) > opts.TopN {
		talkers = talkers[:opts.TopN]
	}
	result.TopTalkers = talkers

	return result
}

func addTraffic(ip *TrafficRecord, pkts, bytes int) *TrafficRecord {
	if ip == nil {
		return &TrafficRecord{Packets: pkts, Bytes: bytes}
	}
	ip.Packets += pkts
	ip.Bytes += bytes
	return ip
}

func (r *AnalysisResult) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "=== 数据包分析报告 ===\n\n")
	fmt.Fprintf(&b, "总计数据包: %d\n", r.TotalPackets)
	if !r.TimeRange.Start.IsZero() {
		fmt.Fprintf(&b, "时间范围: %s - %s\n",
			r.TimeRange.Start.Format("2006-01-02 15:04:05"),
			r.TimeRange.End.Format("2006-01-02 15:04:05"))
	}

	b.WriteString("\n--- 协议分布 ---\n")
	type kv struct {
		k string
		v int
	}
	var protos []kv
	for k, v := range r.ProtocolStats {
		protos = append(protos, kv{k, v})
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i].v > protos[j].v })
	for _, p := range protos {
		pct := float64(p.v) / float64(r.TotalPackets) * 100
		fmt.Fprintf(&b, "  %-10s %6d  (%5.1f%%)\n", p.k, p.v, pct)
	}

	b.WriteString("\n--- 数据包大小 ---\n")
	fmt.Fprintf(&b, "  最小: %d 字节\n", r.SizeStats.Min)
	fmt.Fprintf(&b, "  最大: %d 字节\n", r.SizeStats.Max)
	fmt.Fprintf(&b, "  平均: %d 字节\n", r.SizeStats.Avg)
	fmt.Fprintf(&b, "  总计: %d 字节\n", r.SizeStats.Total)
	if len(r.SizeStats.ByRange) > 0 {
		b.WriteString("\n  大小分布:\n")
		var ranges []string
		for label := range r.SizeStats.ByRange {
			ranges = append(ranges, label)
		}
		sortRangeLabels(ranges)
		for _, label := range ranges {
			fmt.Fprintf(&b, "    %-12s %d\n", label, r.SizeStats.ByRange[label])
		}
	}

	b.WriteString("\n--- Top 流 ---\n")
	for i, f := range r.FlowStats {
		fmt.Fprintf(&b, "  [%d] %s:%d > %s:%d (%s) 包:%d 字节:%d\n",
			i+1, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort,
			f.Protocol, f.Packets, f.Bytes)
	}

	b.WriteString("\n--- Top 端口 ---\n")
	for i, p := range r.PortStats {
		fmt.Fprintf(&b, "  [%d] %d (%s) - %d次\n", i+1, p.Port, p.Protocol, p.Count)
	}

	b.WriteString("\n--- Top 通信主机 ---\n")
	for i, t := range r.TopTalkers {
		fmt.Fprintf(&b, "  [%d] %s  包:%d  字节:%d\n", i+1, t.IP, t.Packets, t.Bytes)
	}

	return b.String()
}

func sortRangeLabels(labels []string) {
	order := map[string]int{
		"<64": 1, "64-127": 2, "128-255": 3,
		"256-511": 4, "512-1023": 5, "1024-1518": 6, ">1518": 7,
	}
	sort.Slice(labels, func(i, j int) bool {
		return order[labels[i]] < order[labels[j]]
	})
}

func AnalyzeFile(filename string) (*AnalysisResult, error) {
	pkts, err := LoadPackets(filename)
	if err != nil {
		return nil, err
	}
	return AnalyzePackets(pkts, nil), nil
}

func LoadPackets(filename string) ([]*Packet, error) {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".cap") {
		return LoadCap(filename)
	}
	return LoadPcap(filename)
}

func SavePackets(filename string, pkts []*Packet) error {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".cap") {
		return DumpCap(filename, pkts)
	}
	return SavePcap(filename, pkts)
}

func FindPackets(pkts []*Packet, filter string) []*Packet {
	var result []*Packet
	for _, pkt := range pkts {
		if pkt.Get(filter) != nil {
			result = append(result, pkt)
			continue
		}
		if matchFilter(pkt, filter) {
			result = append(result, pkt)
		}
	}
	return result
}

func matchFilter(pkt *Packet, filter string) bool {
	srcIP, dstIP, srcPort, dstPort := extractEndpoints(pkt)
	parts := strings.Split(filter, ",")
	hasCondition := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		switch {
		case strings.HasPrefix(p, "src="):
			hasCondition = true
			if strings.TrimPrefix(p, "src=") != srcIP {
				return false
			}
		case strings.HasPrefix(p, "dst="):
			hasCondition = true
			if strings.TrimPrefix(p, "dst=") != dstIP {
				return false
			}
		case strings.HasPrefix(p, "host="):
			hasCondition = true
			host := strings.TrimPrefix(p, "host=")
			if host != srcIP && host != dstIP {
				return false
			}
		case strings.HasPrefix(p, "port="):
			hasCondition = true
			portStr := strings.TrimPrefix(p, "port=")
			port := uint16(parseInt(portStr))
			if port != srcPort && port != dstPort {
				return false
			}
		case strings.HasPrefix(p, "dport="):
			hasCondition = true
			portStr := strings.TrimPrefix(p, "dport=")
			if uint16(parseInt(portStr)) != dstPort {
				return false
			}
		case strings.HasPrefix(p, "sport="):
			hasCondition = true
			portStr := strings.TrimPrefix(p, "sport=")
			if uint16(parseInt(portStr)) != srcPort {
				return false
			}
		}
	}
	return hasCondition
}

func extractEndpoints(pkt *Packet) (srcIP, dstIP string, srcPort, dstPort uint16) {
	if ip := pkt.Get("IPv4"); ip != nil {
		ipv4 := ip.(*IPv4)
		srcIP = IPBytes(ipv4.Src)
		dstIP = IPBytes(ipv4.Dst)
	}
	if tcp := pkt.Get("TCP"); tcp != nil {
		t := tcp.(*TCP)
		srcPort = t.SrcPort
		dstPort = t.DstPort
	} else if udp := pkt.Get("UDP"); udp != nil {
		u := udp.(*UDP)
		srcPort = u.SrcPort
		dstPort = u.DstPort
	}
	return
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

type ProtocolSummary struct {
	Name    string
	Count   int
	Percent float64
}

func ProtocolBreakdown(pkts []*Packet) []ProtocolSummary {
	total := len(pkts)
	counts := make(map[string]int)
	for _, pkt := range pkts {
		for _, l := range pkt.Layers {
			counts[l.Tag()]++
		}
	}
	var result []ProtocolSummary
	for name, count := range counts {
		result = append(result, ProtocolSummary{
			Name:    name,
			Count:   count,
			Percent: float64(count) / float64(total) * 100,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
}

type ConversationKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

type Conversation struct {
	Key     ConversationKey
	Packets []*Packet
	Bytes   int
}

func Conversations(pkts []*Packet) []Conversation {
	convMap := make(map[string]*Conversation)
	for _, pkt := range pkts {
		key := conversationKey(pkt)
		ck := fmt.Sprintf("%s:%d-%s:%d-%s", key.SrcIP, key.SrcPort, key.DstIP, key.DstPort, key.Proto)
		if c, ok := convMap[ck]; ok {
			c.Packets = append(c.Packets, pkt)
			c.Bytes += len(pkt.Bytes())
		} else {
			convMap[ck] = &Conversation{
				Key:     key,
				Packets: []*Packet{pkt},
				Bytes:   len(pkt.Bytes()),
			}
		}
	}
	var result []Conversation
	for _, c := range convMap {
		result = append(result, *c)
	}
	sort.Slice(result, func(i, j int) bool {
		return len(result[i].Packets) > len(result[j].Packets)
	})
	return result
}

func conversationKey(pkt *Packet) ConversationKey {
	key := ConversationKey{Proto: "Unknown"}
	srcIP, dstIP, srcPort, dstPort := extractEndpoints(pkt)
	key.SrcIP = srcIP
	key.DstIP = dstIP
	key.SrcPort = srcPort
	key.DstPort = dstPort
	if pkt.Get("TCP") != nil {
		key.Proto = "TCP"
	} else if pkt.Get("UDP") != nil {
		key.Proto = "UDP"
	} else if pkt.Get("ICMP") != nil {
		key.Proto = "ICMP"
	} else if pkt.Get("ARP") != nil {
		key.Proto = "ARP"
	}
	return key
}

type TCPUDPStats struct {
	TCPCount    int
	UDPCount    int
	SynCount    int
	SynAckCount int
	RstCount    int
	FinCount    int
}

func TCPFlagStats(pkts []*Packet) TCPUDPStats {
	var stats TCPUDPStats
	for _, pkt := range pkts {
		if tcp := pkt.Get("TCP"); tcp != nil {
			t := tcp.(*TCP)
			stats.TCPCount++
			if t.Flags&TCP_SYN != 0 && t.Flags&TCP_ACK == 0 {
				stats.SynCount++
			}
			if t.Flags&TCP_SYN != 0 && t.Flags&TCP_ACK != 0 {
				stats.SynAckCount++
			}
			if t.Flags&TCP_RST != 0 {
				stats.RstCount++
			}
			if t.Flags&TCP_FIN != 0 {
				stats.FinCount++
			}
		}
		if pkt.Get("UDP") != nil {
			stats.UDPCount++
		}
	}
	return stats
}