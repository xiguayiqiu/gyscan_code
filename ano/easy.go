package ano

import (
	"fmt"
	"net"
	"strings"
)

func TCPSyn(srcIP, dstIP string, dport int) *Packet {
	ip := NewIPv4().SetSrc(srcIP).SetDst(dstIP)
	tcp := NewTCP().SetDPort(uint16(dport)).SetFlags(TCP_SYN)
	tcp.Checksum = TCPChecksum(tcp, ip.Src, ip.Dst)
	ether := buildEtherAuto(dstIP)
	return Build(ether, ip, tcp)
}

func SendSYN(srcIP, dstIP string, dport int) error {
	return Send(TCPSyn(srcIP, dstIP, dport))
}

func TCPSynAck(srcIP, dstIP string) *Packet {
	ip := NewIPv4().SetSrc(srcIP).SetDst(dstIP)
	tcp := NewTCP().SetSPort(80).SetFlags(TCP_SYN | TCP_ACK)
	tcp.Checksum = TCPChecksum(tcp, ip.Src, ip.Dst)
	return Build(buildEtherAuto(dstIP), ip, tcp)
}

func TCPRst(srcIP, dstIP string) *Packet {
	ip := NewIPv4().SetSrc(srcIP).SetDst(dstIP)
	tcp := NewTCP().SetFlags(TCP_RST)
	tcp.Checksum = TCPChecksum(tcp, ip.Src, ip.Dst)
	return Build(buildEtherAuto(dstIP), ip, tcp)
}

func SendRST(srcIP, dstIP string) error {
	return Send(TCPRst(srcIP, dstIP))
}

func TCPFin(srcIP, dstIP string) *Packet {
	ip := NewIPv4().SetSrc(srcIP).SetDst(dstIP)
	tcp := NewTCP().SetFlags(TCP_FIN | TCP_ACK)
	tcp.Checksum = TCPChecksum(tcp, ip.Src, ip.Dst)
	return Build(buildEtherAuto(dstIP), ip, tcp)
}

func UDPDNS(srcIP, dstIP, domain string) *Packet {
	if srcIP == "" {
		srcIP = "10.0.0.1"
	}
	if dstIP == "" {
		dstIP = "8.8.8.8"
	}
	if domain == "" {
		domain = "example.com"
	}
	return Build(
		buildEtherAuto(dstIP),
		NewIPv4().SetSrc(srcIP).SetDst(dstIP).SetProtocol(IP_PROTO_UDP),
		NewUDP().SetSPort(12345).SetDPort(53),
		NewDNSQR(domain, DNS_A),
	)
}

func SendDNSQuery(srcIP, dstIP, domain string) error {
	return Send(UDPDNS(srcIP, dstIP, domain))
}

func ICMPPing(srcIP, dstIP string) *Packet {
	if srcIP == "" {
		srcIP = "10.0.0.1"
	}
	if dstIP == "" {
		dstIP = "8.8.8.8"
	}
	return Build(
		buildEtherAuto(dstIP),
		NewIPv4().SetSrc(srcIP).SetDst(dstIP).SetProtocol(IP_PROTO_ICMP),
		NewICMP(),
	)
}

func SendPing(srcIP, dstIP string) error {
	return Send(ICMPPing(srcIP, dstIP))
}

func ARPRequest(srcIP, targetIP, srcMAC string) *Packet {
	if srcMAC == "" {
		srcMAC = "00:de:ad:be:ef:01"
	}
	return Build(
		NewEther().SetDstMAC(BroadcastMAC).SetType(ETH_P_ARP),
		NewARP(ARP_REQUEST).SrcMACStr(srcMAC).SrcIPStr(srcIP).DstIPStr(targetIP),
	)
}

func SendARPWhoHas(srcIP, targetIP string) error {
	return Send(ARPRequest(srcIP, targetIP, ""))
}

func ARPReply(srcIP, srcMAC, dstIP, dstMAC string) *Packet {
	if srcMAC == "" {
		srcMAC = "aa:bb:cc:dd:ee:ff"
	}
	return Build(
		NewEther().SetDst(dstMAC).SetType(ETH_P_ARP),
		NewARP(ARP_REPLY).SrcMACStr(srcMAC).SrcIPStr(srcIP).DstMACStr(dstMAC).DstIPStr(dstIP),
	)
}

func HTTPGet(srcIP, dstIP, host string) *Packet {
	if host == "" {
		host = "example.com"
	}
	body := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", host)
	return Build(
		buildEtherAuto(dstIP),
		NewIPv4().SetSrc(srcIP).SetDst(dstIP).SetProtocol(IP_PROTO_TCP),
		NewTCP().SetSPort(54321).SetDPort(80).SetFlags(TCP_SYN|TCP_ACK),
		NewRaw([]byte(body)),
	)
}

func ICMPUnreach(srcIP, dstIP string) *Packet {
	return Build(
		buildEtherAuto(dstIP),
		NewIPv4().SetSrc(srcIP).SetDst(dstIP).SetProtocol(IP_PROTO_ICMP),
		&ICMP{Type: ICMP_DST_UNREACH, Code: 0, ID: uint16(RandID()), Seq: 1},
	)
}

type PacketBuilder struct {
	pkt *Packet
}

func NewPacket() *PacketBuilder {
	return &PacketBuilder{pkt: Build()}
}

func (b *PacketBuilder) Ether(dst, src string) *PacketBuilder {
	e := NewEther()
	if dst != "" {
		e.Dst = MAC(dst)
	}
	if src != "" {
		e.Src = MAC(src)
	}
	b.pkt.Set(e)
	return b
}

func (b *PacketBuilder) EtherBroadcast() *PacketBuilder {
	return b.Ether("ff:ff:ff:ff:ff:ff", "")
}

func (b *PacketBuilder) IPv4(src, dst string) *PacketBuilder {
	ip := NewIPv4()
	if src != "" {
		ip.Src = IP(src)
	}
	if dst != "" {
		ip.Dst = IP(dst)
	}
	b.pkt.Set(ip)
	return b
}

func (b *PacketBuilder) TCP(sport, dport int, flags string) *PacketBuilder {
	tcp := NewTCP().
		SetSPort(uint16(sport)).
		SetDPort(uint16(dport)).
		SetFlags(parseFlags(flags))
	if ip := b.pkt.Get("IPv4"); ip != nil {
		ipv4 := ip.(*IPv4)
		tcp.Checksum = TCPChecksum(tcp, ipv4.Src, ipv4.Dst)
	}
	b.pkt.Set(tcp)
	return b
}

func (b *PacketBuilder) UDP(sport, dport int) *PacketBuilder {
	u := NewUDP().SetSPort(uint16(sport)).SetDPort(uint16(dport))
	b.pkt.Set(u)
	return b
}

func (b *PacketBuilder) ICMP(typ, code int) *PacketBuilder {
	ic := &ICMP{Type: uint8(typ), Code: uint8(code), ID: uint16(RandID()), Seq: 1}
	b.pkt.Set(ic)
	return b
}

func (b *PacketBuilder) ARP(op int, smac, sip, dmac, dip string) *PacketBuilder {
	a := NewARP(uint16(op))
	if smac != "" {
		a.SrcMAC = MAC(smac)
	}
	if sip != "" {
		a.SrcIP = IP(sip)
	}
	if dmac != "" {
		a.DstMAC = MAC(dmac)
	}
	if dip != "" {
		a.DstIP = IP(dip)
	}
	b.pkt.Set(a)
	b.pkt.Get("Ether").(*Ether).Type = ETH_P_ARP
	return b
}

func (b *PacketBuilder) DNS(domain string, qtype DNSType) *PacketBuilder {
	dns := NewDNSQR(domain, qtype)
	b.pkt.Add(dns)
	return b
}

func (b *PacketBuilder) Raw(data []byte) *PacketBuilder {
	b.pkt.Add(NewRaw(data))
	return b
}

func (b *PacketBuilder) Build() *Packet {
	return b.pkt
}

func (b *PacketBuilder) Send() error {
	return Send(b.pkt)
}

func (b *PacketBuilder) Hex() string {
	return HexDump(b.pkt.Bytes())
}

func (b *PacketBuilder) Show() string {
	return b.pkt.Summary()
}

func buildEtherAuto(dstIP string) *Ether {
	ether := NewEther()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 6 {
			ether.Src = MACFromBytes(iface.HardwareAddr)
			break
		}
	}
	return ether
}

func parseFlags(s string) uint8 {
	f := uint8(0)
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		switch strings.ToLower(p) {
		case "syn":
			f |= TCP_SYN
		case "ack":
			f |= TCP_ACK
		case "fin":
			f |= TCP_FIN
		case "rst":
			f |= TCP_RST
		case "psh":
			f |= TCP_PSH
		case "urg":
			f |= TCP_URG
		}
	}
	return f
}
