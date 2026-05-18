package ano

import (
	"encoding/binary"
	"fmt"
	"net"
)

var (
	BroadcastMAC = [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	ZeroMAC      = [6]byte{0, 0, 0, 0, 0, 0}
)

func MAC(s string) [6]byte {
	var mac [6]byte
	h, err := net.ParseMAC(s)
	if err == nil && len(h) == 6 {
		copy(mac[:], h)
	}
	return mac
}

func MACFromBytes(b []byte) [6]byte {
	var mac [6]byte
	if len(b) >= 6 {
		copy(mac[:], b[:6])
	}
	return mac
}

func MACString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func IP(s string) [4]byte {
	var ip [4]byte
	parsed := net.ParseIP(s)
	if parsed != nil {
		ip4 := parsed.To4()
		if ip4 != nil {
			copy(ip[:], ip4)
		}
	}
	return ip
}

func IPBytes(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

type Ether struct {
	Dst  [6]byte
	Src  [6]byte
	Type uint16
}

func NewEther() *Ether {
	return &Ether{
		Dst:  BroadcastMAC,
		Src:  ZeroMAC,
		Type: ETH_P_IP,
	}
}

func (e *Ether) Tag() string { return "Ether" }
func (e *Ether) Len() int    { return 14 }

func (e *Ether) Copy() Layer {
	ne := &Ether{}
	copy(ne.Dst[:], e.Dst[:])
	copy(ne.Src[:], e.Src[:])
	ne.Type = e.Type
	return ne
}

func (e *Ether) Serialize() []byte {
	b := make([]byte, 14)
	copy(b[0:6], e.Dst[:])
	copy(b[6:12], e.Src[:])
	binary.BigEndian.PutUint16(b[12:14], e.Type)
	return b
}

func (e *Ether) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 14 {
		return data, fmt.Errorf("ether: need 14 bytes, got %d", len(data))
	}
	copy(e.Dst[:], data[0:6])
	copy(e.Src[:], data[6:12])
	e.Type = binary.BigEndian.Uint16(data[12:14])
	return data[14:], nil
}

func (e *Ether) Next(data []byte) Layer {
	switch e.Type {
	case ETH_P_IP:
		return &IPv4{}
	case ETH_P_ARP:
		return &ARP{}
	case ETH_P_IPV6:
		return &IPv6{}
	default:
		return nil
	}
}

func (e *Ether) SetDst(s string) *Ether     { e.Dst = MAC(s); return e }
func (e *Ether) SetSrc(s string) *Ether     { e.Src = MAC(s); return e }
func (e *Ether) SetType(t uint16) *Ether    { e.Type = t; return e }
func (e *Ether) SetDstMAC(m [6]byte) *Ether { e.Dst = m; return e }
func (e *Ether) SetSrcMAC(m [6]byte) *Ether { e.Src = m; return e }

type IPv4 struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	Length   uint16
	ID       uint16
	Flags    uint8
	FragOff  uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	Src      [4]byte
	Dst      [4]byte
	Options  []byte
}

func NewIPv4() *IPv4 {
	return &IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: IP_PROTO_TCP,
		Src:      IP("10.0.0.1"),
		Dst:      IP("10.0.0.2"),
	}
}

func (ip *IPv4) Tag() string { return "IPv4" }
func (ip *IPv4) Len() int    { return int(ip.IHL) * 4 }

func (ip *IPv4) Copy() Layer {
	n := &IPv4{
		Version: ip.Version, IHL: ip.IHL, TOS: ip.TOS,
		Length: ip.Length, ID: ip.ID, Flags: ip.Flags,
		FragOff: ip.FragOff, TTL: ip.TTL, Protocol: ip.Protocol,
		Checksum: ip.Checksum,
	}
	copy(n.Src[:], ip.Src[:])
	copy(n.Dst[:], ip.Dst[:])
	if len(ip.Options) > 0 {
		n.Options = make([]byte, len(ip.Options))
		copy(n.Options, ip.Options)
	}
	return n
}

func (ip *IPv4) Serialize() []byte {
	if ip.IHL == 0 {
		ip.IHL = 5
	}
	if ip.Version == 0 {
		ip.Version = 4
	}
	ihlBytes := int(ip.IHL) * 4
	b := make([]byte, ihlBytes)
	b[0] = (ip.Version << 4) | (ip.IHL & 0x0F)
	b[1] = ip.TOS
	binary.BigEndian.PutUint16(b[2:4], ip.Length)
	binary.BigEndian.PutUint16(b[4:6], ip.ID)
	frag := (uint16(ip.Flags) << 13) | (ip.FragOff & 0x1FFF)
	binary.BigEndian.PutUint16(b[6:8], frag)
	b[8] = ip.TTL
	b[9] = ip.Protocol
	copy(b[12:16], ip.Src[:])
	copy(b[16:20], ip.Dst[:])
	if len(ip.Options) > 0 {
		copy(b[20:], ip.Options)
	}
	ip.Checksum = checksum(b)
	binary.BigEndian.PutUint16(b[10:12], ip.Checksum)
	return b
}

func (ip *IPv4) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 20 {
		return data, fmt.Errorf("ipv4: need 20 bytes, got %d", len(data))
	}
	ip.Version = data[0] >> 4
	ip.IHL = data[0] & 0x0F
	ip.TOS = data[1]
	ip.Length = binary.BigEndian.Uint16(data[2:4])
	ip.ID = binary.BigEndian.Uint16(data[4:6])
	frag := binary.BigEndian.Uint16(data[6:8])
	ip.Flags = uint8(frag >> 13)
	ip.FragOff = frag & 0x1FFF
	ip.TTL = data[8]
	ip.Protocol = data[9]
	copy(ip.Src[:], data[12:16])
	copy(ip.Dst[:], data[16:20])
	ihlBytes := int(ip.IHL) * 4
	if ihlBytes > 20 && len(data) >= ihlBytes {
		ip.Options = make([]byte, ihlBytes-20)
		copy(ip.Options, data[20:ihlBytes])
	}
	if ip.Length > 0 && int(ip.Length) <= len(data) {
		return data[ip.Length:], nil
	}
	return data[ihlBytes:], nil
}

func (ip *IPv4) Next(data []byte) Layer {
	switch ip.Protocol {
	case IP_PROTO_TCP:
		return &TCP{}
	case IP_PROTO_UDP:
		return &UDP{}
	case IP_PROTO_ICMP:
		return &ICMP{}
	default:
		return nil
	}
}

func (ip *IPv4) SetSrc(s string) *IPv4     { ip.Src = IP(s); return ip }
func (ip *IPv4) SetDst(s string) *IPv4     { ip.Dst = IP(s); return ip }
func (ip *IPv4) SetTTL(ttl uint8) *IPv4    { ip.TTL = ttl; return ip }
func (ip *IPv4) SetID(id uint16) *IPv4     { ip.ID = id; return ip }
func (ip *IPv4) SetProtocol(p uint8) *IPv4 { ip.Protocol = p; return ip }

type IPv6 struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	Length       uint16
	NextHeader   uint8
	HopLimit     uint8
	Src          [16]byte
	Dst          [16]byte
}

func NewIPv6() *IPv6 {
	return &IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: IP_PROTO_TCP,
	}
}

func (ip6 *IPv6) Tag() string { return "IPv6" }
func (ip6 *IPv6) Len() int    { return 40 }

func (ip6 *IPv6) Copy() Layer {
	n := &IPv6{
		Version: ip6.Version, TrafficClass: ip6.TrafficClass,
		FlowLabel: ip6.FlowLabel, Length: ip6.Length,
		NextHeader: ip6.NextHeader, HopLimit: ip6.HopLimit,
	}
	copy(n.Src[:], ip6.Src[:])
	copy(n.Dst[:], ip6.Dst[:])
	return n
}

func (ip6 *IPv6) Serialize() []byte {
	b := make([]byte, 40)
	verTC := (uint32(ip6.Version) << 28) | (uint32(ip6.TrafficClass) << 20) | (ip6.FlowLabel & 0xFFFFF)
	binary.BigEndian.PutUint32(b[0:4], verTC)
	binary.BigEndian.PutUint16(b[4:6], ip6.Length)
	b[6] = ip6.NextHeader
	b[7] = ip6.HopLimit
	copy(b[8:24], ip6.Src[:])
	copy(b[24:40], ip6.Dst[:])
	return b
}

func (ip6 *IPv6) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 40 {
		return data, fmt.Errorf("ipv6: need 40 bytes, got %d", len(data))
	}
	verTC := binary.BigEndian.Uint32(data[0:4])
	ip6.Version = uint8(verTC >> 28)
	ip6.TrafficClass = uint8(verTC >> 20 & 0xFF)
	ip6.FlowLabel = verTC & 0xFFFFF
	ip6.Length = binary.BigEndian.Uint16(data[4:6])
	ip6.NextHeader = data[6]
	ip6.HopLimit = data[7]
	copy(ip6.Src[:], data[8:24])
	copy(ip6.Dst[:], data[24:40])
	return data[40:], nil
}

func (ip6 *IPv6) Next(data []byte) Layer {
	switch ip6.NextHeader {
	case IP_PROTO_TCP:
		return &TCP{}
	case IP_PROTO_UDP:
		return &UDP{}
	case IP_PROTO_ICMPV6:
		return &ICMP{}
	default:
		return nil
	}
}

type TCP struct {
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	DataOff  uint8
	Flags    uint8
	Window   uint16
	Checksum uint16
	UrgPtr   uint16
	Options  []byte
}

const (
	TCP_FIN uint8 = 1
	TCP_SYN uint8 = 2
	TCP_RST uint8 = 4
	TCP_PSH uint8 = 8
	TCP_ACK uint8 = 16
	TCP_URG uint8 = 32
	TCP_ECE uint8 = 64
	TCP_CWR uint8 = 128
)

func NewTCP() *TCP {
	return &TCP{
		SrcPort: uint16(RandInt(1024, 65535)),
		DstPort: 80,
		Seq:     RandSeq(),
		Window:  65535,
		Flags:   TCP_SYN,
		DataOff: 5,
	}
}

func (t *TCP) Tag() string { return "TCP" }
func (t *TCP) Len() int    { return int(t.DataOff) * 4 }

func (t *TCP) Copy() Layer {
	n := &TCP{
		SrcPort: t.SrcPort, DstPort: t.DstPort, Seq: t.Seq,
		Ack: t.Ack, DataOff: t.DataOff, Flags: t.Flags,
		Window: t.Window, Checksum: t.Checksum, UrgPtr: t.UrgPtr,
	}
	if len(t.Options) > 0 {
		n.Options = make([]byte, len(t.Options))
		copy(n.Options, t.Options)
	}
	return n
}

func (t *TCP) Serialize() []byte {
	if t.DataOff == 0 {
		t.DataOff = 5
	}
	doffBytes := int(t.DataOff) * 4
	b := make([]byte, doffBytes)
	binary.BigEndian.PutUint16(b[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], t.DstPort)
	binary.BigEndian.PutUint32(b[4:8], t.Seq)
	binary.BigEndian.PutUint32(b[8:12], t.Ack)
	b[12] = (t.DataOff << 4) & 0xF0
	b[13] = t.Flags
	binary.BigEndian.PutUint16(b[14:16], t.Window)
	binary.BigEndian.PutUint16(b[16:18], t.Checksum)
	binary.BigEndian.PutUint16(b[18:20], t.UrgPtr)
	if len(t.Options) > 0 {
		copy(b[20:], t.Options)
	}
	return b
}

func (t *TCP) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 20 {
		return data, fmt.Errorf("tcp: need 20 bytes, got %d", len(data))
	}
	t.SrcPort = binary.BigEndian.Uint16(data[0:2])
	t.DstPort = binary.BigEndian.Uint16(data[2:4])
	t.Seq = binary.BigEndian.Uint32(data[4:8])
	t.Ack = binary.BigEndian.Uint32(data[8:12])
	t.DataOff = data[12] >> 4
	t.Flags = data[13]
	t.Window = binary.BigEndian.Uint16(data[14:16])
	t.Checksum = binary.BigEndian.Uint16(data[16:18])
	t.UrgPtr = binary.BigEndian.Uint16(data[18:20])
	doffBytes := int(t.DataOff) * 4
	if doffBytes > 20 && len(data) >= doffBytes {
		t.Options = make([]byte, doffBytes-20)
		copy(t.Options, data[20:doffBytes])
	}
	return data[doffBytes:], nil
}

func (t *TCP) Next(data []byte) Layer {
	if len(data) > 0 && IsTLS(data) {
		return &TLSRecord{}
	}
	return nil
}

func (t *TCP) SetSPort(p uint16) *TCP  { t.SrcPort = p; return t }
func (t *TCP) SetDPort(p uint16) *TCP  { t.DstPort = p; return t }
func (t *TCP) SetSeq(s uint32) *TCP    { t.Seq = s; return t }
func (t *TCP) SetAck(a uint32) *TCP    { t.Ack = a; return t }
func (t *TCP) SetFlags(f uint8) *TCP   { t.Flags = f; return t }
func (t *TCP) SetWindow(w uint16) *TCP { t.Window = w; return t }

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func NewUDP() *UDP {
	return &UDP{
		SrcPort: uint16(RandInt(1024, 65535)),
		DstPort: 53,
		Length:  8,
	}
}

func (u *UDP) Tag() string { return "UDP" }
func (u *UDP) Len() int    { return 8 }

func (u *UDP) Copy() Layer {
	return &UDP{SrcPort: u.SrcPort, DstPort: u.DstPort, Length: u.Length, Checksum: u.Checksum}
}

func (u *UDP) Serialize() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], u.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], u.DstPort)
	binary.BigEndian.PutUint16(b[4:6], u.Length)
	binary.BigEndian.PutUint16(b[6:8], u.Checksum)
	return b
}

func (u *UDP) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return data, fmt.Errorf("udp: need 8 bytes, got %d", len(data))
	}
	u.SrcPort = binary.BigEndian.Uint16(data[0:2])
	u.DstPort = binary.BigEndian.Uint16(data[2:4])
	u.Length = binary.BigEndian.Uint16(data[4:6])
	u.Checksum = binary.BigEndian.Uint16(data[6:8])
	return data[8:], nil
}

func (u *UDP) Next(data []byte) Layer { return nil }

func (u *UDP) SetSPort(p uint16) *UDP { u.SrcPort = p; return u }
func (u *UDP) SetDPort(p uint16) *UDP { u.DstPort = p; return u }

type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Payload  []byte
}

const (
	ICMP_ECHO_REPLY   uint8 = 0
	ICMP_ECHO_REQUEST uint8 = 8
	ICMP_DST_UNREACH  uint8 = 3
	ICMP_TIME_EXCEED  uint8 = 11
)

func NewICMP() *ICMP {
	return &ICMP{
		Type: ICMP_ECHO_REQUEST,
		Code: 0,
		ID:   uint16(RandID()),
		Seq:  1,
	}
}

func (ic *ICMP) Tag() string { return "ICMP" }
func (ic *ICMP) Len() int    { return 8 }

func (ic *ICMP) Copy() Layer {
	n := &ICMP{Type: ic.Type, Code: ic.Code, Checksum: ic.Checksum, ID: ic.ID, Seq: ic.Seq}
	if len(ic.Payload) > 0 {
		n.Payload = make([]byte, len(ic.Payload))
		copy(n.Payload, ic.Payload)
	}
	return n
}

func (ic *ICMP) Serialize() []byte {
	b := make([]byte, 8+len(ic.Payload))
	b[0] = ic.Type
	b[1] = ic.Code
	binary.BigEndian.PutUint16(b[4:6], ic.ID)
	binary.BigEndian.PutUint16(b[6:8], ic.Seq)
	if len(ic.Payload) > 0 {
		copy(b[8:], ic.Payload)
	}
	ic.Checksum = checksum(b)
	binary.BigEndian.PutUint16(b[2:4], ic.Checksum)
	return b
}

func (ic *ICMP) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return data, fmt.Errorf("icmp: need 8 bytes, got %d", len(data))
	}
	ic.Type = data[0]
	ic.Code = data[1]
	ic.Checksum = binary.BigEndian.Uint16(data[2:4])
	ic.ID = binary.BigEndian.Uint16(data[4:6])
	ic.Seq = binary.BigEndian.Uint16(data[6:8])
	if len(data) > 8 {
		ic.Payload = make([]byte, len(data)-8)
		copy(ic.Payload, data[8:])
	}
	return nil, nil
}

func (ic *ICMP) Next(data []byte) Layer { return nil }

type ARP struct {
	HWType    uint16
	ProtoType uint16
	HWLen     uint8
	ProtoLen  uint8
	Op        uint16
	SrcMAC    [6]byte
	SrcIP     [4]byte
	DstMAC    [6]byte
	DstIP     [4]byte
}

const (
	ARP_REQUEST = 1
	ARP_REPLY   = 2
)

func NewARP(op uint16) *ARP {
	return &ARP{
		HWType:    1,
		ProtoType: ETH_P_IP,
		HWLen:     6,
		ProtoLen:  4,
		Op:        op,
	}
}

func (a *ARP) Tag() string { return "ARP" }
func (a *ARP) Len() int    { return 28 }

func (a *ARP) Copy() Layer {
	n := &ARP{
		HWType: a.HWType, ProtoType: a.ProtoType,
		HWLen: a.HWLen, ProtoLen: a.ProtoLen, Op: a.Op,
	}
	copy(n.SrcMAC[:], a.SrcMAC[:])
	copy(n.SrcIP[:], a.SrcIP[:])
	copy(n.DstMAC[:], a.DstMAC[:])
	copy(n.DstIP[:], a.DstIP[:])
	return n
}

func (a *ARP) Serialize() []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:2], a.HWType)
	binary.BigEndian.PutUint16(b[2:4], a.ProtoType)
	b[4] = a.HWLen
	b[5] = a.ProtoLen
	binary.BigEndian.PutUint16(b[6:8], a.Op)
	copy(b[8:14], a.SrcMAC[:])
	copy(b[14:18], a.SrcIP[:])
	copy(b[18:24], a.DstMAC[:])
	copy(b[24:28], a.DstIP[:])
	return b
}

func (a *ARP) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 28 {
		return data, fmt.Errorf("arp: need 28 bytes, got %d", len(data))
	}
	a.HWType = binary.BigEndian.Uint16(data[0:2])
	a.ProtoType = binary.BigEndian.Uint16(data[2:4])
	a.HWLen = data[4]
	a.ProtoLen = data[5]
	a.Op = binary.BigEndian.Uint16(data[6:8])
	copy(a.SrcMAC[:], data[8:14])
	copy(a.SrcIP[:], data[14:18])
	copy(a.DstMAC[:], data[18:24])
	copy(a.DstIP[:], data[24:28])
	return data[28:], nil
}

func (a *ARP) Next(data []byte) Layer { return nil }

func (a *ARP) Request() *ARP           { a.Op = ARP_REQUEST; return a }
func (a *ARP) Reply() *ARP             { a.Op = ARP_REPLY; return a }
func (a *ARP) SrcMACStr(s string) *ARP { a.SrcMAC = MAC(s); return a }
func (a *ARP) DstMACStr(s string) *ARP { a.DstMAC = MAC(s); return a }
func (a *ARP) SrcIPStr(s string) *ARP  { a.SrcIP = IP(s); return a }
func (a *ARP) DstIPStr(s string) *ARP  { a.DstIP = IP(s); return a }

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TCPChecksum(tcp *TCP, srcIP, dstIP [4]byte) uint16 {
	tcpLen := len(tcp.Serialize())
	pseudoLen := 12 + tcpLen
	pseudo := make([]byte, pseudoLen)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = IP_PROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], tcp.Serialize())
	return checksum(pseudo)
}

func UDPChecksum(udp *UDP, srcIP, dstIP [4]byte) uint16 {
	udpLen := len(udp.Serialize())
	pseudoLen := 12 + udpLen
	pseudo := make([]byte, pseudoLen)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = IP_PROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))
	copy(pseudo[12:], udp.Serialize())
	cs := checksum(pseudo)
	if cs == 0 {
		cs = 0xFFFF
	}
	return cs
}
