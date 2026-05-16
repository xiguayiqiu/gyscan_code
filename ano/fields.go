package ano

type FieldDesc struct {
	Name   string
	Offset int
	Len    int
}

type FieldLayer interface {
	Layer
	Fields() []FieldDesc
	GetField(name string) interface{}
	SetField(name string, val interface{})
}

type layerFactory func() Layer

var bindingMap = map[uint16]layerFactory{}

func RegisterBinding(proto uint16, factory layerFactory) {
	bindingMap[proto] = factory
}

func LookupBinding(proto uint16) Layer {
	if f, ok := bindingMap[proto]; ok {
		return f()
	}
	return nil
}

func FuzzLayer(l Layer) {
	if f, ok := l.(fuzzable); ok {
		f.Fuzz()
	}
}

type fuzzable interface {
	Fuzz()
}

func (e *Ether) Fuzz() {
	e.Dst = randomMAC()
	e.Src = randomMAC()
	e.Type = uint16(RandInt(0, 65535))
}

func (e *Ether) Fields() []FieldDesc {
	return []FieldDesc{
		{"Dst", 0, 6},
		{"Src", 6, 6},
		{"Type", 12, 2},
	}
}

func (e *Ether) GetField(name string) interface{} {
	switch name {
	case "Dst":
		return e.Dst
	case "Src":
		return e.Src
	case "Type":
		return e.Type
	}
	return nil
}

func (e *Ether) SetField(name string, val interface{}) {
	switch name {
	case "Dst":
		if v, ok := val.([6]byte); ok {
			e.Dst = v
		}
	case "Src":
		if v, ok := val.([6]byte); ok {
			e.Src = v
		}
	case "Type":
		if v, ok := val.(uint16); ok {
			e.Type = v
		}
	}
}

func (ip *IPv4) Fuzz() {
	ip.Version = 4
	ip.IHL = 5
	ip.TOS = uint8(RandInt(0, 255))
	ip.ID = uint16(RandInt(0, 65535))
	ip.TTL = uint8(RandTTL())
	ip.Protocol = uint8(RandChoice(int(IP_PROTO_TCP), int(IP_PROTO_UDP), int(IP_PROTO_ICMP)))
	ip.Src = randomIPv4()
	ip.Dst = randomIPv4()
}

func (t *TCP) Fuzz() {
	t.SrcPort = uint16(RandPort())
	t.DstPort = uint16(RandPort())
	t.Seq = RandSeq()
	t.Ack = uint32(RandInt(0, 1<<32-1))
	t.Flags = uint8(RandChoice(int(TCP_SYN), int(TCP_ACK), int(TCP_SYN|TCP_ACK), int(TCP_FIN), int(TCP_RST)))
	t.Window = uint16(RandChoice(14600, 29200, 5840, 65535, 8192))
}

func (u *UDP) Fuzz() {
	u.SrcPort = uint16(RandPort())
	u.DstPort = uint16(RandPort())
}

func (ic *ICMP) Fuzz() {
	ic.Type = uint8(RandChoice(int(ICMP_ECHO_REQUEST), int(ICMP_ECHO_REPLY), int(ICMP_DST_UNREACH)))
	ic.Code = 0
	ic.ID = uint16(RandID())
	ic.Seq = uint16(RandInt(0, 65535))
}

func (a *ARP) Fuzz() {
	a.Op = uint16(RandChoice(ARP_REQUEST, ARP_REPLY))
	a.SrcMAC = randomMAC()
	a.SrcIP = randomIPv4()
	a.DstMAC = randomMAC()
	a.DstIP = randomIPv4()
}

func randomMAC() [6]byte {
	var mac [6]byte
	for i := range mac {
		mac[i] = byte(RandInt(0, 255))
	}
	return mac
}

func randomIPv4() [4]byte {
	var ip [4]byte
	ip[0] = byte(RandInt(1, 223))
	ip[1] = byte(RandInt(0, 255))
	ip[2] = byte(RandInt(0, 255))
	ip[3] = byte(RandInt(1, 254))
	return ip
}

type FuzzOpts struct {
	RandIP     bool
	RandMAC    bool
	RandPort   bool
	RandSeq    bool
	RandTTL    bool
	RandFlags  bool
	RandWindow bool
	RandID     bool
}

func DefaultFuzzOpts() *FuzzOpts {
	return &FuzzOpts{
		RandIP:     true,
		RandMAC:    true,
		RandPort:   true,
		RandSeq:    true,
		RandTTL:    true,
		RandFlags:  true,
		RandWindow: true,
		RandID:     true,
	}
}

func FuzzPacket(pkt *Packet, opts *FuzzOpts) *Packet {
	if opts == nil {
		opts = DefaultFuzzOpts()
	}
	for _, l := range pkt.Layers {
		switch v := l.(type) {
		case *Ether:
			if opts.RandMAC {
				v.Dst = randomMAC()
				v.Src = randomMAC()
			}
		case *IPv4:
			if opts.RandIP {
				v.Src = randomIPv4()
				v.Dst = randomIPv4()
			}
			if opts.RandTTL {
				v.TTL = uint8(RandTTL())
			}
			if opts.RandID {
				v.ID = uint16(RandInt(0, 65535))
			}
		case *TCP:
			if opts.RandPort {
				v.SrcPort = uint16(RandPort())
				v.DstPort = uint16(RandPort())
			}
			if opts.RandSeq {
				v.Seq = RandSeq()
			}
			if opts.RandFlags {
				v.Flags = uint8(RandChoice(int(TCP_SYN), int(TCP_ACK), int(TCP_SYN|TCP_ACK)))
			}
			if opts.RandWindow {
				v.Window = uint16(RandChoice(14600, 29200, 5840, 65535))
			}
		case *UDP:
			if opts.RandPort {
				v.SrcPort = uint16(RandPort())
				v.DstPort = uint16(RandPort())
			}
		case *ICMP:
			v.Type = uint8(RandChoice(int(ICMP_ECHO_REQUEST), int(ICMP_ECHO_REPLY)))
			v.ID = uint16(RandID())
		case *ARP:
			if opts.RandMAC {
				v.SrcMAC = randomMAC()
				v.DstMAC = randomMAC()
			}
			if opts.RandIP {
				v.SrcIP = randomIPv4()
				v.DstIP = randomIPv4()
			}
		}
	}
	return pkt
}

func RandIPLayer(l Layer) {
	switch v := l.(type) {
	case *Ether:
		v.Dst = randomMAC()
		v.Src = randomMAC()
	case *IPv4:
		v.Src = randomIPv4()
		v.Dst = randomIPv4()
	case *TCP:
		v.SrcPort = uint16(RandPort())
		v.DstPort = uint16(RandPort())
		v.Seq = uint32(RandInt(0, 1<<32-1))
	case *UDP:
		v.SrcPort = uint16(RandPort())
		v.DstPort = uint16(RandPort())
	}
}
