package ano

import (
	"testing"
)

func TestDisplayFilter(t *testing.T) {
	pkt1 := Build(
		&Ether{Src: [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, Dst: [6]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, Type: 0x0800},
		&IPv4{Src: [4]byte{192, 168, 1, 100}, Dst: [4]byte{10, 0, 0, 1}, TTL: 64, Protocol: 6},
		&TCP{SrcPort: 12345, DstPort: 80, Flags: TCP_SYN, Window: 65535},
	)
	pkt2 := Build(
		&Ether{Src: [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, Dst: [6]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, Type: 0x0800},
		&IPv4{Src: [4]byte{192, 168, 1, 200}, Dst: [4]byte{10, 0, 0, 2}, TTL: 128, Protocol: 17},
		&UDP{SrcPort: 53, DstPort: 54321, Length: 60},
	)

	pl := NewPacketList()
	pl.Add(pkt1)
	pl.Add(pkt2)

	tests := []struct {
		expr    string
		matchP1 bool
		matchP2 bool
	}{
		{"tcp.port==80", true, false},
		{"tcp.srcport==12345", true, false},
		{"tcp.dstport==80", true, false},
		{"ip.src==192.168.1.100", true, false},
		{"ip.dst==10.0.0.1", true, false},
		{"udp.port==53", false, true},
		{"udp.srcport==53", false, true},
		{"ip.ttl==64", true, false},
		{"ip.ttl>100", false, true},
		{"ip.ttl<100", true, false},
		{"tcp.flags.syn==1", true, false},
		{"tcp.flags.syn==0", false, false},
		{"tcp.flags.ack==0", true, false},
		{"tcp.flags.ack==0 || udp.srcport==53", true, true},
		{"ip.src==192.168.1.100 && tcp.port==80", true, false},
		{"ip.src==192.168.1.100 || udp.port==53", true, true},
		{"!(tcp.port==80)", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			df, err := ParseDisplayFilter(tt.expr)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if df.Match(pkt1) != tt.matchP1 {
				t.Errorf("数据包1: 期望 %v, 得到 %v", tt.matchP1, df.Match(pkt1))
			}
			if df.Match(pkt2) != tt.matchP2 {
				t.Errorf("数据包2: 期望 %v, 得到 %v", tt.matchP2, df.Match(pkt2))
			}
		})
	}
}

func TestMatchFilter(t *testing.T) {
	pkt := Build(
		&Ether{Type: 0x0800},
		&IPv4{Src: [4]byte{10, 0, 0, 1}, Dst: [4]byte{8, 8, 8, 8}, TTL: 64, Protocol: 6},
		&TCP{SrcPort: 12345, DstPort: 80, Flags: TCP_SYN},
	)

	ok, err := MatchFilter(pkt, "tcp.port==80")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("期望 true")
	}

	ok, err = MatchFilter(pkt, "tcp.port==443")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("期望 false")
	}
}

func TestFilterPackets(t *testing.T) {
	pkt1 := Build(&Ether{Type: 0x0800}, &IPv4{Src: [4]byte{1, 1, 1, 1}}, &TCP{SrcPort: 1111, DstPort: 80, Flags: TCP_SYN})
	pkt2 := Build(&Ether{Type: 0x0800}, &IPv4{Src: [4]byte{2, 2, 2, 2}}, &UDP{SrcPort: 53})
	pkt3 := Build(&Ether{Type: 0x0800}, &IPv4{Src: [4]byte{3, 3, 3, 3}}, &TCP{SrcPort: 3333, DstPort: 443, Flags: TCP_ACK})
	pkts := []*Packet{pkt1, pkt2, pkt3}

	filtered, err := FilterPackets(pkts, "tcp.port==80")
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Errorf("期望 1, 得到 %d", len(filtered))
	}

	count, err := CountByFilter(pkts, "tcp.flags.syn==1")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("期望 1, 得到 %d", count)
	}

	first, err := FirstByFilter(pkts, "udp.port==53")
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Error("期望非 nil")
	}

	none, err := FirstByFilter(pkts, "icmp.type==8")
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Error("期望 nil")
	}
}

func TestTLSDisplayFilter(t *testing.T) {
	tlsPkt := Build(
		&Ether{Type: 0x0800},
		&IPv4{Src: [4]byte{10, 0, 0, 1}, Dst: [4]byte{93, 184, 216, 34}, TTL: 64, Protocol: 6},
		&TCP{SrcPort: 54321, DstPort: 443, Flags: TCP_ACK | TCP_PSH},
		NewTLSClientHello("example.com"),
	)
	plainPkt := Build(
		&Ether{Type: 0x0800},
		&IPv4{Src: [4]byte{10, 0, 0, 1}, Dst: [4]byte{8, 8, 8, 8}, TTL: 64, Protocol: 6},
		&TCP{SrcPort: 12345, DstPort: 80, Flags: TCP_SYN},
	)

	tests := []struct {
		expr       string
		matchTLS   bool
		matchPlain bool
	}{
		{"tcp.dstport==443", true, false},
		{"tcp.port==443", true, false},
		{"tls.record.content_type==22", true, false},
		{"tls.handshake.type==1", true, false},
		{"tls.handshake.sni contains example", true, false},
		{"tls.handshake.sni==example.com", true, false},
		{"tls.handshake.sni==other.com", false, false},
		{"tls.handshake.version==0x0303", true, false},
		{"tls.handshake.extensions>0", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			df, err := ParseDisplayFilter(tt.expr)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if df.Match(tlsPkt) != tt.matchTLS {
				t.Errorf("TLS包: 期望 %v, 得到 %v", tt.matchTLS, df.Match(tlsPkt))
			}
			if df.Match(plainPkt) != tt.matchPlain {
				t.Errorf("普通包: 期望 %v, 得到 %v", tt.matchPlain, df.Match(plainPkt))
			}
		})
	}
}

func TestTLSLayer(t *testing.T) {
	tls := NewTLSClientHello("google.com")
	if tls.Tag() != "TLS" {
		t.Errorf("期望 Tag=TLS, 得到 %s", tls.Tag())
	}
	if tls.Len() < 5 {
		t.Errorf("Len 太短: %d", tls.Len())
	}
	data := tls.Serialize()
	if len(data) < 5 {
		t.Errorf("Serialize 太短: %d", len(data))
	}

	var tls2 TLSRecord
	rest, err := tls2.Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize 失败: %v", err)
	}
	if tls2.ContentType != TLS_HANDSHAKE {
		t.Errorf("ContentType: 期望 %d, 得到 %d", TLS_HANDSHAKE, tls2.ContentType)
	}
	if tls2.ServerName != "google.com" {
		t.Errorf("ServerName: 期望 google.com, 得到 %s", tls2.ServerName)
	}
	_ = rest
}

func TestTLSSerializeRoundtrip(t *testing.T) {
	tls := NewTLSClientHello("test.example.org")
	raw := tls.Serialize()

	var tls2 TLSRecord
	_, err := tls2.Deserialize(raw)
	if err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if tls2.ServerName != "test.example.org" {
		t.Errorf("SNI 解析失败: 期望 test.example.org, 得到 %s", tls2.ServerName)
	}
	if tls2.ContentType != TLS_HANDSHAKE {
		t.Errorf("ContentType: 期望 %d, 得到 %d", TLS_HANDSHAKE, tls2.ContentType)
	}
}