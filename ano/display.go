package ano

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type DFNodeType int

const (
	DF_CMP  DFNodeType = iota
	DF_AND
	DF_OR
	DF_NOT
)

type DFNode struct {
	Type    DFNodeType
	Field   string
	Op      string
	Value   string
	Left    *DFNode
	Right   *DFNode
	Negated bool
}

type DisplayFilter struct {
	root *DFNode
}

func (df *DisplayFilter) Match(pkt *Packet) bool {
	if df.root == nil {
		return true
	}
	return evalNode(df.root, pkt)
}

func (df *DisplayFilter) String() string {
	if df.root == nil {
		return ""
	}
	return nodeString(df.root)
}

func evalNode(n *DFNode, pkt *Packet) bool {
	switch n.Type {
	case DF_CMP:
		val, ok := getFieldValue(pkt, n.Field)
		if !ok {
			return false
		}
		return compare(val, n.Op, n.Value)
	case DF_AND:
		l := evalNode(n.Left, pkt)
		if !l {
			return false
		}
		return evalNode(n.Right, pkt)
	case DF_OR:
		l := evalNode(n.Left, pkt)
		if l {
			return true
		}
		return evalNode(n.Right, pkt)
	case DF_NOT:
		return !evalNode(n.Left, pkt)
	}
	return false
}

func nodeString(n *DFNode) string {
	switch n.Type {
	case DF_CMP:
		return fmt.Sprintf("%s%s%s", n.Field, n.Op, n.Value)
	case DF_AND:
		return fmt.Sprintf("(%s && %s)", nodeString(n.Left), nodeString(n.Right))
	case DF_OR:
		return fmt.Sprintf("(%s || %s)", nodeString(n.Left), nodeString(n.Right))
	case DF_NOT:
		return fmt.Sprintf("!%s", nodeString(n.Left))
	}
	return ""
}

func getFieldValue(pkt *Packet, field string) (string, bool) {
	switch {
	case field == "frame.number":
		return "", false
	case field == "frame.len":
		return strconv.Itoa(len(pkt.Bytes())), true
	case field == "frame.cap_len":
		return strconv.Itoa(len(pkt.Bytes())), true
	case field == "ip.version":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		return strconv.Itoa(int(ip.(*IPv4).Version)), true
	case field == "ip.src":
		ip := pkt.Get("IPv4")
		if ip == nil {
			ip = pkt.Get("IPv6")
			if ip == nil {
				return "", false
			}
			return net.IP(ip.(*IPv6).Src[:]).String(), true
		}
		return IPBytes(ip.(*IPv4).Src), true
	case field == "ip.dst":
		ip := pkt.Get("IPv4")
		if ip == nil {
			ip = pkt.Get("IPv6")
			if ip == nil {
				return "", false
			}
			return net.IP(ip.(*IPv6).Dst[:]).String(), true
		}
		return IPBytes(ip.(*IPv4).Dst), true
	case field == "ip.ttl":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		return strconv.Itoa(int(ip.(*IPv4).TTL)), true
	case field == "ip.id":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		return strconv.Itoa(int(ip.(*IPv4).ID)), true
	case field == "ip.flags.df":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		if (ip.(*IPv4).FragOff>>13)&0x04 != 0 {
			return "1", true
		}
		return "0", true
	case field == "ip.flags.mf":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		if (ip.(*IPv4).FragOff>>13)&0x02 != 0 {
			return "1", true
		}
		return "0", true
	case field == "ip.frag_offset":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		return strconv.Itoa(int(ip.(*IPv4).FragOff & 0x1FFF)), true
	case field == "ip.proto":
		ip := pkt.Get("IPv4")
		if ip == nil {
			return "", false
		}
		return strconv.Itoa(int(ip.(*IPv4).Protocol)), true
	case field == "tcp.srcport":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).SrcPort)), true
	case field == "tcp.dstport":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).DstPort)), true
	case field == "tcp.port":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).SrcPort)) + "," + strconv.Itoa(int(tcp.(*TCP).DstPort)), true
	case field == "tcp.seq":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).Seq)), true
	case field == "tcp.ack":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).Ack)), true
	case field == "tcp.len":
		return "", false
	case field == "tcp.hdr_len":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		do := tcp.(*TCP).DataOff
		if do == 0 {
			do = 5
		}
		return strconv.Itoa(int(do * 4)), true
	case field == "tcp.flags":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return fmt.Sprintf("0x%02x", tcp.(*TCP).Flags), true
	case field == "tcp.flags.syn":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_SYN != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.ack":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_ACK != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.fin":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_FIN != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.rst":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_RST != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.psh":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_PSH != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.urg":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_URG != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.cwr":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_CWR != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.flags.ece":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		if tcp.(*TCP).Flags&TCP_ECE != 0 {
			return "1", true
		}
		return "0", true
	case field == "tcp.window_size":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).Window)), true
	case field == "tcp.checksum":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return fmt.Sprintf("0x%04x", tcp.(*TCP).Checksum), true
	case field == "tcp.urgent_pointer":
		tcp := pkt.Get("TCP")
		if tcp == nil {
			return "", false
		}
		return strconv.Itoa(int(tcp.(*TCP).UrgPtr)), true
	case field == "udp.srcport":
		udp := pkt.Get("UDP")
		if udp == nil {
			return "", false
		}
		return strconv.Itoa(int(udp.(*UDP).SrcPort)), true
	case field == "udp.dstport":
		udp := pkt.Get("UDP")
		if udp == nil {
			return "", false
		}
		return strconv.Itoa(int(udp.(*UDP).DstPort)), true
	case field == "udp.port":
		udp := pkt.Get("UDP")
		if udp == nil {
			return "", false
		}
		return strconv.Itoa(int(udp.(*UDP).SrcPort)) + "," + strconv.Itoa(int(udp.(*UDP).DstPort)), true
	case field == "udp.length":
		udp := pkt.Get("UDP")
		if udp == nil {
			return "", false
		}
		return strconv.Itoa(int(udp.(*UDP).Length)), true
	case field == "udp.checksum":
		udp := pkt.Get("UDP")
		if udp == nil {
			return "", false
		}
		return fmt.Sprintf("0x%04x", udp.(*UDP).Checksum), true
	case field == "icmp.type":
		icmp := pkt.Get("ICMP")
		if icmp == nil {
			return "", false
		}
		return strconv.Itoa(int(icmp.(*ICMP).Type)), true
	case field == "icmp.code":
		icmp := pkt.Get("ICMP")
		if icmp == nil {
			return "", false
		}
		return strconv.Itoa(int(icmp.(*ICMP).Code)), true
	case field == "icmp.identifier":
		icmp := pkt.Get("ICMP")
		if icmp == nil {
			return "", false
		}
		return strconv.Itoa(int(icmp.(*ICMP).ID)), true
	case field == "icmp.sequence":
		icmp := pkt.Get("ICMP")
		if icmp == nil {
			return "", false
		}
		return strconv.Itoa(int(icmp.(*ICMP).Seq)), true
	case field == "arp.src.hw_mac":
		arp := pkt.Get("ARP")
		if arp == nil {
			return "", false
		}
		return MACString(arp.(*ARP).SrcMAC), true
	case field == "arp.dst.hw_mac":
		arp := pkt.Get("ARP")
		if arp == nil {
			return "", false
		}
		return MACString(arp.(*ARP).DstMAC), true
	case field == "arp.src.proto_ipv4":
		arp := pkt.Get("ARP")
		if arp == nil {
			return "", false
		}
		return IPBytes(arp.(*ARP).SrcIP), true
	case field == "arp.dst.proto_ipv4":
		arp := pkt.Get("ARP")
		if arp == nil {
			return "", false
		}
		return IPBytes(arp.(*ARP).DstIP), true
	case field == "arp.opcode":
		arp := pkt.Get("ARP")
		if arp == nil {
			return "", false
		}
		return strconv.Itoa(int(arp.(*ARP).Op)), true
	case field == "dns.id":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		return strconv.Itoa(int(dns.(*DNS).ID)), true
	case field == "dns.flags.response":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		if dns.(*DNS).Flags&uint16(DNS_QR_RESP) != 0 {
			return "1", true
		}
		return "0", true
	case field == "dns.flags.opcode":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		return strconv.Itoa(int((dns.(*DNS).Flags >> 11) & 0xF)), true
	case field == "dns.flags.aa":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		if dns.(*DNS).Flags&uint16(DNS_AA) != 0 {
			return "1", true
		}
		return "0", true
	case field == "dns.flags.tc":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		if dns.(*DNS).Flags&uint16(DNS_TC) != 0 {
			return "1", true
		}
		return "0", true
	case field == "dns.flags.rd":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		if dns.(*DNS).Flags&uint16(DNS_RD) != 0 {
			return "1", true
		}
		return "0", true
	case field == "dns.flags.ra":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		if dns.(*DNS).Flags&uint16(DNS_RA) != 0 {
			return "1", true
		}
		return "0", true
	case field == "dns.qry.name":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		dd := dns.(*DNS)
		if len(dd.Questions) > 0 {
			return dd.Questions[0].Name, true
		}
		return "", false
	case field == "dns.qry.type":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		dd := dns.(*DNS)
		if len(dd.Questions) > 0 {
			return strconv.Itoa(int(dd.Questions[0].Type)), true
		}
		return "", false
	case field == "dns.resp.name":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		dd := dns.(*DNS)
		if len(dd.Answers) > 0 {
			return dd.Answers[0].Name, true
		}
		return "", false
	case field == "dns.resp.type":
		dns := pkt.Get("DNS")
		if dns == nil {
			return "", false
		}
		dd := dns.(*DNS)
		if len(dd.Answers) > 0 {
			return strconv.Itoa(int(dd.Answers[0].Type)), true
		}
		return "", false
	case field == "eth.src":
		eth := pkt.Get("Ether")
		if eth == nil {
			return "", false
		}
		return MACString(eth.(*Ether).Src), true
	case field == "eth.dst":
		eth := pkt.Get("Ether")
		if eth == nil {
			return "", false
		}
		return MACString(eth.(*Ether).Dst), true
	case field == "eth.type":
		eth := pkt.Get("Ether")
		if eth == nil {
			return "", false
		}
		return fmt.Sprintf("0x%04x", eth.(*Ether).Type), true
	case field == "tls.record.content_type":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return strconv.Itoa(int(tls.(*TLSRecord).ContentType)), true
	case field == "tls.record.version":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return fmt.Sprintf("0x%04x", tls.(*TLSRecord).Version), true
	case field == "tls.handshake.type":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return strconv.Itoa(int(tls.(*TLSRecord).HandshakeType)), true
	case field == "tls.handshake.version":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return fmt.Sprintf("0x%04x", tls.(*TLSRecord).ClientVersion), true
	case field == "tls.handshake.cipher_suite":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		tr := tls.(*TLSRecord)
		if len(tr.CipherSuites) == 0 {
			return "", false
		}
		var csStr string
		for i, cs := range tr.CipherSuites {
			if i > 0 {
				csStr += ","
			}
			csStr += fmt.Sprintf("0x%04x", cs)
		}
		return csStr, true
	case field == "tls.handshake.sni":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		sni := tls.(*TLSRecord).ServerName
		if sni == "" {
			return "", false
		}
		return sni, true
	case field == "tls.handshake.extensions":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return strconv.Itoa(len(tls.(*TLSRecord).Extensions)), true
	case field == "tls.alert.level":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return strconv.Itoa(int(tls.(*TLSRecord).AlertLevel)), true
	case field == "tls.alert.description":
		tls := pkt.Get("TLS")
		if tls == nil {
			return "", false
		}
		return strconv.Itoa(int(tls.(*TLSRecord).AlertDesc)), true
	}
	return "", false
}

func compare(fieldVal, op, filterVal string) bool {
	switch op {
	case "==":
		return compareEqual(fieldVal, filterVal)
	case "!=":
		return !compareEqual(fieldVal, filterVal)
	case ">":
		return compareNumeric(fieldVal, filterVal) > 0
	case "<":
		return compareNumeric(fieldVal, filterVal) < 0
	case ">=":
		return compareNumeric(fieldVal, filterVal) >= 0
	case "<=":
		return compareNumeric(fieldVal, filterVal) <= 0
	case "contains":
		return strings.Contains(fieldVal, filterVal)
	}
	return false
}

func compareEqual(a, b string) bool {
	if a == b {
		return true
	}
	an, ae := strconv.ParseInt(a, 0, 64)
	bn, be := strconv.ParseInt(b, 0, 64)
	if ae == nil && be == nil {
		return an == bn
	}
	au, aue := strconv.ParseUint(a, 0, 64)
	bu, bue := strconv.ParseUint(b, 0, 64)
	if aue == nil && bue == nil {
		return au == bu
	}
	if strings.Contains(a, ",") {
		parts := strings.Split(a, ",")
		for _, p := range parts {
			if strings.TrimSpace(p) == strings.TrimSpace(b) {
				return true
			}
		}
	}
	return false
}

func compareNumeric(a, b string) int {
	an, ae := strconv.ParseInt(a, 0, 64)
	bn, be := strconv.ParseInt(b, 0, 64)
	if ae == nil && be == nil {
		if an < bn {
			return -1
		}
		if an > bn {
			return 1
		}
		return 0
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

type dfTokenizer struct {
	expr string
	pos  int
}

type dfToken struct {
	kind  string
	value string
}

func (t *dfTokenizer) next() *dfToken {
	t.skipSpace()
	if t.pos >= len(t.expr) {
		return nil
	}
	c := t.expr[t.pos]

	if c == '(' {
		t.pos++
		return &dfToken{kind: "(", value: "("}
	}
	if c == ')' {
		t.pos++
		return &dfToken{kind: ")", value: ")"}
	}
	if c == '!' && t.pos+1 < len(t.expr) && t.expr[t.pos+1] == '=' {
		t.pos += 2
		return &dfToken{kind: "op", value: "!="}
	}
	if c == '!' {
		t.pos++
		return &dfToken{kind: "!", value: "!"}
	}
	if c == '=' && t.pos+1 < len(t.expr) && t.expr[t.pos+1] == '=' {
		t.pos += 2
		return &dfToken{kind: "op", value: "=="}
	}
	if c == '>' && t.pos+1 < len(t.expr) && t.expr[t.pos+1] == '=' {
		t.pos += 2
		return &dfToken{kind: "op", value: ">="}
	}
	if c == '<' && t.pos+1 < len(t.expr) && t.expr[t.pos+1] == '=' {
		t.pos += 2
		return &dfToken{kind: "op", value: "<="}
	}
	if c == '>' {
		t.pos++
		return &dfToken{kind: "op", value: ">"}
	}
	if c == '<' {
		t.pos++
		return &dfToken{kind: "op", value: "<"}
	}
	if c == '&' && t.pos+1 < len(t.expr) && t.expr[t.pos+1] == '&' {
		t.pos += 2
		return &dfToken{kind: "&&", value: "&&"}
	}
	if c == '|' && t.pos+1 < len(t.expr) && t.expr[t.pos+1] == '|' {
		t.pos += 2
		return &dfToken{kind: "||", value: "||"}
	}

	if c == '"' || c == '\'' {
		quote := c
		t.pos++
		start := t.pos
		for t.pos < len(t.expr) && t.expr[t.pos] != quote {
			t.pos++
		}
		val := t.expr[start:t.pos]
		if t.pos < len(t.expr) {
			t.pos++
		}
		return &dfToken{kind: "value", value: val}
	}

	if isFieldChar(c) {
		start := t.pos
		for t.pos < len(t.expr) && isFieldChar(t.expr[t.pos]) {
			t.pos++
		}
		word := t.expr[start:t.pos]

		if word == "contains" {
			return &dfToken{kind: "op", value: "contains"}
		}
		if word == "true" || word == "false" {
			return &dfToken{kind: "value", value: word}
		}

		if t.pos < len(t.expr) && isOpStart(t.expr[t.pos]) {
			return &dfToken{kind: "field", value: word}
		}

		return &dfToken{kind: "value", value: word}
	}

	if isDigit(c) {
		start := t.pos
		if c == '0' && t.pos+1 < len(t.expr) && (t.expr[t.pos+1] == 'x' || t.expr[t.pos+1] == 'X') {
			t.pos += 2
			for t.pos < len(t.expr) && isHexDigit(t.expr[t.pos]) {
				t.pos++
			}
		} else {
			for t.pos < len(t.expr) && (isDigit(t.expr[t.pos]) || t.expr[t.pos] == '.') {
				t.pos++
			}
		}
		return &dfToken{kind: "value", value: t.expr[start:t.pos]}
	}

	t.pos++
	return &dfToken{kind: "value", value: string(c)}
}

func (t *dfTokenizer) skipSpace() {
	for t.pos < len(t.expr) && t.expr[t.pos] == ' ' {
		t.pos++
	}
}

func isFieldChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.'
}

func isOpStart(c byte) bool {
	return c == '=' || c == '!' || c == '>' || c == '<' || c == ' '
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

type dfParser struct {
	t   *dfTokenizer
	tok *dfToken
}

func (p *dfParser) advance() {
	p.tok = p.t.next()
}

func (p *dfParser) parse() (*DFNode, error) {
	p.advance()
	if p.tok == nil {
		return nil, nil
	}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.tok != nil {
		return nil, fmt.Errorf("意外的标记: %s", p.tok.value)
	}
	return node, nil
}

func (p *dfParser) parseOr() (*DFNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.tok != nil && p.tok.kind == "||" {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &DFNode{Type: DF_OR, Left: left, Right: right}
	}
	return left, nil
}

func (p *dfParser) parseAnd() (*DFNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.tok != nil && p.tok.kind == "&&" {
		p.advance()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &DFNode{Type: DF_AND, Left: left, Right: right}
	}
	return left, nil
}

func (p *dfParser) parseNot() (*DFNode, error) {
	if p.tok != nil && p.tok.kind == "!" {
		p.advance()
		child, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		return &DFNode{Type: DF_NOT, Left: child}, nil
	}
	return p.parseAtom()
}

func (p *dfParser) parseAtom() (*DFNode, error) {
	if p.tok == nil {
		return nil, fmt.Errorf("表达式不完整")
	}
	if p.tok.kind == "(" {
		p.advance()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.tok == nil || p.tok.kind != ")" {
			return nil, fmt.Errorf("缺少右括号")
		}
		p.advance()
		return node, nil
	}
	return p.parseComparison()
}

func (p *dfParser) parseComparison() (*DFNode, error) {
	if p.tok == nil || p.tok.kind != "field" {
		return nil, fmt.Errorf("期望字段名，得到: %v", p.tok)
	}
	field := p.tok.value
	p.advance()
	if p.tok == nil || p.tok.kind != "op" {
		return nil, fmt.Errorf("期望操作符 (==, !=, >, <, >=, <=, contains)")
	}
	op := p.tok.value
	p.advance()
	if p.tok == nil || p.tok.kind != "value" {
		return nil, fmt.Errorf("期望值")
	}
	value := p.tok.value
	p.advance()
	return &DFNode{Type: DF_CMP, Field: field, Op: op, Value: value}, nil
}

func ParseDisplayFilter(expr string) (*DisplayFilter, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return &DisplayFilter{}, nil
	}
	t := &dfTokenizer{expr: expr}
	p := &dfParser{t: t}
	root, err := p.parse()
	if err != nil {
		return nil, err
	}
	return &DisplayFilter{root: root}, nil
}

func (pl *PacketList) FilterByDisplay(expr string) (*PacketList, error) {
	df, err := ParseDisplayFilter(expr)
	if err != nil {
		return nil, err
	}
	result := NewPacketList()
	if df.root == nil {
		for _, p := range pl.Packets {
			result.Add(p)
		}
		return result, nil
	}
	for i, pkt := range pl.Packets {
		if df.Match(pkt) {
			_ = i
			result.Add(pkt)
		}
	}
	return result, nil
}

func MatchFilter(pkt *Packet, expr string) (bool, error) {
	df, err := ParseDisplayFilter(expr)
	if err != nil {
		return false, err
	}
	return df.Match(pkt), nil
}

func FilterPackets(pkts []*Packet, expr string) ([]*Packet, error) {
	df, err := ParseDisplayFilter(expr)
	if err != nil {
		return nil, err
	}
	var result []*Packet
	for _, pkt := range pkts {
		if df.Match(pkt) {
			result = append(result, pkt)
		}
	}
	return result, nil
}

func CountByFilter(pkts []*Packet, expr string) (int, error) {
	filtered, err := FilterPackets(pkts, expr)
	if err != nil {
		return 0, err
	}
	return len(filtered), nil
}

func FirstByFilter(pkts []*Packet, expr string) (*Packet, error) {
	df, err := ParseDisplayFilter(expr)
	if err != nil {
		return nil, err
	}
	for _, pkt := range pkts {
		if df.Match(pkt) {
			return pkt, nil
		}
	}
	return nil, nil
}