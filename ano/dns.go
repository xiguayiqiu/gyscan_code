package ano

import (
	"encoding/binary"
	"fmt"
)

type DNSFlag uint16

const (
	DNS_QR_QUERY  DNSFlag = 0
	DNS_QR_RESP   DNSFlag = 1 << 15
	DNS_OPCODE    DNSFlag = 0x7800
	DNS_AA        DNSFlag = 1 << 10
	DNS_TC        DNSFlag = 1 << 9
	DNS_RD        DNSFlag = 1 << 8
	DNS_RA        DNSFlag = 1 << 7
)

type DNSType uint16

const (
	DNS_A     DNSType = 1
	DNS_NS    DNSType = 2
	DNS_MD    DNSType = 3
	DNS_MF    DNSType = 4
	DNS_CNAME DNSType = 5
	DNS_SOA   DNSType = 6
	DNS_MX    DNSType = 15
	DNS_TXT   DNSType = 16
	DNS_AAAA  DNSType = 28
	DNS_SRV   DNSType = 33
	DNS_OPT   DNSType = 41
)

type DNSClass uint16

const (
	DNS_IN   DNSClass = 1
	DNS_CH   DNSClass = 3
	DNS_HS   DNSClass = 4
)

type DNS struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
	Questions []DNSQuestion
	Answers   []DNSResource
}

type DNSQuestion struct {
	Name  string
	Type  DNSType
	Class DNSClass
}

type DNSResource struct {
	Name     string
	Type     DNSType
	Class    DNSClass
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func NewDNS() *DNS {
	return &DNS{
		ID:      uint16(RandID()),
		QDCount: 1,
		Flags:   uint16(DNS_RD),
	}
}

func NewDNSQR(name string, qtype DNSType) *DNS {
	dns := NewDNS()
	dns.Questions = []DNSQuestion{{
		Name: name, Type: qtype, Class: DNS_IN,
	}}
	return dns
}

func (d *DNS) Tag() string { return "DNS" }

func (d *DNS) Len() int {
	hdr := 12
	for _, q := range d.Questions {
		hdr += len(q.Name) + 2 + 4
	}
	for _, a := range d.Answers {
		hdr += len(a.Name) + 2 + 10 + int(a.RDLength)
	}
	return hdr
}

func (d *DNS) Copy() Layer {
	n := &DNS{
		ID: d.ID, Flags: d.Flags,
		QDCount: d.QDCount, ANCount: d.ANCount,
		NSCount: d.NSCount, ARCount: d.ARCount,
	}
	n.Questions = append(n.Questions, d.Questions...)
	n.Answers = append(n.Answers, d.Answers...)
	return n
}

func (d *DNS) Serialize() []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], d.ID)
	binary.BigEndian.PutUint16(b[2:4], d.Flags)
	d.QDCount = uint16(len(d.Questions))
	d.ANCount = uint16(len(d.Answers))
	binary.BigEndian.PutUint16(b[4:6], d.QDCount)
	binary.BigEndian.PutUint16(b[6:8], d.ANCount)
	binary.BigEndian.PutUint16(b[8:10], d.NSCount)
	binary.BigEndian.PutUint16(b[10:12], d.ARCount)
	for _, q := range d.Questions {
		b = append(b, encodeDNSName(q.Name)...)
		b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
		b = binary.BigEndian.AppendUint16(b, uint16(q.Class))
	}
	for _, a := range d.Answers {
		b = append(b, encodeDNSName(a.Name)...)
		b = binary.BigEndian.AppendUint16(b, uint16(a.Type))
		b = binary.BigEndian.AppendUint16(b, uint16(a.Class))
		b = binary.BigEndian.AppendUint32(b, a.TTL)
		b = binary.BigEndian.AppendUint16(b, a.RDLength)
		b = append(b, a.RData...)
	}
	return b
}

func (d *DNS) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return data, fmt.Errorf("dns: need 12 bytes, got %d", len(data))
	}
	d.ID = binary.BigEndian.Uint16(data[0:2])
	d.Flags = binary.BigEndian.Uint16(data[2:4])
	d.QDCount = binary.BigEndian.Uint16(data[4:6])
	d.ANCount = binary.BigEndian.Uint16(data[6:8])
	d.NSCount = binary.BigEndian.Uint16(data[8:10])
	d.ARCount = binary.BigEndian.Uint16(data[10:12])
	offset := 12
	for i := 0; i < int(d.QDCount); i++ {
		name, n := decodeDNSName(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if offset+4 > len(data) {
			break
		}
		q := DNSQuestion{Name: name, Type: DNSType(binary.BigEndian.Uint16(data[offset:])), Class: DNSClass(binary.BigEndian.Uint16(data[offset+2:]))}
		d.Questions = append(d.Questions, q)
		offset += 4
	}
	for i := 0; i < int(d.ANCount); i++ {
		name, n := decodeDNSName(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if offset+10 > len(data) {
			break
		}
		rr := DNSResource{
			Name: name,
			Type: DNSType(binary.BigEndian.Uint16(data[offset:])),
			Class: DNSClass(binary.BigEndian.Uint16(data[offset+2:])),
			TTL:  binary.BigEndian.Uint32(data[offset+4:]),
		}
		rr.RDLength = binary.BigEndian.Uint16(data[offset+8:])
		offset += 10
		if int(rr.RDLength) <= len(data[offset:]) {
			rr.RData = make([]byte, rr.RDLength)
			copy(rr.RData, data[offset:offset+int(rr.RDLength)])
			offset += int(rr.RDLength)
		}
		d.Answers = append(d.Answers, rr)
	}
	return data[offset:], nil
}

func (d *DNS) Next(data []byte) Layer { return nil }

func encodeDNSName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	var b []byte
	for _, part := range split(name, ".") {
		b = append(b, byte(len(part)))
		b = append(b, []byte(part)...)
	}
	b = append(b, 0)
	return b
}

func decodeDNSName(data []byte) (string, int) {
	var name string
	offset := 0
	for {
		if offset >= len(data) {
			return name, offset
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			ptr := (int(length&0x3F) << 8) | int(data[offset+1])
			expanded, _ := decodeDNSName(data[ptr:])
			name += expanded
			offset += 2
			break
		}
		offset++
		if offset+length > len(data) {
			break
		}
		if name != "" {
			name += "."
		}
		name += string(data[offset : offset+length])
		offset += length
	}
	return name, offset
}

func split(s, sep string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if string(s[i]) == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

func DNSGetRCODE(flags uint16) int  { return int(flags & 0xF) }
func DNSIsQR(flags uint16) bool    { return flags&(1<<15) != 0 }
func DNSIsTC(flags uint16) bool    { return flags&(1<<9) != 0 }
func DNSIsRD(flags uint16) bool    { return flags&(1<<8) != 0 }
func DNSIsRA(flags uint16) bool    { return flags&(1<<7) != 0 }
func DNSIsAA(flags uint16) bool    { return flags&(1<<10) != 0 }
