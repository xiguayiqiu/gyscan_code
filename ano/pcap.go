package ano

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

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

func NewPcapWriter(w io.Writer) *PcapWriter {
	return &PcapWriter{w: w}
}

type PcapWriter struct {
	w io.Writer
}

func (pw *PcapWriter) WriteHeader() error {
	hdr := PcapHeader{
		MagicNumber:  0xA1B2C3D4,
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
	r      io.Reader
	Header PcapHeader
}

func OpenPcap(path string) (*PcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pr := &PcapReader{r: f}
	if err := binary.Read(pr.r, binary.LittleEndian, &pr.Header); err != nil {
		f.Close()
		return nil, err
	}
	return pr, nil
}

func NewPcapReader(r io.Reader) (*PcapReader, error) {
	pr := &PcapReader{r: r}
	if err := binary.Read(pr.r, binary.LittleEndian, &pr.Header); err != nil {
		return nil, err
	}
	return pr, nil
}

func (pr *PcapReader) ReadPacket() (*PcapRecord, error) {
	var rec PcapRecord
	if err := binary.Read(pr.r, binary.LittleEndian, &rec.TsSec); err != nil {
		return nil, err
	}
	if err := binary.Read(pr.r, binary.LittleEndian, &rec.TsUsec); err != nil {
		return nil, err
	}
	if err := binary.Read(pr.r, binary.LittleEndian, &rec.InclLen); err != nil {
		return nil, err
	}
	if err := binary.Read(pr.r, binary.LittleEndian, &rec.OrigLen); err != nil {
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
	fmt.Println(HexDump(pkt.Bytes()))
	fmt.Printf("Total: %d bytes\n", len(pkt.Bytes()))
	fmt.Printf("Layers: %s\n", pkt.Show())
	for _, l := range pkt.Layers {
		switch v := l.(type) {
		case *Ether:
			fmt.Printf("  Ether: %s > %s type=0x%04x\n", MACString(v.Src), MACString(v.Dst), v.Type)
		case *IPv4:
			fmt.Printf("  IPv4:  %s > %s ttl=%d proto=%d\n", IPBytes(v.Src), IPBytes(v.Dst), v.TTL, v.Protocol)
		case *TCP:
			flags := ""
			if v.Flags&TCP_SYN != 0 {
				flags += "SYN "
			}
			if v.Flags&TCP_ACK != 0 {
				flags += "ACK "
			}
			if v.Flags&TCP_FIN != 0 {
				flags += "FIN "
			}
			if v.Flags&TCP_RST != 0 {
				flags += "RST "
			}
			fmt.Printf("  TCP:   %d->%d seq=%d flags=%swindow=%d\n", v.SrcPort, v.DstPort, v.Seq, flags, v.Window)
		case *UDP:
			fmt.Printf("  UDP:   %d->%d len=%d\n", v.SrcPort, v.DstPort, v.Length)
		case *ICMP:
			fmt.Printf("  ICMP: type=%d code=%d id=%d seq=%d\n", v.Type, v.Code, v.ID, v.Seq)
		case *ARP:
			fmt.Printf("  ARP:   op=%d %s > %s %s > %s\n", v.Op, MACString(v.SrcMAC), IPBytes(v.SrcIP), MACString(v.DstMAC), IPBytes(v.DstIP))
		case *Raw:
			fmt.Printf("  Raw:   %d bytes\n", len(v.Load))
		}
	}
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
