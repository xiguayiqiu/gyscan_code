package ano

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

type NetInterface struct {
	Name        string
	Index       int
	MAC         string
	IPs         []string
	Flags       []string
	MTU         int
	IsUp        bool
	IsLoopback  bool
	IsMulticast bool
}

func ListNetInterfaces() ([]NetInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("ano: list interfaces: %w", err)
	}

	var result []NetInterface
	for _, iface := range ifaces {
		ni := NetInterface{
			Name:        iface.Name,
			Index:       iface.Index,
			MTU:         iface.MTU,
			IsUp:        iface.Flags&net.FlagUp != 0,
			IsLoopback:  iface.Flags&net.FlagLoopback != 0,
			IsMulticast: iface.Flags&net.FlagMulticast != 0,
		}

		if iface.HardwareAddr != nil {
			ni.MAC = iface.HardwareAddr.String()
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.IPs = append(ni.IPs, addr.String())
			}
		}

		if ni.IsUp {
			ni.Flags = append(ni.Flags, "UP")
		}
		if ni.IsLoopback {
			ni.Flags = append(ni.Flags, "LOOPBACK")
		}
		if ni.IsMulticast {
			ni.Flags = append(ni.Flags, "MULTICAST")
		}
		if iface.Flags&net.FlagBroadcast != 0 {
			ni.Flags = append(ni.Flags, "BROADCAST")
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			ni.Flags = append(ni.Flags, "P2P")
		}

		result = append(result, ni)
	}

	return result, nil
}

func FindInterface(name string) (*NetInterface, error) {
	nics, err := ListNetInterfaces()
	if err != nil {
		return nil, err
	}
	for _, nic := range nics {
		if nic.Name == name {
			return &nic, nil
		}
	}
	return nil, fmt.Errorf("ano: interface %s not found", name)
}

func DefaultInterface() (*NetInterface, error) {
	nics, err := ListNetInterfaces()
	if err != nil {
		return nil, err
	}
	for _, nic := range nics {
		if nic.IsLoopback || !nic.IsUp || nic.MAC == "" {
			continue
		}
		return &nic, nil
	}
	if len(nics) > 0 {
		return &nics[0], nil
	}
	return nil, fmt.Errorf("ano: no available interface")
}

func Capture(iface string, timeout time.Duration, count int) ([]*Packet, error) {
	return Sniff(iface, timeout, count)
}

func CaptureWithFilter(iface string, timeout time.Duration, count int, filter string) ([]*Packet, error) {
	return SniffWithFilter(iface, timeout, count, filter)
}

func CaptureWithCallback(iface string, timeout time.Duration, count int, cb func(*Packet)) error {
	s := NewSniffer().OnIface(iface).WithTimeout(timeout).WithCount(count).WithCallback(cb)
	ch, err := s.Start()
	if err != nil {
		return err
	}
	for range ch {
	}
	return nil
}

func CaptureWithFilterCallback(iface string, timeout time.Duration, count int, filter string, cb func(*Packet)) error {
	s := NewSniffer().OnIface(iface).WithTimeout(timeout).WithCount(count).WithFilter(filter).WithCallback(cb)
	ch, err := s.Start()
	if err != nil {
		return err
	}
	for range ch {
	}
	return nil
}

const (
	capMagic   uint32 = 0x43415021
	capVersion uint16 = 1
)

type capHeader struct {
	Magic    uint32
	Version  uint16
	SnapLen  uint32
	LinkType uint32
}

type capRecord struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

func DumpCap(path string, pkts []*Packet) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("ano: dump cap: %w", err)
	}
	defer f.Close()

	hdr := capHeader{
		Magic:    capMagic,
		Version:  capVersion,
		SnapLen:  65535,
		LinkType: 1,
	}
	if err := binary.Write(f, binary.LittleEndian, &hdr); err != nil {
		return fmt.Errorf("ano: dump cap header: %w", err)
	}

	for _, pkt := range pkts {
		data := pkt.Bytes()
		now := time.Now()
		rec := capRecord{
			TsSec:   uint32(now.Unix()),
			TsUsec:  uint32(now.Nanosecond() / 1000),
			InclLen: uint32(len(data)),
			OrigLen: uint32(len(data)),
		}
		if err := binary.Write(f, binary.LittleEndian, &rec); err != nil {
			return fmt.Errorf("ano: dump cap record: %w", err)
		}
		if _, err := f.Write(data); err != nil {
			return fmt.Errorf("ano: dump cap data: %w", err)
		}
	}

	return nil
}

func DumpPcap(path string, pkts []*Packet) error {
	return SavePcap(path, pkts)
}

func LoadCap(path string) ([]*Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ano: load cap: %w", err)
	}
	defer f.Close()

	var hdr capHeader
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("ano: load cap header: %w", err)
	}
	if hdr.Magic != capMagic {
		return nil, fmt.Errorf("ano: invalid cap magic: 0x%08x", hdr.Magic)
	}

	var pkts []*Packet
	for {
		var rec capRecord
		if err := binary.Read(f, binary.LittleEndian, &rec); err != nil {
			break
		}
		data := make([]byte, rec.InclLen)
		if _, err := f.Read(data); err != nil {
			break
		}
		pkt, err := ParseEther(data)
		if err != nil {
			pkts = append(pkts, Build(NewRaw(data)))
			continue
		}
		pkts = append(pkts, pkt)
	}

	return pkts, nil
}

func Dump(path string, pkts []*Packet) error {
	if len(path) >= 4 && path[len(path)-4:] == ".cap" {
		return DumpCap(path, pkts)
	}
	return DumpPcap(path, pkts)
}