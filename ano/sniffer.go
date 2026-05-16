package ano

import (
	"fmt"
	"syscall"
	"time"
)

type Sniffer struct {
	iface     string
	timeout   time.Duration
	count     int
	promisc   bool
	Filter    string
	OnPacket  func(*Packet)
}

func NewSniffer() *Sniffer {
	return &Sniffer{
		count:   0,
		promisc: true,
	}
}

func (s *Sniffer) OnIface(iface string) *Sniffer {
	s.iface = iface
	return s
}

func (s *Sniffer) WithTimeout(d time.Duration) *Sniffer {
	s.timeout = d
	return s
}

func (s *Sniffer) WithCount(n int) *Sniffer {
	s.count = n
	return s
}

func (s *Sniffer) WithFilter(f string) *Sniffer {
	s.Filter = f
	return s
}

func (s *Sniffer) WithCallback(fn func(*Packet)) *Sniffer {
	s.OnPacket = fn
	return s
}

func (s *Sniffer) Start() (<-chan *Packet, error) {
	rs, err := NewRawSocket(s.iface)
	if err != nil {
		return nil, fmt.Errorf("ano: sniffer: %w", err)
	}

	if s.Filter != "" {
		if err := rs.SetBPF(s.Filter); err != nil {
			rs.Close()
			return nil, fmt.Errorf("ano: sniffer bpf: %w", err)
		}
	}

	ch := make(chan *Packet, 1000)

	go func() {
		defer rs.Close()
		defer close(ch)

		deadline := time.Now().Add(s.timeout)
		captured := 0

		for {
			if s.count > 0 && captured >= s.count {
				return
			}
			if s.timeout > 0 && time.Now().After(deadline) {
				return
			}

			remaining := time.Hour
			if s.timeout > 0 {
				remaining = time.Until(deadline)
				if remaining < 0 {
					return
				}
			}

			pkt, err := rs.Recv(remaining)
			if err != nil {
				continue
			}
			if pkt == nil {
				continue
			}

			captured++
			if s.OnPacket != nil {
				s.OnPacket(pkt)
			}
			select {
			case ch <- pkt:
			default:
			}
		}
	}()

	return ch, nil
}

func Sniff(iface string, timeout time.Duration, count int) ([]*Packet, error) {
	s := NewSniffer().OnIface(iface).WithTimeout(timeout).WithCount(count)
	ch, err := s.Start()
	if err != nil {
		return nil, err
	}
	var pkts []*Packet
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	return pkts, nil
}

func SniffCount(iface string, count int) ([]*Packet, error) {
	return Sniff(iface, time.Hour, count)
}

func SniffWithFilter(iface string, timeout time.Duration, count int, filter string) ([]*Packet, error) {
	s := NewSniffer().OnIface(iface).WithTimeout(timeout).WithCount(count).WithFilter(filter)
	ch, err := s.Start()
	if err != nil {
		return nil, err
	}
	var pkts []*Packet
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	return pkts, nil
}

func initSocket(fd int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2*1024*1024); err != nil {
		return err
	}
	return nil
}
