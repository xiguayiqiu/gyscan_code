package ano

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type RawSocket struct {
	fd     int
	iface  string
	addr   *syscall.SockaddrLinklayer
}

func NewRawSocket(iface string) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("ano: raw socket: %w", err)
	}

	rs := &RawSocket{fd: fd, iface: iface}

	if iface != "" {
		ift, err := net.InterfaceByName(iface)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("ano: interface %s: %w", iface, err)
		}
		rs.addr = &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_ALL),
			Ifindex:  ift.Index,
		}
		if err := syscall.Bind(fd, rs.addr); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("ano: bind: %w", err)
		}
	}

	return rs, nil
}

func (rs *RawSocket) Send(pkt *Packet) error {
	data := pkt.Bytes()
	var err error
	if rs.addr != nil {
		err = syscall.Sendto(rs.fd, data, 0, rs.addr)
	} else {
		err = syscall.Sendto(rs.fd, data, 0, &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_ALL),
		})
	}
	if err != nil {
		return fmt.Errorf("ano: send: %w", err)
	}
	return nil
}

func (rs *RawSocket) Recv(timeout time.Duration) (*Packet, error) {
	if timeout > 0 {
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		if err := syscall.SetsockoptTimeval(rs.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, fmt.Errorf("ano: set timeout: %w", err)
		}
	}

	buf := make([]byte, 65535)
	n, _, err := syscall.Recvfrom(rs.fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("ano: recv: %w", err)
	}

	ether := &Ether{}
	_, err = ether.Deserialize(buf[:n])
	if err != nil {
		return nil, err
	}

	pkt := Build(ether)
	remaining := buf[14:n]
	next := ether.Next(remaining)
	for next != nil {
		remaining, err = next.Deserialize(remaining)
		if err != nil {
			break
		}
		pkt.Add(next)
		next = next.Next(remaining)
	}

	if len(remaining) > 0 {
		pkt.Payload = make([]byte, len(remaining))
		copy(pkt.Payload, remaining)
	}

	return pkt, nil
}

func (rs *RawSocket) Close() error {
	return syscall.Close(rs.fd)
}

func (rs *RawSocket) SetBPF(expr string) error {
	return SetSocketBPF(rs.fd, expr)
}

func (rs *RawSocket) Sr(pkt *Packet, timeout time.Duration) ([]*Packet, error) {
	if err := rs.Send(pkt); err != nil {
		return nil, err
	}
	var replies []*Packet
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining < 0 {
			break
		}
		resp, err := rs.Recv(remaining)
		if err != nil {
			break
		}
		replies = append(replies, resp)
	}
	return replies, nil
}

func Send(pkt *Packet) error {
	iface := DetectInterface()
	rs, err := NewRawSocket(iface)
	if err != nil {
		return err
	}
	defer rs.Close()
	return rs.Send(pkt)
}

func DetectInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.HardwareAddr == nil || len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.Name
	}
	if len(ifaces) > 0 {
		return ifaces[0].Name
	}
	return ""
}

func SendOnIface(iface string, pkt *Packet) error {
	rs, err := NewRawSocket(iface)
	if err != nil {
		return err
	}
	defer rs.Close()
	return rs.Send(pkt)
}

func Sr(pkt *Packet, timeout time.Duration) ([]*Packet, error) {
	iface := DetectInterface()
	rs, err := NewRawSocket(iface)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	return rs.Sr(pkt, timeout)
}

func htons(h uint16) uint16 {
	return (h << 8) | (h >> 8)
}

func GetInterfaceIP(iface string) (net.IP, error) {
	ift, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := ift.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() != nil {
			return ipnet.IP, nil
		}
	}
	return nil, fmt.Errorf("ano: no IPv4 on %s", iface)
}

func GetInterfaceMAC(iface string) (net.HardwareAddr, error) {
	ift, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	return ift.HardwareAddr, nil
}

func ListInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return ifaces
}
