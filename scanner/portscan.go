package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type PortResult struct {
	Host     string
	Port     int
	Protocol string
	Status   string
	Latency  time.Duration
}

func (r *PortResult) String() string {
	return fmt.Sprintf("[%s] %s:%d - %s (%v)", r.Protocol, r.Host, r.Port, r.Status, r.Latency)
}

type PortConfig struct {
	Threads  int
	Timeout  time.Duration
	Ports    []int
	Protocol string
}

func DefaultPortConfig() *PortConfig {
	return &PortConfig{
		Threads:  100,
		Timeout:  3 * time.Second,
		Ports:    []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017},
		Protocol: "tcp",
	}
}

func Ping(host string) bool {
	cfg := &PortConfig{Timeout: 3 * time.Second}
	return PingWithConfig(host, cfg)
}

func PingWithConfig(host string, cfg *PortConfig) bool {
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	host = strings.Split(host, ":")[0]
	host = strings.Split(host, "/")[0]

	if net.ParseIP(host) == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		host = addrs[0]
	}

	start := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, cfg.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return time.Since(start) < cfg.Timeout
}

func ScanPorts(host string, ports []int) []*PortResult {
	cfg := DefaultPortConfig()
	cfg.Ports = ports
	return ScanPortsWithConfig(host, cfg)
}

func ScanPortsWithConfig(host string, cfg *PortConfig) []*PortResult {
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	host = strings.Split(host, ":")[0]
	host = strings.Split(host, "/")[0]

	if net.ParseIP(host) == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return []*PortResult{}
		}
		host = addrs[0]
	}

	results := make([]*PortResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)

	for _, port := range cfg.Ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanPort(host, p, cfg)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}

func scanPort(host string, port int, cfg *PortConfig) *PortResult {
	start := time.Now()

	switch strings.ToLower(cfg.Protocol) {
	case "tcp":
		return tcpConnectScan(host, port, cfg.Timeout, start)
	case "fin":
		return finScan(host, port, cfg.Timeout, start)
	case "ack":
		return ackScan(host, port, cfg.Timeout, start)
	case "udp":
		return udpScan(host, port, cfg.Timeout, start)
	default:
		return tcpConnectScan(host, port, cfg.Timeout, start)
	}
}

func tcpConnectScan(host string, port int, timeout time.Duration, start time.Time) *PortResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)

	if err != nil {
		return &PortResult{
			Host:     host,
			Port:     port,
			Protocol: "tcp",
			Status:   "closed",
			Latency:  time.Since(start),
		}
	}
	conn.Close()

	return &PortResult{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		Status:   "open",
		Latency:  time.Since(start),
	}
}

func finScan(host string, port int, timeout time.Duration, start time.Time) *PortResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return &PortResult{
				Host:     host,
				Port:     port,
				Protocol: "fin",
				Status:   "open|filtered",
				Latency:  time.Since(start),
			}
		}
		return &PortResult{
			Host:     host,
			Port:     port,
			Protocol: "fin",
			Status:   "filtered",
			Latency:  time.Since(start),
		}
	}
	conn.Close()

	return &PortResult{
		Host:     host,
		Port:     port,
		Protocol: "fin",
		Status:   "closed",
		Latency:  time.Since(start),
	}
}

func ackScan(host string, port int, timeout time.Duration, start time.Time) *PortResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)

	if err != nil {
		return &PortResult{
			Host:     host,
			Port:     port,
			Protocol: "ack",
			Status:   "filtered",
			Latency:  time.Since(start),
		}
	}
	conn.Close()

	return &PortResult{
		Host:     host,
		Port:     port,
		Protocol: "ack",
		Status:   "unfiltered",
		Latency:  time.Since(start),
	}
}

func udpScan(host string, port int, timeout time.Duration, start time.Time) *PortResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", addr, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			return &PortResult{
				Host:     host,
				Port:     port,
				Protocol: "udp",
				Status:   "open|filtered",
				Latency:  time.Since(start),
			}
		}
		return &PortResult{
			Host:     host,
			Port:     port,
			Protocol: "udp",
			Status:   "closed",
			Latency:  time.Since(start),
		}
	}
	conn.Close()

	return &PortResult{
		Host:     host,
		Port:     port,
		Protocol: "udp",
		Status:   "open",
		Latency:  time.Since(start),
	}
}

type PortScanner struct {
	host     string
	threads  int
	timeout  time.Duration
	ports    []int
	protocol string
}

func NewPortScanner() *PortScanner {
	return &PortScanner{
		threads:  100,
		timeout:  3 * time.Second,
		protocol: "tcp",
	}
}

func (s *PortScanner) Host(host string) *PortScanner {
	s.host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	s.host = strings.Split(s.host, ":")[0]
	s.host = strings.Split(s.host, "/")[0]
	return s
}

func (s *PortScanner) Threads(n int) *PortScanner {
	s.threads = n
	return s
}

func (s *PortScanner) Timeout(d time.Duration) *PortScanner {
	s.timeout = d
	return s
}

func (s *PortScanner) Ports(ports []int) *PortScanner {
	s.ports = ports
	return s
}

func (s *PortScanner) Protocol(p string) *PortScanner {
	s.protocol = p
	return s
}

func (s *PortScanner) Scan() []*PortResult {
	cfg := &PortConfig{
		Threads:  s.threads,
		Timeout:  s.timeout,
		Ports:    s.ports,
		Protocol: s.protocol,
	}
	return ScanPortsWithConfig(s.host, cfg)
}

func (s *PortScanner) Ping() bool {
	cfg := &PortConfig{Timeout: s.timeout}
	return PingWithConfig(s.host, cfg)
}

func QuickScan(host string) []*PortResult {
	return NewPortScanner().Host(host).Scan()
}

func ScanPortsWithList(host string, ports []int) []*PortResult {
	return NewPortScanner().Host(host).Ports(ports).Scan()
}

func TopPorts(host string, count int) []*PortResult {
	topPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}
	if count > 0 && count < len(topPorts) {
		topPorts = topPorts[:count]
	}
	return NewPortScanner().Host(host).Ports(topPorts).Scan()
}