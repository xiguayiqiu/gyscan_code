package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/xiguayiqiu/gyscan_code/ano"
)

type URLRecord struct {
	Method string
	URL    string
	Host   string
	Port   int
	Count  int
}

func DiscoverFromPcap(cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	var allEndpoints []APIEndpoint

	for _, path := range cfg.PcapPaths {
		endpoints, err := analyzePcap(path, cfg)
		if err != nil {
			return nil, fmt.Errorf("analyze pcap %s: %w", path, err)
		}
		allEndpoints = append(allEndpoints, endpoints...)
	}

	return allEndpoints, nil
}

func analyzePcap(path string, cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	var urls []URLRecord

	if isPcapFile(path) {
		pkts, err := ano.LoadPcap(path)
		if err != nil {
			return nil, err
		}
		urls = extractURLsFromPackets(pkts, cfg)
	} else if isJSONLogFile(path) {
		var err error
		urls, err = extractURLsFromJSONLog(path)
		if err != nil {
			return nil, err
		}
	} else {
		urls = extractURLsFromURLList(path)
	}

	host := cfg.Target
	if host == "" && len(urls) > 0 {
		host = extractDomain(urls[0].Host)
	}

	return urlsToEndpoints(urls, host), nil
}

func isPcapFile(path string) bool {
	ext := strings.ToLower(path)
	return strings.HasSuffix(ext, ".pcap") || strings.HasSuffix(ext, ".pcapng") || strings.HasSuffix(ext, ".cap")
}

func isJSONLogFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".json") || strings.HasSuffix(strings.ToLower(path), ".jsonl")
}

func extractURLsFromPackets(pkts []*ano.Packet, cfg *DiscoveryConfig) []URLRecord {
	recordMap := make(map[string]*URLRecord)

	for _, pkt := range pkts {
		var srcIP, dstIP string
		var srcPort, dstPort int

		if ip := pkt.Get("IPv4"); ip != nil {
			ipv4 := ip.(*ano.IPv4)
			srcIP = ano.IPBytes(ipv4.Src)
			dstIP = ano.IPBytes(ipv4.Dst)
		}

		if tcp := pkt.Get("TCP"); tcp != nil {
			t := tcp.(*ano.TCP)
			srcPort = int(t.SrcPort)
			dstPort = int(t.DstPort)
		} else if udp := pkt.Get("UDP"); udp != nil {
			u := udp.(*ano.UDP)
			srcPort = int(u.SrcPort)
			dstPort = int(u.DstPort)
		}

		if dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 8443 || dstPort == 3000 || dstPort == 5000 {
			host := dstIP
			if cfg.IncludeHost != "" {
				host = cfg.IncludeHost
			}

			if pkt.Payload != nil && len(pkt.Payload) > 0 {
				urls := parseHTTPFromPayload(pkt.Payload, host, dstPort)
				for _, u := range urls {
					key := u.Method + " " + u.URL
					if existing, ok := recordMap[key]; ok {
						existing.Count++
					} else {
						recordMap[key] = &URLRecord{
							Method: u.Method,
							URL:    u.URL,
							Host:   host,
							Port:   dstPort,
							Count:  1,
						}
					}
				}
			}
		}
		_ = srcIP
		_ = srcPort
	}

	var result []URLRecord
	for _, r := range recordMap {
		result = append(result, *r)
	}
	return result
}

func parseHTTPFromPayload(payload []byte, host string, port int) []URLRecord {
	var urls []URLRecord
	text := string(payload)

	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 {
		return urls
	}

	firstLine := lines[0]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return urls
	}

	method := strings.ToUpper(parts[0])
	path := parts[1]

	if method == "GET" || method == "POST" || method == "PUT" || method == "DELETE" ||
		method == "PATCH" || method == "OPTIONS" || method == "HEAD" {
		if !strings.HasPrefix(path, "/") {
			u, err := url.Parse(path)
			if err == nil && u.Path != "" {
				path = u.Path
			}
		}
		if strings.HasPrefix(path, "/") && !IsStaticResource(path) {
			if method == "GET" && strings.Contains(path, ".js") {
				return urls
			}
			urls = append(urls, URLRecord{
				Method: method,
				URL:    path,
				Host:   host,
				Port:   port,
				Count:  1,
			})
		}
	}

	return urls
}

func extractURLsFromJSONLog(path string) ([]URLRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []URLRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		var entry struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Path   string `json:"path"`
			Host   string `json:"host"`
			Port   int    `json:"port"`
			Count  int    `json:"count"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.Method == "" {
			entry.Method = "GET"
		}
		u := entry.URL
		if u == "" {
			u = entry.Path
		}
		if u == "" {
			continue
		}
		if entry.Count == 0 {
			entry.Count = 1
		}

		parsed, err := url.Parse(u)
		if err == nil {
			u = parsed.Path
		}

		if strings.HasPrefix(u, "/") && !IsStaticResource(u) {
			urls = append(urls, URLRecord{
				Method: strings.ToUpper(entry.Method),
				URL:    u,
				Host:   entry.Host,
				Port:   entry.Port,
				Count:  entry.Count,
			})
		}
	}

	return urls, scanner.Err()
}

func extractURLsFromURLList(path string) []URLRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var urls []URLRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		method := "GET"
		urlStr := line

		if len(parts) == 2 && isValidMethod(parts[0]) {
			method = strings.ToUpper(parts[0])
			urlStr = parts[1]
		}

		u, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		host := u.Host
		port := 80
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}

		if strings.HasPrefix(u.Path, "/") && !IsStaticResource(u.Path) {
			urls = append(urls, URLRecord{
				Method: method,
				URL:    u.Path,
				Host:   host,
				Port:   port,
				Count:  1,
			})
		}
	}

	return urls
}

func isValidMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
		return true
	}
	return false
}

func urlsToEndpoints(urls []URLRecord, targetHost string) []APIEndpoint {
	dedup := make(map[string]*APIEndpoint)

	for _, u := range urls {
		normPath := NormalizePath(u.URL)
		key := normPath + "|" + u.Method + "|" + u.Host

		if existing, ok := dedup[key]; ok {
			existing.SeenCount += u.Count
			continue
		}

		dedup[key] = &APIEndpoint{
			Path:       normPath,
			Methods:    []HTTPMethod{HTTPMethod(u.Method)},
			Host:       u.Host,
			Port:       u.Port,
			Confidence: ConfidenceTraffic,
			Source:     SourceTraffic,
			SeenCount:  u.Count,
		}
	}

	if targetHost != "" {
		for _, ep := range dedup {
			if ep.Host == "" || ep.Host == targetHost {
				ep.Host = targetHost
			}
		}
	}

	var result []APIEndpoint
	for _, ep := range dedup {
		result = append(result, *ep)
	}
	return result
}

func extractDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}