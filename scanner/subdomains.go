package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xiguayiqiu/gyscan_code/httpclient"
)

type SubdomainConfig struct {
	Threads         int
	Timeout         time.Duration
	Resolver        string
	Ports           []int
	CheckHTTP       bool
	HTTPTimeout     time.Duration
	InsecureSkipVerify bool
	Proxy           string
	UserAgent       string
	WildcardEnabled bool
	WildcardThreshold int
	Retries         int
}

func DefaultSubdomainConfig() *SubdomainConfig {
	return &SubdomainConfig{
		Threads:            100,
		Timeout:            3 * time.Second,
		Resolver:           "8.8.8.8:53",
		Ports:              []int{80, 443, 8080, 8443},
		CheckHTTP:          true,
		HTTPTimeout:        5 * time.Second,
		WildcardEnabled:    true,
		WildcardThreshold:  5,
	}
}

type SubdomainResult struct {
	Subdomain string
	Port      int
	Status    string
	IP        []string
	Duration  time.Duration
	Error     string
}

func (r *SubdomainResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("%s:%d - ERROR: %s", r.Subdomain, r.Port, r.Error)
	}
	return fmt.Sprintf("%s:%d [%s] IPs: %v", r.Subdomain, r.Port, r.Status, r.IP)
}

type SubdomainScanner struct {
	config    *SubdomainConfig
	client    *httpclient.Client
	wordlist  *WordList
	store     *ResultStore
	handlers  *EventHandlerGroup
}

func NewSubdomainScanner(wordlist []string, config *SubdomainConfig) *SubdomainScanner {
	if config == nil {
		config = DefaultSubdomainConfig()
	}
	if config.Threads <= 0 {
		config.Threads = 100
	}
	if config.Threads > 500 {
		config.Threads = 500
	}

	var proxy string
	if config.Proxy != "" {
		proxy = config.Proxy
	}

	clientConfig := &httpclient.Config{
		Timeout:            config.HTTPTimeout,
		FollowRedirects:    false,
		InsecureSkipVerify: config.InsecureSkipVerify,
		ProxyURL:           proxy,
	}

	var ua string
	if config.UserAgent != "" {
		ua = config.UserAgent
	} else {
		ua = httpclient.Random()
	}

	return &SubdomainScanner{
		config:   config,
		client:   mustNewClient(clientConfig, ua),
		wordlist: NewWordList(wordlist),
		store:    NewResultStore(),
		handlers: NewEventHandlerGroup(),
	}
}

func mustNewClient(config *httpclient.Config, ua string) *httpclient.Client {
	c, err := httpclient.New(config)
	if err != nil {
		panic(err)
	}
	return c
}

func (s *SubdomainScanner) OnResult(handler EventHandler) {
	s.handlers.Add(handler)
}

func (s *SubdomainScanner) Scan(target string) []*SubdomainResult {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimSuffix(target, "/")

	baseDomain := s.extractBaseDomain(target)
	if baseDomain == "" {
		return nil
	}

	var wildcardIPs map[string]bool
	if s.config.WildcardEnabled {
		wildcardIPs = s.detectWildcard(target)
	}

	results := s.scanSubdomains(baseDomain, target, wildcardIPs)
	return results
}

func (s *SubdomainScanner) extractBaseDomain(target string) string {
	parts := strings.Split(target, ".")
	if len(parts) < 2 {
		return ""
	}

	tlds := map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true,
		"cn": true, "io": true, "co": true, "info": true, "biz": true,
		"cc": true, "tv": true, "me": true, "moe": true, "ai": true,
		"app": true, "dev": true, "cloud": true, "site": true,
		"top": true, "xyz": true, "online": true, "shop": true,
		"ru": true, "de": true, "fr": true, "jp": true, "kr": true,
		"au": true, "ca": true, "in": true, "br": true, "mx": true,
	}

	domain := target
	parts = strings.Split(domain, ".")

	if len(parts) >= 3 && tlds[parts[len(parts)-1]] {
		if len(parts) >= 4 {
			if parts[len(parts)-3] == "co" ||
				parts[len(parts)-3] == "com" ||
				parts[len(parts)-3] == "net" {
				domain = strings.Join(parts[len(parts)-4:], ".")
			} else {
				domain = strings.Join(parts[len(parts)-3:], ".")
			}
		} else {
			domain = strings.Join(parts[len(parts)-2:], ".")
		}
	}

	return domain
}

func (s *SubdomainScanner) detectWildcard(target string) map[string]bool {
	testSub := fmt.Sprintf("wildcard-test-%d", time.Now().UnixNano())
	testDomain := testSub + "." + target

	wcIPs := make(map[string]bool)

	for _, port := range s.config.Ports {
		url := s.buildURL(testDomain, port)
		if url == "" {
			continue
		}

		start := time.Now()
		_, err := s.client.Head(url, httpclient.WithTimeout(s.config.HTTPTimeout))
		duration := time.Since(start)

		if err == nil {
			continue
		}

		ipStr := extractIPFromError(err.Error())
		if ipStr != "" {
			wcIPs[ipStr] = true
		} else if duration < 500*time.Millisecond {
			wcIPs["fast-response"] = true
		}
	}

	return wcIPs
}

func (s *SubdomainScanner) buildURL(subdomain string, port int) string {
	if port == 443 || port == 8443 {
		return fmt.Sprintf("https://%s:%d/", subdomain, port)
	}
	return fmt.Sprintf("http://%s:%d/", subdomain, port)
}

func (s *SubdomainScanner) scanSubdomains(baseDomain, target string, wildcardIPs map[string]bool) []*SubdomainResult {
	results := make([]*SubdomainResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, s.config.Threads)

	for i := 0; i < s.wordlist.Len(); i++ {
		item, ok := s.wordlist.Get(i)
		if !ok {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			subdomain := sub + "." + baseDomain
			result := s.checkSubdomain(subdomain, target, wildcardIPs)

			mu.Lock()
			if result != nil && result.Status != "filtered" {
				results = append(results, result)
				s.store.Add(&Result{
					Target: target,
					Found:  subdomain,
					Type:   ResultSubdomain,
					Status: 0,
				})
				s.handlers.Handle(&Result{
					Target:   target,
					Found:    subdomain,
					Type:     ResultSubdomain,
					Duration: result.Duration,
				})
			}
			mu.Unlock()
		}(item)
	}

	wg.Wait()
	return results
}

func (s *SubdomainScanner) checkSubdomain(subdomain, target string, wildcardIPs map[string]bool) *SubdomainResult {
	result := &SubdomainResult{
		Subdomain: subdomain,
		Duration:  -1,
	}

	resolver := s.config.Resolver
	if resolver == "" {
		resolver = "8.8.8.8:53"
	}

	start := time.Now()

	ips, err := s.resolveDNS(subdomain, resolver)
	result.Duration = time.Since(start)

	if err != nil {
		result.Status = "nxdomain"
		result.Error = err.Error()
		return result
	}

	if len(ips) == 0 {
		result.Status = "nxdomain"
		return result
	}

	result.IP = ips

	if s.isWildcardResponse(ips, wildcardIPs) {
		result.Status = "wildcard"
		return result
	}

	if s.config.CheckHTTP {
		for _, port := range s.config.Ports {
			status, err := s.checkHTTP(subdomain, port)
			if err == nil && status != "" {
				result.Port = port
				result.Status = status
				return result
			}
		}
		result.Status = "dns-only"
	} else {
		result.Port = s.config.Ports[0]
		result.Status = "resolved"
	}

	return result
}

func (s *SubdomainScanner) resolveDNS(host, resolver string) ([]string, error) {
	dialer := net.Dialer{Timeout: s.config.Timeout}

	conn, err := dialer.Dial("udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}
	defer conn.Close()

	msg := buildDNSQuery(host)
	conn.SetWriteDeadline(time.Now().Add(s.config.Timeout))
	_, err = conn.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return parseDNSResponse(buf[:n])
}

func buildDNSQuery(host string) []byte {
	host = strings.TrimSuffix(host, ".")
	parts := strings.Split(host, ".")

	var query []byte
	query = append(query, 0x00, 0x01)

	for _, part := range parts {
		query = append(query, byte(len(part)))
		query = append(query, part...)
	}
	query = append(query, 0x00)

	query = append(query, 0x00, 0x01)
	query = append(query, 0x00, 0x01)

	return query
}

func parseDNSResponse(data []byte) ([]string, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	flags := (int(data[2]) << 8) | int(data[3])
	if flags&0x0400 != 0 {
		return nil, fmt.Errorf("server failure")
	}

	qdcount := (int(data[4]) << 8) | int(data[5])
	ancount := (int(data[6]) << 8) | int(data[7])

	if ancount == 0 {
		return nil, fmt.Errorf("no answers")
	}

	offset := 12
	for i := 0; i < qdcount; i++ {
		offset = skipDNSName(data, offset)
		offset += 4
	}

	var ips []string
	for i := 0; i < ancount; i++ {
		offset = skipDNSName(data, offset)
		if offset+10 > len(data) {
			break
		}

		rdlength := (int(data[offset+8]) << 8) | int(data[offset+9])
		rdstart := offset + 10

		if rdlength == 4 && rdstart+4 <= len(data) {
			ip := fmt.Sprintf("%d.%d.%d.%d", data[rdstart], data[rdstart+1], data[rdstart+2], data[rdstart+3])
			ips = append(ips, ip)
		}

		offset = rdstart + rdlength
	}

	return ips, nil
}

func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			return offset + 1
		}
		if length >= 0xc0 {
			return offset + 2
		}
		offset += length + 1
	}
	return offset
}

func (s *SubdomainScanner) checkHTTP(subdomain string, port int) (string, error) {
	url := s.buildURL(subdomain, port)
	if url == "" {
		return "", fmt.Errorf("invalid url")
	}

	start := time.Now()
	resp, err := s.client.Head(url,
		httpclient.WithTimeout(s.config.HTTPTimeout),
	)
	duration := time.Since(start)

	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return fmt.Sprintf("%d", resp.StatusCode), nil
	}

	if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Sprintf("%d", resp.StatusCode), nil
	}

	return "", fmt.Errorf("status: %d (took %v)", resp.StatusCode, duration)
}

func (s *SubdomainScanner) isWildcardResponse(ips []string, wildcardIPs map[string]bool) bool {
	if len(wildcardIPs) == 0 {
		return false
	}

	for _, ip := range ips {
		if wildcardIPs[ip] || wildcardIPs["fast-response"] {
			return true
		}
	}
	return false
}

func extractIPFromError(errMsg string) string {
	parts := strings.Split(errMsg, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		for _, c := range part {
			if c < '0' || c > '9' {
				return ""
			}
		}
	}
	return errMsg
}

func (s *SubdomainScanner) Results() []*SubdomainResult {
	all := s.store.All()
	results := make([]*SubdomainResult, 0, len(all))
	for _, r := range all {
		results = append(results, &SubdomainResult{
			Subdomain: r.Found,
			Status:    r.Error,
		})
	}
	return results
}

type SubdomainEnumerator struct {
	Scanner *SubdomainScanner
}

func NewSubdomainEnumerator(wordlist []string, config *SubdomainConfig) *SubdomainEnumerator {
	return &SubdomainEnumerator{
		Scanner: NewSubdomainScanner(wordlist, config),
	}
}

func (e *SubdomainEnumerator) Scan(target string) []*SubdomainResult {
	return e.Scanner.Scan(target)
}

func (e *SubdomainEnumerator) OnResult(handler EventHandler) {
	e.Scanner.OnResult(handler)
}

func EnumerateSubdomains(target string, wordlist []string, config *SubdomainConfig) []*SubdomainResult {
	scanner := NewSubdomainScanner(wordlist, config)
	return scanner.Scan(target)
}

func QuickSubdomainScan(target string) []*SubdomainResult {
	return EnumerateSubdomains(target, nil, nil)
}

func SubdomainScanWithChan(target string, wordlist []string, config *SubdomainConfig) <-chan *SubdomainResult {
	ch := make(chan *SubdomainResult, 100)

	go func() {
		defer close(ch)
		results := EnumerateSubdomains(target, wordlist, config)
		for _, r := range results {
			select {
			case ch <- r:
			default:
			}
		}
	}()

	return ch
}

var defaultSubdomainWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp",
	"pop", "ns1", "webdisk", "ns2", "cpanel",
	"whm", "autodiscover", "autoconfig", "m", "imap",
	"test", "ns", "panel", "pop3", "dev",
	"www2", "admin", "forum", "news", "vpn",
	"ns3", "mail2", "new", "mysql", "old",
	"lists", "support", "mobile", "mx", "static",
	"docs", "beta", "shop", "sql", "secure",
	"demo", "hp", "email", "live", "media",
	"gw", "instagram", "api", "fb", "staging",
	"git", "logger", "alpha", "cdnx", "sync",
	"amazon", "aws", "cloud", "google", "s3",
	"backup", "mx1", "crm", "cms", "portal",
	"vps", "edu", "intranet", "jira", "gitlab",
	"slack", "msoid", "web", "corp", "sharepoint",
	"info", "search", "stage", "t", "db",
	"tv", "video", "phone", "chat", "files",
	"app", "apps", "cdn", "assets", "images",
	"img", "css", "js", "static", "assets",
	"pma", "sso", "ssh", "git", "jenkins",
	"docker", "k8s", "kube", "prod", "uat",
	"qa", "sit", "dev", "test1", "test2",
	"staging", "preprod", "pre", "pro", "prod",
}

func DefaultSubdomainWordlist() []string {
	result := make([]string, len(defaultSubdomainWordlist))
	copy(result, defaultSubdomainWordlist)
	return result
}
