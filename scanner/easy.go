package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xiguayiqiu/gyscan_code/httpclient"
)

var defaultDirs = []string{
	"", "admin", "login", "wp-login.php", "administrator", "admin.php",
	"panel", "cpanel", "whm", "dashboard", "webmail",
	"api", "api/v1", "console", "swagger",
	"robots.txt", ".env", ".git",
	"phpmyadmin", "config", "settings", "backup",
	"upload", "uploads", "images", "assets", "static",
	"css", "js", "media", "docs",
}

var defaultSubs = []string{
	"www", "mail", "ftp", "webmail", "smtp",
	"pop", "ns1", "webdisk", "ns2", "cpanel",
	"whm", "autodiscover", "m", "imap",
	"test", "ns", "panel", "dev",
	"www2", "admin", "forum", "news", "vpn",
	"ns3", "mail2", "new", "mysql", "old",
	"lists", "support", "mobile", "mx", "static",
	"docs", "beta", "shop", "secure",
	"demo", "email", "live", "media",
	"gw", "instagram", "api", "fb", "staging",
	"git", "alpha", "sync",
	"amazon", "aws", "cloud", "google", "s3",
	"backup", "crm", "cms", "portal",
	"vps", "edu", "intranet", "jira", "gitlab",
	"slack", "web", "corp", "sharepoint",
	"info", "search", "stage", "db",
	"tv", "video", "chat", "files",
	"app", "cdn",
}

type Scan struct {
	url     string
	threads int
	timeout time.Duration
	verbose bool
}

func New() *Scan {
	return &Scan{
		threads: 30,
		timeout: 10 * time.Second,
	}
}

func (s *Scan) Url(url string) *Scan {
	s.url = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://"), "/")
	return s
}

func (s *Scan) Threads(n int) *Scan {
	s.threads = n
	return s
}

func (s *Scan) Timeout(d time.Duration) *Scan {
	s.timeout = d
	return s
}

func (s *Scan) Verbose(v bool) *Scan {
	s.verbose = v
	return s
}

func (s *Scan) Dirs() []string {
	results := make([]string, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.threads)

	for _, path := range defaultDirs {
		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			u := s.url
			if !strings.HasSuffix(u, "/") && p != "" {
				u += "/"
			}
			u += p

			if s.verbose {
				fmt.Printf("[SCAN] https://%s\n", u)
			}

			resp, _ := httpclient.FetchResponse("https://" + u)
			if resp != nil && resp.StatusCode() > 0 {
				mu.Lock()
				results = append(results, "https://"+u)
				mu.Unlock()
				if s.verbose {
					fmt.Printf("[FIND] [%d] https://%s\n", resp.StatusCode(), u)
				}
			}
		}(path)
	}

	wg.Wait()
	return results
}

func (s *Scan) Subs() []string {
	results := make([]string, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.threads)

	base := extractBase(s.url)

	for _, prefix := range defaultSubs {
		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			sub := p + "." + base

			if s.verbose {
				fmt.Printf("[DNS] %s\n", sub)
			}

			ips, err := net.LookupHost(sub)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				results = append(results, sub)
				mu.Unlock()
				if s.verbose {
					fmt.Printf("[FIND] %s -> %v\n", sub, ips)
				}
			}
		}(prefix)
	}

	wg.Wait()
	return results
}

func (s *Scan) Find() []string {
	return s.Dirs()
}

func extractBase(target string) string {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimSuffix(target, "/")

	parts := strings.Split(target, ".")
	if len(parts) < 2 {
		return target
	}

	tlds := map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true,
		"cn": true, "io": true, "co": true, "info": true, "biz": true,
		"cc": true, "tv": true, "me": true, "ai": true,
		"app": true, "dev": true, "cloud": true, "site": true,
		"top": true, "xyz": true, "online": true, "shop": true,
	}

	if len(parts) >= 3 && tlds[parts[len(parts)-1]] {
		if parts[len(parts)-3] == "co" || parts[len(parts)-3] == "com" || parts[len(parts)-3] == "net" {
			return strings.Join(parts[len(parts)-4:], ".")
		}
		return strings.Join(parts[len(parts)-3:], ".")
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

func Dirs(url string) []string {
	return New().Url(url).Dirs()
}

func Subs(url string) []string {
	return New().Url(url).Subs()
}

func Find(url string) []string {
	return New().Url(url).Find()
}