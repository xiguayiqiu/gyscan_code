package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var probePathSuffixes = []string{
	"/api/v1",
	"/api/v2",
	"/api/v3",
	"/api",
	"/graphql",
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/docs",
	"/rest",
	"/rpc",
	"/health",
	"/healthz",
	"/status",
	"/ping",
	"/metrics",
	"/actuator",
	"/admin",
	"/internal",
	"/private",
	"/debug",
	"/.env",
}

func DiscoverActive(cfg *DiscoveryConfig, existing []APIEndpoint) ([]APIEndpoint, error) {
	if cfg.ProbeLimit <= 0 {
		return nil, nil
	}

	prefixes := ExtractCommonPrefixes(existing)
	candidates := generateProbeCandidates(prefixes, cfg)
	if len(candidates) > cfg.ProbeLimit {
		candidates = candidates[:cfg.ProbeLimit]
	}

	return probeEndpoints(cfg, candidates), nil
}

func generateProbeCandidates(prefixes []string, cfg *DiscoveryConfig) []string {
	seen := make(map[string]bool)
	var candidates []string

	scheme := "https"
	if cfg.AllowHTTP {
		scheme = "http"
	}

	for _, prefix := range prefixes {
		for _, suffix := range probePathSuffixes {
			candidate := prefix + suffix
			if !strings.HasPrefix(candidate, "/") {
				candidate = "/" + candidate
			}
			full := scheme + "://" + cfg.Target + candidate
			if !seen[full] {
				seen[full] = true
				candidates = append(candidates, full)
			}
		}
	}

	for _, suffix := range probePathSuffixes {
		full := scheme + "://" + cfg.Target + suffix
		if !seen[full] {
			seen[full] = true
			candidates = append(candidates, full)
		}
	}

	return candidates
}

func probeEndpoints(cfg *DiscoveryConfig, candidates []string) []APIEndpoint {
	var endpoints []APIEndpoint
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, cfg.RateLimit)
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 5
	}

	for _, candidate := range candidates {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "API-Discovery/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if isAPIResponse(resp) {
				endpoint := APIEndpoint{
					Path:       extractPath(url),
					Methods:    []HTTPMethod{MethodGET},
					Host:       cfg.Target,
					Port:       443,
					Confidence: ConfidenceProbe,
					Source:     SourceActiveProbe,
					SeenCount:  1,
					StatusCode: resp.StatusCode,
					ContentType: resp.Header.Get("Content-Type"),
				}
				mu.Lock()
				endpoints = append(endpoints, endpoint)
				mu.Unlock()
			}

			time.Sleep(50 * time.Millisecond)
		}(candidate)
	}

	wg.Wait()
	return endpoints
}

func isAPIResponse(resp *http.Response) bool {
	if resp.StatusCode == 404 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	apiCTs := []string{
		"application/json", "application/xml", "text/xml",
		"application/protobuf", "application/graphql",
		"application/x-www-form-urlencoded",
	}
	for _, t := range apiCTs {
		if strings.HasPrefix(ct, t) {
			return true
		}
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	if resp.StatusCode == 405 {
		return true
	}

	if len(resp.Header.Get("X-Powered-By")) > 0 && ct == "" {
		return false
	}

	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func extractPath(url string) string {
	s := url
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	idx := strings.Index(s, "/")
	if idx >= 0 {
		return s[idx:]
	}
	return "/"
}

func ProbeEndpoint(target string, path string, timeout time.Duration) (int, string, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("https://%s%s", target, path)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "API-Discovery/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	return resp.StatusCode, resp.Header.Get("Content-Type"), nil
}