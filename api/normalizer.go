package api

import (
	"regexp"
	"strings"
)

var patterns = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`/[0-9a-f]{64}`), "{hash_sha256}"},
	{regexp.MustCompile(`/[0-9a-f]{40}`), "{hash_sha1}"},
	{regexp.MustCompile(`/[0-9a-f]{32}`), "{hash_md5}"},
	{regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), "{uuid}"},
	{regexp.MustCompile(`/\d{4}-\d{2}-\d{2}`), "{date}"},
	{regexp.MustCompile(`/\d{10,13}`), "{timestamp}"},
	{regexp.MustCompile(`/[A-Fa-f0-9]{24}`), "{object_id}"},
	{regexp.MustCompile(`/\d{6,}`), "{id}"},
	{regexp.MustCompile(`/\d+`), "{id}"},
}

var staticExtensions = map[string]bool{
	".js": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".map": true, ".pdf": true, ".zip": true,
	".tar": true, ".gz": true, ".mp4": true, ".mp3": true, ".webm": true,
	".html": true, ".htm": true,
}

var lowConfidenceWords = []string{
	"test", "demo", "example", "sample", "staging", "dev", "debug",
	"mock", "dummy", "temp", "tmp", "old", "backup", "deprecated",
}

func NormalizePath(path string) string {
	result := path
	for _, p := range patterns {
		result = p.re.ReplaceAllString(result, "/"+p.name)
	}
	result = strings.TrimRight(result, "/")
	if result == "" {
		return "/"
	}
	return result
}

func NormalizePaths(endpoints []APIEndpoint) []APIEndpoint {
	for i := range endpoints {
		endpoints[i].Path = NormalizePath(endpoints[i].Path)
	}
	return endpoints
}

func IsStaticResource(path string) bool {
	for ext := range staticExtensions {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func IsLowConfidence(path string) bool {
	lower := strings.ToLower(path)
	for _, word := range lowConfidenceWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

func IsAPIPath(path string) bool {
	if IsStaticResource(path) {
		return false
	}
	lower := strings.ToLower(path)
	apiPrefixes := []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/", "/ws/", "/soap/"}
	for _, p := range apiPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	apiSuffixes := []string{".json", ".xml", ".proto", ".graphql"}
	for _, s := range apiSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

func ExtractSegments(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func ExtractPrefix(path string, depth int) string {
	segs := ExtractSegments(path)
	if depth > len(segs) {
		depth = len(segs)
	}
	return "/" + strings.Join(segs[:depth], "/")
}

func ExtractCommonPrefixes(endpoints []APIEndpoint) []string {
	prefixCount := make(map[string]int)
	for _, ep := range endpoints {
		segs := ExtractSegments(ep.Path)
		for i := 1; i <= len(segs); i++ {
			prefix := "/" + strings.Join(segs[:i], "/")
			prefixCount[prefix]++
		}
	}

	var prefixes []string
	for prefix, count := range prefixCount {
		if count >= 2 && len(prefix) > 1 {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}