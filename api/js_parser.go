package api

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var urlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'\x60](/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=\-]*)\b["'\x60]`),
	regexp.MustCompile(`fetch\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`\.ajax\s*\(\s*\{[^}]*url\s*:\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`XMLHttpRequest.*?\.open\s*\(\s*["']([A-Z]+)["']\s*,\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`baseURL\s*[:=]\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`api(?:Url|URL|Url|Endpoint|Path)\s*[:=]\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`(?:url|endpoint|path)\s*[:=]\s*["'\x60](/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=\-]+)["'\x60]`),
	regexp.MustCompile(`["'\x60](/api/[^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`["'\x60](/v\d+/[^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`["'\x60](/graphql[^"'\x60]*)["'\x60]`),
}

var methodPattern = regexp.MustCompile(`(?:method|type)\s*:\s*["']([A-Z]+)["']`)

var prefixVars = make(map[string]string)

func DiscoverFromJS(cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	var allEndpoints []APIEndpoint

	for _, path := range cfg.JSPaths {
		endpoints, err := analyzeJSPath(path, cfg)
		if err != nil {
			return nil, fmt.Errorf("analyze js %s: %w", path, err)
		}
		allEndpoints = append(allEndpoints, endpoints...)
	}

	return allEndpoints, nil
}

func analyzeJSPath(path string, cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return analyzeJSDir(path, cfg)
	}
	return analyzeJSFile(path, cfg)
}

func analyzeJSDir(dir string, cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	var allEndpoints []APIEndpoint
	maxSize := int64(10 * 1024 * 1024)

	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".js" && ext != ".html" && ext != ".htm" && ext != ".ts" && ext != ".tsx" && ext != ".jsx" && ext != ".mjs" {
			return nil
		}

		limit := maxSize
		if info.Size() < limit {
			limit = info.Size()
		}

		eps, err := analyzeJSFileLimited(p, limit, cfg)
		if err != nil {
			return nil
		}
		allEndpoints = append(allEndpoints, eps...)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return allEndpoints, nil
}

func analyzeJSFile(path string, cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	return analyzeJSFileLimited(path, 2*1024*1024, cfg)
}

func analyzeJSFileLimited(path string, maxSize int64, cfg *DiscoveryConfig) ([]APIEndpoint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	prefixVars = make(map[string]string)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), int(maxSize))

	var content strings.Builder
	totalRead := int64(0)

	for scanner.Scan() {
		line := scanner.Text()
		totalRead += int64(len(line)) + 1
		if totalRead > maxSize {
			content.WriteString(line[:int(maxSize-totalRead+int64(len(line)))])
			break
		}
		content.WriteString(line)
		content.WriteString("\n")
	}

	return extractAPIFromContent(content.String(), cfg), scanner.Err()
}

func extractAPIFromContent(content string, cfg *DiscoveryConfig) []APIEndpoint {
	baseURL := extractBaseURL(content)
	endpointMap := make(map[string]*APIEndpoint)

	for _, pattern := range urlPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			for j := 1; j < len(match); j++ {
				candidate := match[j]
				if !isValidAPICandidate(candidate) {
					continue
				}

				fullPath := resolveFullPath(candidate, baseURL)
				if !strings.HasPrefix(fullPath, "/") {
					continue
				}

				method := extractNearbyMethod(content, candidate)

				if existing, ok := endpointMap[fullPath]; ok {
					existing.SeenCount++
					if method != "" && !containsMethod(existing.Methods, HTTPMethod(method)) {
						existing.Methods = append(existing.Methods, HTTPMethod(method))
					}
				} else {
					endpointMap[fullPath] = &APIEndpoint{
						Path:       fullPath,
						Methods:    defaultMethods(method),
						Host:       cfg.Target,
						Confidence: ConfidenceJSParse,
						Source:     SourceJSParse,
						SeenCount:  1,
					}
				}
			}
		}
	}

	var result []APIEndpoint
	for _, ep := range endpointMap {
		if IsLowConfidence(ep.Path) {
			ep.Confidence = ConfidenceJSParse - 0.2
		}
		if IsAPIPath(ep.Path) {
			if ep.Confidence < 0.85 {
				ep.Confidence = 0.85
			}
		}
		result = append(result, *ep)
	}

	return result
}

func isValidAPICandidate(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		return false
	}
	if IsStaticResource(path) {
		return false
	}
	ignored := []string{
		"/node_modules/", "/bower_components/", "/vendor/",
		"/static/", "/assets/", "/dist/", "/build/",
		"localhost", "127.0.0.1", "0.0.0.0",
	}
	lower := strings.ToLower(path)
	for _, ig := range ignored {
		if strings.Contains(lower, ig) {
			return false
		}
	}
	if strings.HasSuffix(lower, ".min.js") || strings.HasSuffix(lower, ".min.css") {
		return false
	}
	return true
}

func extractBaseURL(content string) string {
	re := regexp.MustCompile(`baseURL\s*[:=]\s*["'\x60]([^"'\x60]+)["'\x60]`)
	m := re.FindStringSubmatch(content)
	if len(m) >= 2 {
		base := m[1]
		prefixVars["baseURL"] = base
		return base
	}

	prefixRe := regexp.MustCompile(`(?:api|API|service|SERVICE)(?:Url|URL|Endpoint|Path|Prefix)\s*[:=]\s*["'\x60]([^"'\x60]+)["'\x60]`)
	pm := prefixRe.FindStringSubmatch(content)
	if len(pm) >= 2 {
		return pm[1]
	}

	return ""
}

func resolveFullPath(candidate string, baseURL string) string {
	if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
		for _, p := range regexp.MustCompile(`https?://[^/"'\x60]+`).FindAllString(candidate, -1) {
			candidate = strings.Replace(candidate, p, "", 1)
		}
		if candidate == "" {
			candidate = "/"
		}
	}

	for varName, varVal := range prefixVars {
		if strings.Contains(candidate, varName) {
			if strings.Contains(candidate, varName+"+") || strings.Contains(candidate, "+"+varName) {
				candidate = strings.ReplaceAll(candidate, varName, "")
				candidate = strings.ReplaceAll(candidate, "+", "")
				candidate = strings.ReplaceAll(candidate, `"`, "")
				candidate = strings.ReplaceAll(candidate, "'", "")
				candidate = strings.ReplaceAll(candidate, "`", "")
				if varVal != "" && baseURL == "" {
					baseURL = varVal
				}
			}
		}
	}

	basePath := baseURL
	if strings.Contains(basePath, "://") {
		idx := strings.Index(basePath, "://")
		basePath = basePath[idx+3:]
		if slashIdx := strings.Index(basePath, "/"); slashIdx >= 0 {
			basePath = basePath[slashIdx:]
		} else {
			basePath = ""
		}
	}

	if basePath != "" && !strings.HasPrefix(candidate, basePath) {
		candidate = strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(candidate, "/")
	}

	if strings.HasPrefix(candidate, "//") {
		candidate = candidate[1:]
	}

	return candidate
}

func extractNearbyMethod(content string, path string) string {
	idx := strings.Index(content, path)
	if idx < 0 {
		return ""
	}

	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(path) + 100
	if end > len(content) {
		end = len(content)
	}

	context := content[start:end]
	match := methodPattern.FindStringSubmatch(context)
	if len(match) >= 2 {
		return strings.ToUpper(match[1])
	}

	if strings.Contains(context, ".post(") || strings.Contains(context, "POST") {
		return "POST"
	}
	if strings.Contains(context, ".put(") || strings.Contains(context, "PUT") {
		return "PUT"
	}
	if strings.Contains(context, ".delete(") || strings.Contains(context, "DELETE") {
		return "DELETE"
	}
	if strings.Contains(context, ".patch(") || strings.Contains(context, "PATCH") {
		return "PATCH"
	}

	return "GET"
}

func defaultMethods(method string) []HTTPMethod {
	if method != "" && isValidMethod(method) {
		return []HTTPMethod{HTTPMethod(method)}
	}
	return []HTTPMethod{MethodGET}
}

func containsMethod(methods []HTTPMethod, method HTTPMethod) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}