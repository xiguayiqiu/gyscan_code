package api

import (
	"fmt"

	secJson "github.com/xiguayiqiu/gyscan_code/secJson"
)

func DiscoverPcap(target string, pcapPath string) ([]APIEndpoint, error) {
	e := NewDiscoveryEngine(&DiscoveryConfig{
		Target:    target,
		Mode:      ModePassiveOnly,
		PcapPaths: []string{pcapPath},
	})
	result, err := e.Run()
	if err != nil {
		return nil, err
	}
	return result.Endpoints, nil
}

func DiscoverLogs(target string, logPath string) ([]APIEndpoint, error) {
	return DiscoverPcap(target, logPath)
}

func DiscoverURLs(target string, urlListPath string) ([]APIEndpoint, error) {
	return DiscoverPcap(target, urlListPath)
}

func DiscoverJS(target string, jsPath string) ([]APIEndpoint, error) {
	e := NewDiscoveryEngine(&DiscoveryConfig{
		Target:  target,
		Mode:    ModePassiveAndJS,
		JSPaths: []string{jsPath},
	})
	result, err := e.Run()
	if err != nil {
		return nil, err
	}
	return result.Endpoints, nil
}

func DiscoverBoth(target string, pcapPath string, jsPath string) ([]APIEndpoint, error) {
	e := NewDiscoveryEngine(&DiscoveryConfig{
		Target:    target,
		Mode:      ModePassiveAndJS,
		PcapPaths: []string{pcapPath},
		JSPaths:   []string{jsPath},
	})
	result, err := e.Run()
	if err != nil {
		return nil, err
	}
	return result.Endpoints, nil
}

func DiscoverWithProbe(target string, pcapPath string, jsPath string, probeLimit int) ([]APIEndpoint, error) {
	e := NewDiscoveryEngine(&DiscoveryConfig{
		Target:      target,
		Mode:        ModeFull,
		PcapPaths:   []string{pcapPath},
		JSPaths:     []string{jsPath},
		ActiveProbe: true,
		ProbeLimit:  probeLimit,
	})
	result, err := e.Run()
	if err != nil {
		return nil, err
	}
	return result.Endpoints, nil
}

func QuickScan(target string) ([]APIEndpoint, error) {
	e := NewDiscoveryEngine(DefaultConfig(target))
	result, err := e.Run()
	if err != nil {
		return nil, err
	}
	return result.Endpoints, nil
}

func CleanEndpoints(endpoints []APIEndpoint) []APIEndpoint {
	endpoints = Deduplicate(endpoints)
	endpoints = NormalizePaths(endpoints)
	endpoints = ClassifyConfidence(endpoints)
	return endpoints
}

func SaveReport(target string, endpoints []APIEndpoint, path string) error {
	return ExportJSON(target, endpoints, ModeFull, path)
}

func UniquePaths(endpoints []APIEndpoint) []string {
	seen := make(map[string]bool)
	var result []string
	for _, ep := range endpoints {
		if !seen[ep.Path] {
			seen[ep.Path] = true
			result = append(result, ep.Path)
		}
	}
	return result
}

func GroupBySource(endpoints []APIEndpoint) map[SourceType][]APIEndpoint {
	groups := make(map[SourceType][]APIEndpoint)
	for _, ep := range endpoints {
		groups[ep.Source] = append(groups[ep.Source], ep)
	}
	return groups
}

func GroupByMethod(endpoints []APIEndpoint) map[HTTPMethod][]APIEndpoint {
	groups := make(map[HTTPMethod][]APIEndpoint)
	for _, ep := range endpoints {
		for _, m := range ep.Methods {
			groups[m] = append(groups[m], ep)
		}
	}
	return groups
}

func GroupByConfidence(endpoints []APIEndpoint) (high, medium, low []APIEndpoint) {
	for _, ep := range endpoints {
		switch {
		case ep.Confidence >= 1.0:
			high = append(high, ep)
		case ep.Confidence >= 0.7:
			medium = append(medium, ep)
		default:
			low = append(low, ep)
		}
	}
	return
}

func Intersect(a, b []APIEndpoint) []APIEndpoint {
	set := make(map[string]bool)
	for _, ep := range a {
		set[ep.Path] = true
	}
	var result []APIEndpoint
	seen := make(map[string]bool)
	for _, ep := range b {
		if set[ep.Path] && !seen[ep.Path] {
			seen[ep.Path] = true
			result = append(result, ep)
		}
	}
	return result
}

func Diff(a, b []APIEndpoint) []APIEndpoint {
	set := make(map[string]bool)
	for _, ep := range b {
		set[ep.Path] = true
	}
	var result []APIEndpoint
	seen := make(map[string]bool)
	for _, ep := range a {
		if !set[ep.Path] && !seen[ep.Path] {
			seen[ep.Path] = true
			result = append(result, ep)
		}
	}
	return result
}

func Union(a, b []APIEndpoint) []APIEndpoint {
	return Deduplicate(append(a, b...))
}

func CountBySource(endpoints []APIEndpoint) map[SourceType]int {
	counts := make(map[SourceType]int)
	for _, ep := range endpoints {
		counts[ep.Source]++
	}
	return counts
}

func CountByMethod(endpoints []APIEndpoint) map[HTTPMethod]int {
	counts := make(map[HTTPMethod]int)
	for _, ep := range endpoints {
		for _, m := range ep.Methods {
			counts[m]++
		}
	}
	return counts
}

func Summary(endpoints []APIEndpoint) string {
	total := len(endpoints)
	high, medium, low := GroupByConfidence(endpoints)
	return fmt.Sprintf("%d endpoints (high:%d medium:%d low:%d)",
		total, len(high), len(medium), len(low))
}

func SortByConfidence(endpoints []APIEndpoint) []APIEndpoint {
	result := make([]APIEndpoint, len(endpoints))
	copy(result, endpoints)
	sortByConf(result)
	return result
}

func SortByCount(endpoints []APIEndpoint) []APIEndpoint {
	result := make([]APIEndpoint, len(endpoints))
	copy(result, endpoints)
	sortByCount(result)
	return result
}

func sortByConf(eps []APIEndpoint) {
	for i := 0; i < len(eps); i++ {
		for j := i + 1; j < len(eps); j++ {
			if eps[j].Confidence > eps[i].Confidence {
				eps[i], eps[j] = eps[j], eps[i]
			}
		}
	}
}

func sortByCount(eps []APIEndpoint) {
	for i := 0; i < len(eps); i++ {
		for j := i + 1; j < len(eps); j++ {
			if eps[j].SeenCount > eps[i].SeenCount {
				eps[i], eps[j] = eps[j], eps[i]
			}
		}
	}
}

// ============================================================
// 敏感 API 分类（sensitive.go）
// ============================================================

func ClassifyAPIs(endpoints []APIEndpoint) []*SensitiveAPI {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	return ClassifySensitiveAPIs(eps)
}

func CountSensitiveAPI(endpoints []APIEndpoint) string {
	return SensitiveSummary(ClassifyAPIs(endpoints))
}

func HasSensitiveAPI(endpoints []APIEndpoint) bool {
	return len(ClassifyAPIs(endpoints)) > 0
}

func FilterSensitiveAPIs(endpoints []APIEndpoint, minLevel SensitivityLevel) []*SensitiveAPI {
	return FilterBySensitivity(ClassifyAPIs(endpoints), minLevel)
}

// ============================================================
// JSON 安全分析（secjson_integration.go）
// ============================================================

func ScanEndpointJSON(endpoint APIEndpoint, jsonData string) (*SecJsonFinding, error) {
	return AnalyzeEndpointWithSecJson(&endpoint, jsonData, nil)
}

func ScanEndpointsJSON(endpoints []APIEndpoint, dataMap map[string]string) ([]*SecJsonFinding, error) {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	return AnalyzeMultipleEndpoints(eps, dataMap, nil)
}

func IsJSONSafe(jsonData string) bool {
	finding, err := secJson.Scan(jsonData)
	if err != nil {
		return false
	}
	return len(finding.Matches) == 0
}

func JSONRiskScore(jsonData string) float64 {
	finding, err := secJson.Scan(jsonData)
	if err != nil {
		return 0
	}
	return finding.RiskScore
}

// ============================================================
// Swagger 文档分析（swagger.go）
// ============================================================

func LoadSwagger(url string) (*SwaggerDoc, []APIEndpoint, error) {
	doc, ptrEps, err := DiscoverSwagger(url)
	if err != nil {
		return nil, nil, err
	}
	eps := make([]APIEndpoint, len(ptrEps))
	for i, e := range ptrEps {
		eps[i] = *e
	}
	return doc, eps, nil
}

func ParseSwagger(data []byte) ([]APIEndpoint, error) {
	_, ptrEps, err := ParseSwaggerJSON(data)
	if err != nil {
		return nil, err
	}
	eps := make([]APIEndpoint, len(ptrEps))
	for i, e := range ptrEps {
		eps[i] = *e
	}
	return eps, nil
}

func CheckSwaggerAuth(swaggerURL string) (auth, noauth int, err error) {
	doc, _, err := DiscoverSwagger(swaggerURL)
	if err != nil {
		return 0, 0, err
	}
	eps := ExtractSwaggerEndpoints(doc)
	a, n := SwaggerEndpointsByAuth(eps)
	return len(a), len(n), nil
}

// ============================================================
// 参数分析（parameter_analysis.go）
// ============================================================

func AnalyzeParams(endpoint APIEndpoint) string {
	return ParamAnalysisSummary(AnalyzeParamDetails(&endpoint))
}

func CollectSensitiveParams(endpoints []APIEndpoint) ([]string, string) {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	params := DetectSensitiveParams(eps)
	names := make([]string, len(params))
	for i, p := range params {
		names[i] = p.Param
	}
	return names, fmt.Sprintf("%d 个敏感参数: %v", len(names), names)
}

func DiffAPIs(old, new []APIEndpoint) (added, removed int) {
	oldPtrs := make([]*APIEndpoint, len(old))
	newPtrs := make([]*APIEndpoint, len(new))
	for i := range old {
		oldPtrs[i] = &old[i]
	}
	for i := range new {
		newPtrs[i] = &new[i]
	}
	result := CompareAPIVersions(oldPtrs, newPtrs)
	return len(result.Added), len(result.Removed)
}

// ============================================================
// 攻击面分析（attack_surface.go）
// ============================================================

func ScanAttackSurface(endpoints []APIEndpoint) string {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	return AttackSurfaceSummary(AnalyzeAttackSurfaces(eps))
}

func TopRiskAPIs(endpoints []APIEndpoint, n int) []*AttackSurface {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	return TopRiskyAPIs(AnalyzeAttackSurfaces(eps), n)
}

func HasRiskyAPI(endpoints []APIEndpoint, minScore float64) bool {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	return len(FilterByRiskScore(AnalyzeAttackSurfaces(eps), minScore)) > 0
}

// ============================================================
// HTTP 探测（httpclient_integration.go）
// ============================================================

func ProbeAPI(endpoint APIEndpoint, baseURL string) *APIProbeResult {
	return ProbeEndpointWithHTTP(&endpoint, baseURL)
}

func ProbeAPIs(endpoints []APIEndpoint, baseURL string) string {
	eps := make([]*APIEndpoint, len(endpoints))
	for i := range endpoints {
		eps[i] = &endpoints[i]
	}
	return ProbeSummary(ProbeEndpointsWithHTTP(eps, baseURL))
}

func QuickProbe(baseURL string, paths ...string) string {
	eps := make([]*APIEndpoint, len(paths))
	for i, p := range paths {
		eps[i] = &APIEndpoint{Path: p, Methods: []HTTPMethod{MethodGET}}
	}
	return ProbeSummary(ProbeEndpointsWithHTTP(eps, baseURL))
}

func TestAuth(endpoint APIEndpoint, baseURL string) bool {
	tests := TestAuthenticationBypass(&endpoint, baseURL)
	for _, t := range tests {
		if t.IsVulnerable {
			return true
		}
	}
	return false
}

func QuickAuthTest(baseURL string, paths ...string) string {
	eps := make([]*APIEndpoint, len(paths))
	for i, p := range paths {
		eps[i] = &APIEndpoint{Path: p, Methods: []HTTPMethod{MethodGET}}
	}
	sas := ClassifySensitiveAPIs(eps)
	tests := TestAllAuthBypass(sas, baseURL)
	vulnCount := 0
	for _, t := range tests {
		if t.IsVulnerable {
			vulnCount++
		}
	}
	if vulnCount > 0 {
		return fmt.Sprintf("发现 %d 个认证绕过风险（共 %d 个测试）", vulnCount, len(tests))
	}
	return fmt.Sprintf("未发现认证绕过（共 %d 个测试）", len(tests))
}

// ============================================================
// 综合报告
// ============================================================

func QuickSecurityReport(target string, endpoints []APIEndpoint) string {
	return fmt.Sprintf("=== %s 安全分析报告 ===\n\n%s\n\n%s\n",
		target, CountSensitiveAPI(endpoints), ScanAttackSurface(endpoints))
}

func HasRiskyEndpoints(endpoints []APIEndpoint) bool {
	return HasSensitiveAPI(endpoints) || HasRiskyAPI(endpoints, 70)
}
