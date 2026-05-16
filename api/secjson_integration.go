package api

import (
	"fmt"
	"net/url"

	sec "github.com/xiguayiqiu/gyscan_code/secJson"
)

type SecJsonFinding struct {
	Endpoint        *APIEndpoint
	Path            string
	MethodStr       string
	Finding         *sec.Finding
	MaskIssues      []sec.MaskIssue
	ComplianceIssues []sec.ComplianceIssue
	IsSafe          bool
}

type SecJsonReport struct {
	Endpoint *SecJsonFinding
	Report   *sec.Report
}

type SecJsonAnalysisConfig struct {
	EnableMasking    bool
	EnableCompliance bool
	StrictMode       bool
}

func DefaultSecJsonConfig() *SecJsonAnalysisConfig {
	return &SecJsonAnalysisConfig{
		EnableMasking:    true,
		EnableCompliance: true,
		StrictMode:       false,
	}
}

func endpointURL(ep *APIEndpoint) string {
	if ep.Host != "" {
		scheme := "https"
		if ep.Port == 80 {
			scheme = "http"
		}
		if ep.Port != 0 && ep.Port != 443 && ep.Port != 80 {
			return fmt.Sprintf("%s://%s:%d%s", scheme, ep.Host, ep.Port, ep.Path)
		}
		return fmt.Sprintf("%s://%s%s", scheme, ep.Host, ep.Path)
	}
	return ep.Path
}

func endpointMethod(ep *APIEndpoint) string {
	if len(ep.Methods) > 0 {
		return string(ep.Methods[0])
	}
	return "GET"
}

func AnalyzeEndpointWithSecJson(endpoint *APIEndpoint, jsonData string, cfg *SecJsonAnalysisConfig) (*SecJsonFinding, error) {
	if cfg == nil {
		cfg = DefaultSecJsonConfig()
	}

	scfg := sec.DefaultConfig()
	scfg.StrictMode = cfg.StrictMode

	var finding *sec.Finding
	var masks []sec.MaskIssue
	var compliance []sec.ComplianceIssue
	var err error

	if cfg.EnableMasking || cfg.EnableCompliance {
		finding, masks, compliance, err = sec.ScanFull(jsonData)
	} else {
		finding, err = sec.Scan(jsonData)
	}
	if err != nil {
		return nil, err
	}

	return &SecJsonFinding{
		Endpoint:         endpoint,
		Path:             endpoint.Path,
		MethodStr:        endpointMethod(endpoint),
		Finding:          finding,
		MaskIssues:       masks,
		ComplianceIssues: compliance,
		IsSafe:           len(finding.Matches) == 0,
	}, nil
}

func AnalyzeMultipleEndpoints(endpoints []*APIEndpoint, dataMap map[string]string, cfg *SecJsonAnalysisConfig) ([]*SecJsonFinding, error) {
	if cfg == nil {
		cfg = DefaultSecJsonConfig()
	}

	var results []*SecJsonFinding
	for _, ep := range endpoints {
		key := ep.Path
		if data, ok := dataMap[key]; ok {
			sf, err := AnalyzeEndpointWithSecJson(ep, data, cfg)
			if err != nil {
				continue
			}
			results = append(results, sf)
		}
	}
	return results, nil
}

func GenerateSecJsonReport(findings []*SecJsonFinding, endpoint *APIEndpoint) *SecJsonReport {
	return &SecJsonReport{
		Endpoint: &SecJsonFinding{
			Endpoint:  endpoint,
			Path:      endpoint.Path,
			MethodStr: endpointMethod(endpoint),
		},
	}
}

func SecJsonQuickReport(endpoints []*APIEndpoint, dataMap map[string]string) (string, error) {
	findings, err := AnalyzeMultipleEndpoints(endpoints, dataMap, DefaultSecJsonConfig())
	if err != nil {
		return "", err
	}

	if len(findings) == 0 {
		return "无JSON数据可用于分析", nil
	}

	var result string
	for _, sf := range findings {
		result += "端点: " + sf.MethodStr + " " + sf.Path + "\n"
		result += sf.Finding.Summary + "\n"
		if len(sf.MaskIssues) > 0 {
			result += "  脱敏问题: " + itoa(len(sf.MaskIssues)) + " 个\n"
		}
		if len(sf.ComplianceIssues) > 0 {
			result += "  合规问题: " + itoa(len(sf.ComplianceIssues)) + " 个\n"
		}
		result += "\n"
	}
	return result, nil
}

func SecJsonFilterEndpoints(endpoints []*APIEndpoint, dataMap map[string]string) []*SecJsonFinding {
	var result []*SecJsonFinding
	for _, ep := range endpoints {
		key := ep.Path
		if data, ok := dataMap[key]; ok {
			sf, _ := AnalyzeEndpointWithSecJson(ep, data, DefaultSecJsonConfig())
			result = append(result, sf)
		}
	}
	return result
}

func SecJsonFindSensitiveEndpoints(findings []*SecJsonFinding, minScore float64) []*SecJsonFinding {
	var result []*SecJsonFinding
	for _, sf := range findings {
		if sf.Finding.RiskScore >= minScore {
			result = append(result, sf)
		}
	}
	return result
}

func SecJsonExtractEndpoints(findings []*SecJsonFinding) []*APIEndpoint {
	var result []*APIEndpoint
	for _, sf := range findings {
		result = append(result, sf.Endpoint)
	}
	return result
}

func SecJsonUpdateEndpointSensitivity(sas []*SensitiveAPI, findings []*SecJsonFinding) []*SensitiveAPI {
	findingMap := make(map[string]*SecJsonFinding)
	for _, f := range findings {
		if f.Endpoint != nil {
			_, err := url.Parse(f.Endpoint.Path)
			if err == nil {
				findingMap[f.Endpoint.Path] = f
			}
		}
	}

	for _, sa := range sas {
		if sa.Endpoint != nil {
			if sf, ok := findingMap[sa.Endpoint.Path]; ok {
				jsonScore := sf.Finding.RiskScore
				if jsonScore > sa.RiskScore {
					sa.RiskScore = jsonScore
					if jsonScore >= 90 {
						sa.Sensitivity = SensCritical
					} else if jsonScore >= 70 {
						sa.Sensitivity = SensHigh
					}
					sa.Reason += "JSON敏感数据评分: " + itoa(int(jsonScore)) + "; "
				}
			}
		}
	}
	return sas
}

func SecJsonSummary(findings []*SecJsonFinding) string {
	if len(findings) == 0 {
		return "无JSON分析结果"
	}

	totalFields := 0
	totalMatches := 0
	totalMasks := 0
	totalCompliance := 0
	riskyCount := 0

	for _, sf := range findings {
		totalFields += sf.Finding.TotalFields
		totalMatches += len(sf.Finding.Matches)
		totalMasks += len(sf.MaskIssues)
		totalCompliance += len(sf.ComplianceIssues)
		if sf.Finding.RiskScore > 50 {
			riskyCount++
		}
	}

	result := "secJson分析摘要:\n"
	result += "  分析端点: " + itoa(len(findings)) + " 个\n"
	result += "  总字段数: " + itoa(totalFields) + "\n"
	result += "  敏感匹配: " + itoa(totalMatches) + " 个\n"
	result += "  脱敏问题: " + itoa(totalMasks) + " 个\n"
	result += "  合规问题: " + itoa(totalCompliance) + " 个\n"
	result += "  高风险端点: " + itoa(riskyCount) + " 个"
	return result
}