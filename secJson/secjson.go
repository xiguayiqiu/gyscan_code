package secjson

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Category string

const (
	CategoryIdentity   Category = "IDENTITY"
	CategoryFinance    Category = "FINANCE"
	CategoryCredential Category = "CREDENTIAL"
	CategoryBiometric  Category = "BIOMETRIC"
	CategoryInternal   Category = "INTERNAL"
	CategoryPrivacy    Category = "PRIVACY"
	CategoryCombined   Category = "COMBINED"
)

type Match struct {
	Field    string   `json:"field"`
	Path     string   `json:"path"`
	Value    string   `json:"value,omitempty"`
	Masked   string   `json:"masked,omitempty"`
	Type     string   `json:"type"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

type Finding struct {
	Matches     []Match  `json:"matches"`
	TotalFields int      `json:"total_fields"`
	RiskScore   float64  `json:"risk_score"`
	Summary     string   `json:"summary"`
	Compliance  []string `json:"compliance_issues,omitempty"`
}

type MaskIssue struct {
	Field      string `json:"field"`
	Path       string `json:"path"`
	Issue      string `json:"issue"`
	Level      string `json:"level"`
	Suggestion string `json:"suggestion"`
}

type ComplianceIssue struct {
	Standard string `json:"standard"`
	Rule     string `json:"rule"`
	Field    string `json:"field"`
	Path     string `json:"path"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}

type Config struct {
	StrictMode  bool
	MinSeverity Severity
	MaxDepth    int
	SkipFields  []string
	CustomRules []CustomRule
	ContextPath string
}

type CustomRule struct {
	Name     string
	Pattern  string
	Category Category
	Severity Severity
	Message  string
}

func DefaultConfig() *Config {
	return &Config{
		StrictMode:  false,
		MinSeverity: SeverityLow,
		MaxDepth:    50,
	}
}

type Analyzer struct {
	config *Config
}

func NewAnalyzer(cfg *Config) *Analyzer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Analyzer{config: cfg}
}

func (a *Analyzer) Analyze(jsonData string) (*Finding, error) {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("secjson: parse error: %w", err)
	}

	matches := a.walkJSON(data, "$", 0)
	matches = a.filterBySeverity(matches)
	matches = a.deduplicate(matches)

	combined := CombineRisk(matches)
	matches = append(matches, combined...)

	complianceIssues := CheckCompliance(jsonData, matches, a.config)

	totalFields := a.countFields(data)
	riskScore := a.calculateRisk(matches, totalFields)

	for i := range matches {
		matches[i].Masked = maskValue(matches[i].Value)
	}

	summary := a.buildSummary(len(matches), riskScore, totalFields)
	complianceMsgs := joinCompliance(complianceIssues)

	return &Finding{
		Matches:     matches,
		TotalFields: totalFields,
		RiskScore:   riskScore,
		Summary:     summary,
		Compliance:  complianceMsgs,
	}, nil
}

func (a *Analyzer) AnalyzeJSON(jsonData string) (*Finding, []MaskIssue, []ComplianceIssue, error) {
	finding, err := a.Analyze(jsonData)
	if err != nil {
		return nil, nil, nil, err
	}
	maskIssues := AnalyzeMasking(jsonData, finding.Matches)
	complianceIssues := CheckCompliance(jsonData, finding.Matches, a.config)
	return finding, maskIssues, complianceIssues, nil
}

func (a *Analyzer) walkJSON(data interface{}, path string, depth int) []Match {
	if depth > a.config.MaxDepth {
		return nil
	}

	switch v := data.(type) {
	case map[string]interface{}:
		return a.walkMap(v, path, depth)
	case []interface{}:
		return a.walkArray(v, path, depth)
	case string:
		return a.analyzeString(v, path, "")
	case float64, bool, nil:
		return nil
	default:
		return nil
	}
}

func (a *Analyzer) walkMap(m map[string]interface{}, path string, depth int) []Match {
	var matches []Match
	for key, val := range m {
		childPath := path + "." + key
		fieldMatches := a.analyzeFieldName(key, childPath)

		switch v := val.(type) {
		case string:
			strMatches := a.analyzeString(v, childPath, key)
			matches = append(matches, strMatches...)
		case map[string]interface{}:
			matches = append(matches, a.walkMap(v, childPath, depth+1)...)
		case []interface{}:
			matches = append(matches, a.walkArray(v, childPath, depth+1)...)
		}

		matches = append(matches, fieldMatches...)
	}
	return matches
}

func (a *Analyzer) walkArray(arr []interface{}, path string, depth int) []Match {
	var matches []Match
	for i, val := range arr {
		childPath := fmt.Sprintf("%s[%d]", path, i)
		matches = append(matches, a.walkJSON(val, childPath, depth+1)...)
	}
	return matches
}

func (a *Analyzer) analyzeString(value string, path string, fieldName string) []Match {
	var matches []Match

	for _, p := range sensitivePatterns {
		if !p.re.MatchString(value) {
			continue
		}
		if a.isFalsePositive(value, p.typeName) {
			continue
		}

		severity := p.severity
		if a.config.StrictMode && severity == SeverityMedium {
			severity = SeverityHigh
		}

		matches = append(matches, Match{
			Field:    fieldName,
			Path:     path,
			Value:    value,
			Type:     p.typeName,
			Category: p.category,
			Severity: severity,
			Message:  p.message,
		})
	}

	return matches
}

func (a *Analyzer) analyzeFieldName(key string, path string) []Match {
	lower := strings.ToLower(key)

	for _, f := range sensitiveFields {
		if !f.re.MatchString(lower) {
			continue
		}

		severity := f.severity
		if a.config.ContextPath != "" && strings.Contains(path, "/admin") {
			severity = a.raiseSeverity(severity)
		}

		return []Match{{
			Field:    key,
			Path:     path,
			Type:     f.typeName,
			Category: f.category,
			Severity: severity,
			Message:  f.message,
		}}
	}

	return nil
}

func (a *Analyzer) isFalsePositive(value string, typeName string) bool {
	if len(value) > 200 {
		return true
	}
	switch typeName {
	case "number_sequence":
		if len(value) < 6 {
			return true
		}
	}
	return false
}

func (a *Analyzer) filterBySeverity(matches []Match) []Match {
	var result []Match
	for _, m := range matches {
		if severityRank(m.Severity) >= severityRank(a.config.MinSeverity) {
			if a.shouldSkip(m.Field) {
				continue
			}
			result = append(result, m)
		}
	}
	return result
}

func (a *Analyzer) shouldSkip(field string) bool {
	for _, s := range a.config.SkipFields {
		if strings.EqualFold(s, field) {
			return true
		}
	}
	return false
}

func (a *Analyzer) deduplicate(matches []Match) []Match {
	seen := make(map[string]Match)
	var result []Match

	for _, m := range matches {
		key := m.Path + ":" + m.Type
		if existing, ok := seen[key]; ok {
			if severityRank(m.Severity) > severityRank(existing.Severity) {
				seen[key] = m
			}
		} else {
			seen[key] = m
		}
	}

	for _, m := range seen {
		result = append(result, m)
	}
	return result
}

func (a *Analyzer) countFields(data interface{}) int {
	count := 0
	switch v := data.(type) {
	case map[string]interface{}:
		for _, val := range v {
			count++
			count += a.countFields(val)
		}
	case []interface{}:
		for _, val := range v {
			count += a.countFields(val)
		}
	}
	return count
}

func (a *Analyzer) calculateRisk(matches []Match, totalFields int) float64 {
	if totalFields == 0 {
		return 0
	}

	weights := map[Severity]float64{
		SeverityCritical: 10.0,
		SeverityHigh:     5.0,
		SeverityMedium:   2.0,
		SeverityLow:      0.5,
	}

	var weightedSum float64
	for _, m := range matches {
		w := weights[m.Severity]
		if m.Path != "" {
			w *= ContextWeight(m.Path)
		}
		weightedSum += w
	}

	score := (weightedSum / float64(totalFields)) * 10
	if score > 100 {
		score = 100
	}

	for _, m := range matches {
		if m.Category == CategoryCombined {
			score += 15
		}
	}

	if score > 100 {
		score = 100
	}
	return float64(int(score*10)) / 10
}

func (a *Analyzer) buildSummary(matchCount int, riskScore float64, totalFields int) string {
	switch {
	case riskScore >= 80:
		return fmt.Sprintf("严重风险：发现 %d 个敏感字段, 风险评分 %.1f/100, 已检查 %d 个字段", matchCount, riskScore, totalFields)
	case riskScore >= 50:
		return fmt.Sprintf("高风险：发现 %d 个敏感字段, 风险评分 %.1f/100, 已检查 %d 个字段", matchCount, riskScore, totalFields)
	case riskScore >= 20:
		return fmt.Sprintf("中等风险：发现 %d 个敏感字段, 风险评分 %.1f/100, 已检查 %d 个字段", matchCount, riskScore, totalFields)
	case matchCount > 0:
		return fmt.Sprintf("低风险：发现 %d 个敏感字段, 风险评分 %.1f/100, 已检查 %d 个字段", matchCount, riskScore, totalFields)
	default:
		return fmt.Sprintf("安全：未发现敏感字段, 已检查 %d 个字段", totalFields)
	}
}

func (a *Analyzer) raiseSeverity(s Severity) Severity {
	switch s {
	case SeverityMedium:
		return SeverityHigh
	case SeverityLow:
		return SeverityMedium
	default:
		return s
	}
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func maskValue(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	if len(value) <= 8 {
		return value[:2] + "****" + value[len(value)-2:]
	}
	return value[:3] + "****" + value[len(value)-3:]
}

func joinCompliance(issues []ComplianceIssue) []string {
	if len(issues) == 0 {
		return nil
	}
	var result []string
	for _, issue := range issues {
		result = append(result, fmt.Sprintf("[%s] %s: %s", issue.Standard, issue.Rule, issue.Detail))
	}
	return result
}
