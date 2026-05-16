package secjson

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Report struct {
	Metadata   ReportMetadata    `json:"metadata"`
	Finding    *Finding          `json:"finding"`
	Masks      []MaskIssue       `json:"mask_issues,omitempty"`
	Compliance []ComplianceIssue `json:"compliance_issues,omitempty"`
}

type ReportMetadata struct {
	GeneratedAt string `json:"generated_at"`
	Version     string `json:"version"`
	Analyzer    string `json:"analyzer"`
	Mode        string `json:"mode"`
}

func GenerateReport(finding *Finding, masks []MaskIssue, compliance []ComplianceIssue) *Report {
	return &Report{
		Metadata: ReportMetadata{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Version:     "1.0.0",
			Analyzer:    "secJson",
			Mode:        "full",
		},
		Finding:    finding,
		Masks:      masks,
		Compliance: compliance,
	}
}

func (r *Report) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("secjson: marshal report: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (r *Report) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("secjson: marshal report: %w", err)
	}
	return string(data), nil
}

func (r *Report) Summary() string {
	var lines []string

	lines = append(lines, fmt.Sprintf("敏感JSON分析报告"))
	lines = append(lines, fmt.Sprintf("========================="))
	lines = append(lines, fmt.Sprintf("风险评分: %.1f/100", r.Finding.RiskScore))
	lines = append(lines, fmt.Sprintf("发现 %d 个敏感字段", len(r.Finding.Matches)))
	lines = append(lines, fmt.Sprintf("脱敏问题: %d 个", len(r.Masks)))
	lines = append(lines, fmt.Sprintf("合规问题: %d 个", len(r.Compliance)))

	if len(r.Finding.Matches) > 0 {
		lines = append(lines, "\n敏感字段明细:")
		for i, m := range r.Finding.Matches {
			lines = append(lines, fmt.Sprintf("  %d. [%s] %s: %s",
				i+1, m.Severity, m.Field, m.Message))
		}
	}

	if len(r.Masks) > 0 {
		lines = append(lines, "\n脱敏建议:")
		for i, m := range r.Masks {
			lines = append(lines, fmt.Sprintf("  %d. [%s] %s: %s", i+1, m.Level, m.Field, m.Suggestion))
		}
	}

	if len(r.Compliance) > 0 {
		lines = append(lines, "\n合规问题:")
		for i, c := range r.Compliance {
			lines = append(lines, fmt.Sprintf("  %d. [%s] %s: %s", i+1, c.Standard, c.Rule, c.Detail))
		}
	}

	result := ""
	for _, line := range lines {
		result += line + "\n"
	}
	return result
}