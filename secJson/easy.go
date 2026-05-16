package secjson

import (
	"fmt"
	"os"
)

func Scan(jsonData string) (*Finding, error) {
	a := NewAnalyzer(DefaultConfig())
	return a.Analyze(jsonData)
}

func ScanStrict(jsonData string) (*Finding, error) {
	cfg := DefaultConfig()
	cfg.StrictMode = true
	cfg.MinSeverity = SeverityLow
	a := NewAnalyzer(cfg)
	return a.Analyze(jsonData)
}

func ScanFull(jsonData string) (*Finding, []MaskIssue, []ComplianceIssue, error) {
	a := NewAnalyzer(DefaultConfig())
	return a.AnalyzeJSON(jsonData)
}

func ScanFullStrict(jsonData string) (*Finding, []MaskIssue, []ComplianceIssue, error) {
	cfg := DefaultConfig()
	cfg.StrictMode = true
	a := NewAnalyzer(cfg)
	return a.AnalyzeJSON(jsonData)
}

func ScanBytes(data []byte) (*Finding, error) {
	return Scan(string(data))
}

func ScanFile(path string) (*Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secjson: read file %s: %w", path, err)
	}
	return Scan(string(data))
}

func ScanFileFull(path string) (*Finding, []MaskIssue, []ComplianceIssue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("secjson: read file %s: %w", path, err)
	}
	return ScanFull(string(data))
}

func IsSafe(jsonData string) bool {
	f, err := Scan(jsonData)
	if err != nil {
		return false
	}
	return f.RiskScore < 20
}

func QuickReport(jsonData string) (string, error) {
	finding, masks, compliance, err := ScanFull(jsonData)
	if err != nil {
		return "", err
	}
	report := GenerateReport(finding, masks, compliance)
	return report.Summary(), nil
}

func SaveReportTo(jsonData string, path string) error {
	finding, masks, compliance, err := ScanFull(jsonData)
	if err != nil {
		return err
	}
	report := GenerateReport(finding, masks, compliance)
	return report.SaveJSON(path)
}

func ScanFileAndSave(inputPath, outputPath string) error {
	finding, masks, compliance, err := ScanFileFull(inputPath)
	if err != nil {
		return err
	}
	report := GenerateReport(finding, masks, compliance)
	return report.SaveJSON(outputPath)
}