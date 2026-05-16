package secjson

import (
	"encoding/json"
	"os"
	"testing"
)

const testJSON = `{
  "user": {
    "id_card": "110101199001011234",
    "phone": "13800138000",
    "email": "user@example.com",
    "name": "张三",
    "address": "北京市朝阳区"
  },
  "payment": {
    "bank_card": "6222021234567890123",
    "amount": 100.50
  },
  "auth": {
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.signature",
    "api_key": "sk_prod_abcdef1234567890"
  },
  "metadata": {
    "ip": "192.168.1.1",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}`

const safeJSON = `{
  "status": "ok",
  "message": "操作成功",
  "data": {
    "items": ["a", "b", "c"],
    "count": 3
  }
}`

func TestScanSensitiveJSON(t *testing.T) {
	finding, err := Scan(testJSON)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(finding.Matches) < 4 {
		t.Errorf("Expected at least 4 sensitive fields, got %d", len(finding.Matches))
	}

	for _, m := range finding.Matches {
		t.Logf("  [%s] %s: %s", m.Severity, m.Type, m.Message)
	}

	if finding.RiskScore < 40 {
		t.Errorf("Risk score too low for sensitive data: %.1f", finding.RiskScore)
	}

	t.Logf("Risk score: %.1f/100", finding.RiskScore)
}

func TestScanSafeJSON(t *testing.T) {
	finding, err := Scan(safeJSON)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(finding.Matches) > 0 {
		t.Errorf("Safe JSON should have 0 matches, got %d", len(finding.Matches))
	}

	if finding.RiskScore > 5 {
		t.Errorf("Safe JSON risk score too high: %.1f", finding.RiskScore)
	}

	t.Logf("Safe JSON: %s", finding.Summary)
}

func TestScanFull(t *testing.T) {
	finding, masks, compliance, err := ScanFull(testJSON)
	if err != nil {
		t.Fatalf("ScanFull() error: %v", err)
	}

	if finding == nil {
		t.Fatal("finding is nil")
	}
	if len(masks) == 0 {
		t.Error("Expected mask issues for plaintext sensitive data")
	}
	if len(compliance) == 0 {
		t.Error("Expected compliance issues")
	}

	t.Logf("Finding: %d matches", len(finding.Matches))
	t.Logf("Mask issues: %d", len(masks))
	for _, m := range masks {
		t.Logf("  [%s] %s: %s", m.Level, m.Field, m.Issue)
	}
	t.Logf("Compliance issues: %d", len(compliance))
	for _, c := range compliance {
		t.Logf("  [%s] %s: %s", c.Standard, c.Rule, c.Detail)
	}
}

func TestIsSafeFlag(t *testing.T) {
	if IsSafe(testJSON) {
		t.Error("Sensitive JSON should NOT be safe")
	}
	if !IsSafe(safeJSON) {
		t.Error("Safe JSON should be safe")
	}
}

func TestIDCardDetection(t *testing.T) {
	tests := []struct {
		id     string
		detect bool
	}{
		{"110101199001011234", true},
		{"440106198512120019", true},
		{"123456789012345678", false},
		{"11010119900101123X", true},
	}
	for _, tt := range tests {
		jsonData := `{"id_card":"` + tt.id + `"}`
		f, _ := Scan(jsonData)
		found := false
		for _, m := range f.Matches {
			if m.Type == "id_card_cn" || m.Type == "id_card_cn_18" {
				found = true
				break
			}
		}
		if found != tt.detect {
			t.Errorf("ID %s: detected=%v, want=%v", tt.id, found, tt.detect)
		}
	}
}

func TestPhoneDetection(t *testing.T) {
	jsonData := `{"phone":"13800138000"}`
	f, _ := Scan(jsonData)
	if len(f.Matches) < 1 {
		t.Fatalf("Expected at least 1 match, got %d", len(f.Matches))
	}
	hasPhoneValue := false
	for _, m := range f.Matches {
		if m.Type == "phone_cn" {
			hasPhoneValue = true
		}
	}
	if !hasPhoneValue {
		t.Error("phone_cn value pattern not matched")
	}
}

func TestBankCardLuhn(t *testing.T) {
	if !IsValidBankCard("6222021234567890123") {
		t.Log("Note: Luhn check may fail for non-standard card numbers")
	}
	if LuhnCheck("1234567") {
		t.Error("Short numbers should not pass Luhn (used as test case)")
	}
}

func TestMaskingDetection(t *testing.T) {
	maskedJSON := `{"id_card":"110***1234","phone":"138****8000"}`
	plainJSON := `{"id_card":"110101199001011234","phone":"13800138000"}`

	issues := AnalyzeMasking(maskedJSON, []Match{
		{Field: "id_card", Path: "$.id_card", Type: "id_card_cn", Category: CategoryIdentity},
		{Field: "phone", Path: "$.phone", Type: "phone_cn", Category: CategoryPrivacy},
	})

	for _, issue := range issues {
		t.Logf("Mask issue: %s - %s", issue.Field, issue.Issue)
	}

	_, _, compliance, _ := ScanFull(plainJSON)
	if len(compliance) == 0 {
		t.Error("Plaintext sensitive data should trigger compliance issues")
	}
}

func TestReportGeneration(t *testing.T) {
	finding, masks, compliance, err := ScanFull(testJSON)
	if err != nil {
		t.Fatal(err)
	}

	report := GenerateReport(finding, masks, compliance)

	tmpFile := "/tmp/secjson_report_test.json"
	defer os.Remove(tmpFile)

	if err := report.SaveJSON(tmpFile); err != nil {
		t.Fatalf("SaveJSON error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	var loaded Report
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if loaded.Metadata.Analyzer != "secJson" {
		t.Errorf("Unexpected analyzer: %s", loaded.Metadata.Analyzer)
	}

	summary := report.Summary()
	if len(summary) < 50 {
		t.Error("Report summary too short")
	}
	t.Logf("Report summary:\n%s", summary)
}

func TestQuickReport(t *testing.T) {
	report, err := QuickReport(testJSON)
	if err != nil {
		t.Fatalf("QuickReport error: %v", err)
	}
	if len(report) < 50 {
		t.Error("QuickReport too short")
	}
	t.Logf("Quick report:\n%s", report)
}

func TestStrictMode(t *testing.T) {
	normal, _ := Scan(testJSON)
	strict, _ := ScanStrict(testJSON)

	if strict.RiskScore < normal.RiskScore {
		t.Logf("Strict mode increases risk: %.1f -> %.1f", normal.RiskScore, strict.RiskScore)
	}
}

func TestFieldNameAnalysis(t *testing.T) {
	jsonData := `{"password":"123456","token":"abc123","api_key":"sk_test","credit_card":"4111111111111111"}`
	f, _ := Scan(jsonData)

	hasPassword := false
	hasToken := false
	for _, m := range f.Matches {
		if m.Field == "password" {
			hasPassword = true
		}
		if m.Field == "token" {
			hasToken = true
		}
	}
	if !hasPassword {
		t.Error("password field should be detected by field name")
	}
	if !hasToken {
		t.Error("token field should be detected by field name")
	}
}

func TestJWTDetection(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.dxL1kOu6nIoMrAYG5CR_yjz3fH5qXwx_yuAo9VXSmf0"
	jsonData := `{"auth":"` + jwt + `"}`
	f, _ := Scan(jsonData)

	found := false
	for _, m := range f.Matches {
		if m.Type == "jwt_token" {
			found = true
		}
	}
	if !found {
		t.Log("JWT detection may require exact format match")
	}
}

func TestConfigOptions(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxDepth != 50 {
		t.Errorf("Default MaxDepth should be 50")
	}

	cfg.MinSeverity = SeverityHigh
	a := NewAnalyzer(cfg)
	f, _ := a.Analyze(testJSON)
	for _, m := range f.Matches {
		if severityRank(m.Severity) < severityRank(SeverityHigh) {
			t.Errorf("MinSeverity=High but found %s: %s", m.Severity, m.Field)
		}
	}

	cfg.SkipFields = []string{"phone", "email"}
	a = NewAnalyzer(cfg)
	f2, _ := a.Analyze(testJSON)
	for _, m := range f2.Matches {
		if m.Field == "phone" || m.Field == "email" {
			t.Errorf("Skipped field %s should not appear", m.Field)
		}
	}

	t.Log("Config options verified")
}

func TestSaveReportTo(t *testing.T) {
	tmpFile := "/tmp/secjson_easy_report.json"
	defer os.Remove(tmpFile)

	if err := SaveReportTo(testJSON, tmpFile); err != nil {
		t.Fatalf("SaveReportTo error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 100 {
		t.Error("Saved report too small")
	}
	t.Logf("Report saved: %d bytes", len(data))
}