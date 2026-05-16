package secjson

import (
	"encoding/json"
	"strings"
)

var complianceRules = []struct {
	standard  string
	rule      string
	check     func(matches []Match, data map[string]interface{}) *ComplianceIssue
}{
	{
		standard: "PCI-DSS",
		rule:     "禁止明文存储PAN",
		check: func(matches []Match, _ map[string]interface{}) *ComplianceIssue {
			for _, m := range matches {
				if m.Category == CategoryFinance &&
					(m.Type == "credit_card" || m.Type == "bank_card_potential") &&
					m.Value == m.Masked {
					return &ComplianceIssue{
						Standard: "PCI-DSS",
						Rule:     "禁止明文存储PAN",
						Field:    m.Field,
						Path:     m.Path,
						Status:   "违反",
						Detail:   "PAN（主账号）以明文存储在JSON中，PCI-DSS要求#3.4必须加密",
					}
				}
			}
			return nil
		},
	},
	{
		standard: "PCI-DSS",
		rule:     "禁止存储CVV/CVC",
		check: func(matches []Match, _ map[string]interface{}) *ComplianceIssue {
			for _, m := range matches {
				if m.Type == "cvv_field" {
					return &ComplianceIssue{
						Standard: "PCI-DSS",
						Rule:     "禁止存储CVV/CVC",
						Field:    m.Field,
						Path:     m.Path,
						Status:   "严重违反",
						Detail:   "CVV/CVC在任何情况下都不得存储，PCI-DSS要求#3.2",
					}
				}
			}
			return nil
		},
	},
	{
		standard: "GDPR",
		rule:     "个人数据的合法处理",
		check: func(matches []Match, _ map[string]interface{}) *ComplianceIssue {
			hasPII := false
			for _, m := range matches {
				if m.Category == CategoryIdentity || m.Category == CategoryPrivacy {
					hasPII = true
					break
				}
			}
			if hasPII {
				return &ComplianceIssue{
					Standard: "GDPR",
					Rule:     "个人数据的合法处理",
					Status:   "需评估",
					Detail:   "JSON中包含个人身份信息(PII)，需确认处理目的合法且有适当保护措施",
				}
			}
			return nil
		},
	},
	{
		standard: "GDPR",
		rule:     "数据最小化原则",
		check: func(matches []Match, _ map[string]interface{}) *ComplianceIssue {
			count := 0
			for _, m := range matches {
				if m.Category == CategoryPrivacy || m.Category == CategoryIdentity {
					count++
				}
			}
			if count > 5 {
				return &ComplianceIssue{
					Standard: "GDPR",
					Rule:     "数据最小化原则",
					Status:   "需审查",
					Detail:   "JSON中包含大量个人数据字段（>5个），可能违反数据最小化原则",
				}
			}
			return nil
		},
	},
	{
		standard: "等保2.0",
		rule:     "敏感字段加密存储",
		check: func(matches []Match, jsonData map[string]interface{}) *ComplianceIssue {
			for _, m := range matches {
				if m.Severity == SeverityCritical || m.Severity == SeverityHigh {
					if m.Value == m.Masked {
						return &ComplianceIssue{
							Standard: "等保2.0",
							Rule:     "敏感字段加密存储",
							Field:    m.Field,
							Path:     m.Path,
							Status:   "不符合",
							Detail:   "三级以上系统要求敏感字段存储加密率100%",
						}
					}
				}
			}
			return nil
		},
	},
	{
		standard: "数据安全法",
		rule:     "重要数据分类分级",
		check: func(matches []Match, _ map[string]interface{}) *ComplianceIssue {
			hasCritical := false
			for _, m := range matches {
				if m.Severity == SeverityCritical {
					hasCritical = true
					break
				}
			}
			if hasCritical {
				return &ComplianceIssue{
					Standard: "数据安全法",
					Rule:     "重要数据分类分级",
					Status:   "需落实",
					Detail:   "JSON中包含重要级别数据，需按数据安全法对数据进行分类分级保护",
				}
			}
			return nil
		},
	},
}

func CheckCompliance(jsonData string, matches []Match, config *Config) []ComplianceIssue {
	var data interface{}

	var dataMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err == nil {
		if m, ok := data.(map[string]interface{}); ok {
			dataMap = m
		}
	}

	var issues []ComplianceIssue
	for _, rule := range complianceRules {
		issue := rule.check(matches, dataMap)
		if issue != nil {
			issues = append(issues, *issue)
		}
	}

	for _, m := range matches {
		if m.Category == CategoryBiometric && !strings.Contains(jsonData, "encrypted") && !strings.Contains(jsonData, "hash") {
			issues = append(issues, ComplianceIssue{
				Standard: "GDPR",
				Rule:     "生物特征特殊保护",
				Field:    m.Field,
				Path:     m.Path,
				Status:   "需评估",
				Detail:   "生物特征数据属于特殊类别数据，GDPR要求额外保护措施",
			})
			break
		}
	}

	return issues
}