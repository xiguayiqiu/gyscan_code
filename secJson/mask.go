package secjson

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

func AnalyzeMasking(jsonData string, matches []Match) []MaskIssue {
	var issues []MaskIssue

	var data interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return issues
	}

	for _, m := range matches {
		if m.Field == "" {
			continue
		}

		rawValue := extractRawValue(data, m.Path)
		if rawValue == "" {
			continue
		}

		if issue := checkMaskingQuality(m.Field, m.Path, rawValue, m.Type, m.Category); issue != nil {
			issues = append(issues, *issue)
		}
	}

	return issues
}

func extractRawValue(data interface{}, path string) string {
	parts := strings.Split(path, ".")
	if len(parts) <= 1 {
		return ""
	}

	current := data
	for i := 1; i < len(parts); i++ {
		part := strings.TrimRight(parts[i], "[]0123456789")
		if idxStart := strings.Index(parts[i], "["); idxStart >= 0 {
			part = parts[i][:idxStart]
		}

		if m, ok := current.(map[string]interface{}); ok {
			if v, ok := m[part]; ok {
				current = v
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	if s, ok := current.(string); ok {
		return s
	}
	return ""
}

func checkMaskingQuality(field, path, value, dataType string, category Category) *MaskIssue {
	resolvedCategory := resolveCategory(field, category, dataType)
	switch resolvedCategory {
	case CategoryIdentity:
		return checkIdentityMasking(field, path, value)
	case CategoryFinance:
		return checkFinanceMasking(field, path, value)
	case CategoryCredential:
		return checkCredentialMasking(field, path, value)
	case CategoryPrivacy:
		return checkPrivacyMasking(field, path, value)
	}
	return nil
}

func resolveCategory(field string, category Category, dataType string) Category {
	if category == CategoryFinance && dataType == "bank_card_potential" {
		if isIdentityField(field) {
			return CategoryIdentity
		}
		if isCredentialField(field) {
			return CategoryCredential
		}
	}
	return category
}

func isIdentityField(field string) bool {
	var idFields = []string{"id_card", "card_id", "idcard", "identity_card", "passport", "ssn"}
	lower := strings.ToLower(field)
	for _, f := range idFields {
		if lower == f {
			return true
		}
	}
	return false
}

func isCredentialField(field string) bool {
	var credFields = []string{"token", "jwt", "access_token", "api_key", "apikey", "secret", "password"}
	lower := strings.ToLower(field)
	for _, f := range credFields {
		if lower == f {
			return true
		}
	}
	return false
}

func checkIdentityMasking(field, path, value string) *MaskIssue {
	if isMasked(value) {
		maskQuality := assessMaskQuality(value)
		if maskQuality < 50 {
			return &MaskIssue{
				Field:      field,
				Path:       path,
				Issue:      fmt.Sprintf("脱敏强度不足（当前%s%%可还原）", itoaMask(maskQuality)),
				Level:      "HIGH",
				Suggestion: "建议使用哈希+盐或AES-256加密替代简单掩码",
			}
		}
		return nil
	}

	return &MaskIssue{
		Field:      field,
		Path:       path,
		Issue:      "身份信息以明文存储，严重违规",
		Level:      "CRITICAL",
		Suggestion: "必须对身份证号等强监管字段进行加密存储，禁止明文",
	}
}

func checkFinanceMasking(field, path, value string) *MaskIssue {
	if isMasked(value) {
		return nil
	}

	if IsValidBankCard(value) {
		return &MaskIssue{
			Field:      field,
			Path:       path,
			Issue:      "银行卡号明文存储，违反PCI-DSS规范",
			Level:      "CRITICAL",
			Suggestion: "银行卡号必须加密存储，仅可保留后4位用于展示",
		}
	}

	return &MaskIssue{
		Field:      field,
		Path:       path,
		Issue:      "金融信息以明文存储",
		Level:      "HIGH",
		Suggestion: "金融相关字段建议使用AES-256-GCM加密存储",
	}
}

func checkCredentialMasking(field, path, value string) *MaskIssue {
	if len(value) > 8 && !isMasked(value) {
		return &MaskIssue{
			Field:      field,
			Path:       path,
			Issue:      "凭证/令牌以明文存储，泄露即获得访问权限",
			Level:      "CRITICAL",
			Suggestion: "凭证类字段严禁明文存储，应使用哈希或密封存储方案",
		}
	}
	return nil
}

func checkPrivacyMasking(field, path, value string) *MaskIssue {
	if !isMasked(value) {
		return &MaskIssue{
			Field:      field,
			Path:       path,
			Issue:      "个人隐私信息以明文存储",
			Level:      "MEDIUM",
			Suggestion: "建议对个人隐私字段进行脱敏处理，符合GDPR最小化原则",
		}
	}
	return nil
}

func isMasked(value string) bool {
	if strings.Contains(value, "****") || strings.Contains(value, "***") {
		return true
	}
	if matched, _ := regexp.MatchString(`^\d{3}\*+\d{4}$`, value); matched {
		return true
	}
	if matched, _ := regexp.MatchString(`^[a-zA-Z]+\*+[a-zA-Z]+$`, value); matched {
		return true
	}
	return false
}

func assessMaskQuality(maskedValue string) int {
	length := len(maskedValue)
	stars := strings.Count(maskedValue, "*")

	if stars == 0 {
		return 0
	}
	if length <= 4 && stars >= 2 {
		return 80
	}

	maskRatio := float64(stars) / float64(length) * 100
	switch {
	case maskRatio >= 80:
		return 90
	case maskRatio >= 60:
		return 70
	case maskRatio >= 40:
		return 50
	case maskRatio >= 20:
		return 30
	default:
		return 15
	}
}

func itoaMask(n int) string {
	return fmt.Sprintf("%d", n)
}