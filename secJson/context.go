package secjson

import "strings"

func CombineRisk(matches []Match) []Match {
	type combo struct {
		fields []string
		desc   string
	}

	has := func(fieldType string) bool {
		for _, m := range matches {
			if m.Type == fieldType {
				return true
			}
		}
		return false
	}

	combos := []combo{
		{[]string{"id_card_cn", "phone_cn"}, "身份证+手机号组合可精准定位个人身份"},
		{[]string{"id_card_cn", "email"}, "身份证+邮箱组合可关联多个账号"},
		{[]string{"id_card_cn", "ip_address"}, "身份证+IP地址可追溯用户地理位置"},
		{[]string{"bank_card_potential", "phone_cn"}, "银行卡+手机号可用于金融诈骗"},
		{[]string{"phone_cn", "address_field"}, "手机+地址可用于线下骚扰"},
		{[]string{"api_key", "token_field"}, "API密钥+Token组合可获取完整权限"},
		{[]string{"jwt_token", "password_field"}, "JWT+密码字段表示认证信息完整泄露"},
		{[]string{"phone_cn", "jwt_token"}, "手机号+JWT可劫持用户会话"},
	}

	var extra []Match
	for _, c := range combos {
		allFound := true
		for _, t := range c.fields {
			if !has(t) {
				allFound = false
				break
			}
		}
		if allFound {
			extra = append(extra, Match{
				Type:     "combined_risk",
				Category: CategoryCombined,
				Severity: SeverityCritical,
				Message:  c.desc,
			})
		}
	}

	return extra
}

func ContextWeight(path string) float64 {
	if strings.Contains(path, "/admin") || strings.Contains(path, "/manage") {
		return 1.5
	}
	if strings.Contains(path, "/api/user") || strings.Contains(path, "/profile") {
		return 1.3
	}
	if strings.Contains(path, "/login") || strings.Contains(path, "/auth") {
		return 1.4
	}
	if strings.Contains(path, "/register") || strings.Contains(path, "/signup") {
		return 1.3
	}
	if strings.Contains(path, "/payment") || strings.Contains(path, "/order") {
		return 1.5
	}
	if strings.Contains(path, "/internal") || strings.Contains(path, "/private") {
		return 1.6
	}
	return JSONPathWeight(path)
}

func JSONPathWeight(path string) float64 {
	if strings.Contains(path, ".password") || strings.Contains(path, ".secret") || strings.Contains(path, ".token") {
		return 1.5
	}
	if strings.Contains(path, ".auth") || strings.Contains(path, ".credential") {
		return 1.4
	}
	if strings.Contains(path, ".payment") || strings.Contains(path, ".bank") || strings.Contains(path, ".finance") {
		return 1.4
	}
	if strings.Contains(path, ".user") || strings.Contains(path, ".profile") || strings.Contains(path, ".account") {
		return 1.2
	}
	if strings.Contains(path, ".admin") || strings.Contains(path, ".internal") {
		return 1.5
	}
	return 1.0
}