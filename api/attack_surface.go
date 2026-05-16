package api

import (
	"regexp"
	"strings"
)

type AttackSurfaceCategory string

const (
	ASCHighRiskAPI     AttackSurfaceCategory = "high_risk_api"
	ASCAuthAPI         AttackSurfaceCategory = "auth_api"
	ASCAdminAPI        AttackSurfaceCategory = "admin_api"
	ASCDataLeakAPI     AttackSurfaceCategory = "data_leak_api"
	ASCUnauthAPI       AttackSurfaceCategory = "unauth_api"
	ASCInternalAPI     AttackSurfaceCategory = "internal_api"
	ASCDebugAPI        AttackSurfaceCategory = "debug_api"
	ASCFileAPI         AttackSurfaceCategory = "file_api"
	ASCInjectionAPI    AttackSurfaceCategory = "injection_api"
)

type AttackSurface struct {
	Endpoint   *APIEndpoint
	Categories []AttackSurfaceCategory
	RiskScore  float64
	Severity   string
	Issues     []string
}

var highRiskPatterns = []struct {
	pathRe    *regexp.Regexp
	category  AttackSurfaceCategory
	issue     string
	riskScore float64
}{
	{regexp.MustCompile(`(?i)/(admin|manage|dashboard|control|master|root)$`), ASCAdminAPI, "后台管理接口暴露", 85},
	{regexp.MustCompile(`(?i)/(config|setting|env|environment|property)`), ASCInternalAPI, "配置接口暴露", 80},
	{regexp.MustCompile(`(?i)/(debug|trace|profiling|pprof|health|actuator|metrics)`), ASCDebugAPI, "调试/监控接口暴露", 95},
	{regexp.MustCompile(`(?i)/(download|export|backup|dump|snapshot)`), ASCDataLeakAPI, "数据导出接口暴露", 85},
	{regexp.MustCompile(`(?i)/(upload|uploader|file|tmp/upload)`), ASCFileAPI, "文件上传接口暴露", 80},
	{regexp.MustCompile(`(?i)/(swagger|docs|api-docs|openapi|redoc|api\.json)`), ASCInternalAPI, "API文档暴露", 75},
	{regexp.MustCompile(`(?i)/(graphql|graphiql|playground|voyager)`), ASCDataLeakAPI, "GraphQL接口暴露", 80},
	{regexp.MustCompile(`(?i)/(sql|query|raw|execute)`), ASCInjectionAPI, "原始查询接口暴露", 90},
	{regexp.MustCompile(`(?i)/(webhook|callback|hook|event)`), ASCHighRiskAPI, "Webhook接口暴露", 75},
}

var authPatterns = []struct {
	pathRe    *regexp.Regexp
	category  AttackSurfaceCategory
	issue     string
	riskScore float64
}{
	{regexp.MustCompile(`(?i)/(login|signin|auth|authenticate|oauth|sso|saml)`), ASCAuthAPI, "认证接口", 70},
	{regexp.MustCompile(`(?i)/(register|signup|create_account|onboard)`), ASCAuthAPI, "注册接口", 60},
	{regexp.MustCompile(`(?i)/(password|passwd|reset|forgot|change_password)`), ASCAuthAPI, "密码操作接口", 90},
	{regexp.MustCompile(`(?i)/(token|jwt|refresh|session|cookie)`), ASCAuthAPI, "Token/会话接口", 85},
	{regexp.MustCompile(`(?i)/(two_factor|2fa|mfa|otp|totp|verify)`), ASCAuthAPI, "多因子认证接口", 75},
	{regexp.MustCompile(`(?i)/(logout|signout|revoke|invalidate)`), ASCAuthAPI, "登出/撤销接口", 60},
}

var unauthPatterns = []struct {
	pathRe    *regexp.Regexp
	category  AttackSurfaceCategory
	issue     string
	riskScore float64
}{
	{regexp.MustCompile(`(?i)/(payment|pay|checkout|transaction|order|wallet|balance)`), ASCDataLeakAPI, "支付/交易接口可能未认证", 95},
	{regexp.MustCompile(`(?i)/(user|profile|account|member|customer)`), ASCDataLeakAPI, "用户数据接口可能未认证", 85},
	{regexp.MustCompile(`(?i)/(api/v?\d+/message|api/v?\d+/chat|api/v?\d+/notification)`), ASCDataLeakAPI, "消息/通知接口可能未认证", 70},
}

func AnalyzeAttackSurface(endpoint *APIEndpoint) *AttackSurface {
	as := &AttackSurface{
		Endpoint: endpoint,
	}

	lower := strings.ToLower(endpoint.Path)

	for _, p := range highRiskPatterns {
		if p.pathRe.MatchString(lower) {
			as.Categories = append(as.Categories, p.category)
			as.Issues = append(as.Issues, p.issue)
			if p.riskScore > as.RiskScore {
				as.RiskScore = p.riskScore
			}
		}
	}

	for _, p := range authPatterns {
		if p.pathRe.MatchString(lower) {
			as.Categories = append(as.Categories, p.category)
			as.Issues = append(as.Issues, p.issue)
			if p.riskScore > as.RiskScore {
				as.RiskScore = p.riskScore
			}
		}
	}

	for _, p := range unauthPatterns {
		if p.pathRe.MatchString(lower) {
			as.Categories = append(as.Categories, p.category)
			as.Issues = append(as.Issues, p.issue)
			if p.riskScore > as.RiskScore {
				as.RiskScore = p.riskScore
			}
		}
	}

	if as.RiskScore >= 90 {
		as.Severity = "critical"
	} else if as.RiskScore >= 70 {
		as.Severity = "high"
	} else if as.RiskScore >= 50 {
		as.Severity = "medium"
	} else if as.RiskScore > 0 {
		as.Severity = "low"
	} else {
		as.Severity = "info"
	}

	return as
}

func AnalyzeAttackSurfaces(endpoints []*APIEndpoint) []*AttackSurface {
	var result []*AttackSurface
	for _, ep := range endpoints {
		as := AnalyzeAttackSurface(ep)
		if len(as.Categories) > 0 {
			result = append(result, as)
		}
	}
	return result
}

func AttackSurfaceSummary(attackSurfaces []*AttackSurface) string {
	if len(attackSurfaces) == 0 {
		return "未发现攻击面"
	}

	m := make(map[string]int)
	catCount := make(map[AttackSurfaceCategory]int)

	for _, as := range attackSurfaces {
		m[as.Severity]++
		for _, cat := range as.Categories {
			catCount[cat]++
		}
	}

	result := "攻击面分析摘要:\n"
	result += "  总风险API: " + itoa(len(attackSurfaces)) + " 个\n"

	order := []string{"critical", "high", "medium", "low", "info"}
	for _, s := range order {
		if c := m[s]; c > 0 {
			result += "  " + s + ": " + itoa(c) + " 个\n"
		}
	}

	result += "  各类别: "
	var catLines []string
	for cat, c := range catCount {
		catLines = append(catLines, string(cat)+":"+itoa(c))
	}
	result += strings.Join(catLines, ", ")

	return result
}

func FindAdminAPIs(endpoints []*APIEndpoint) []*AttackSurface {
	var result []*AttackSurface
	for _, as := range AnalyzeAttackSurfaces(endpoints) {
		for _, cat := range as.Categories {
			if cat == ASCAdminAPI {
				result = append(result, as)
				break
			}
		}
	}
	return result
}

func FindAuthAPIs(endpoints []*APIEndpoint) []*AttackSurface {
	var result []*AttackSurface
	for _, as := range AnalyzeAttackSurfaces(endpoints) {
		for _, cat := range as.Categories {
			if cat == ASCAuthAPI {
				result = append(result, as)
				break
			}
		}
	}
	return result
}

func FindDataLeakAPIs(endpoints []*APIEndpoint) []*AttackSurface {
	var result []*AttackSurface
	for _, as := range AnalyzeAttackSurfaces(endpoints) {
		for _, cat := range as.Categories {
			if cat == ASCDataLeakAPI {
				result = append(result, as)
				break
			}
		}
	}
	return result
}

func FindDebugAPIs(endpoints []*APIEndpoint) []*AttackSurface {
	var result []*AttackSurface
	for _, as := range AnalyzeAttackSurfaces(endpoints) {
		for _, cat := range as.Categories {
			if cat == ASCDebugAPI {
				result = append(result, as)
				break
			}
		}
	}
	return result
}

func FilterByRiskScore(surfaces []*AttackSurface, minScore float64) []*AttackSurface {
	var result []*AttackSurface
	for _, as := range surfaces {
		if as.RiskScore >= minScore {
			result = append(result, as)
		}
	}
	return result
}

func TopRiskyAPIs(surfaces []*AttackSurface, n int) []*AttackSurface {
	if n <= 0 {
		return nil
	}

	sorted := make([]*AttackSurface, len(surfaces))
	copy(sorted, surfaces)

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].RiskScore > sorted[i].RiskScore {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}