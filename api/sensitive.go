package api

import (
	"net/url"
	"regexp"
	"strings"
)

type SensitivityLevel string

const (
	SensCritical  SensitivityLevel = "critical"
	SensHigh      SensitivityLevel = "high"
	SensMedium    SensitivityLevel = "medium"
	SensLow       SensitivityLevel = "low"
	SensInfo      SensitivityLevel = "info"
	SensNone      SensitivityLevel = "none"
)

type SensitiveCategory string

const (
	CatAuth        SensitiveCategory = "auth"
	CatAdmin       SensitiveCategory = "admin"
	CatUser        SensitiveCategory = "user"
	CatPayment     SensitiveCategory = "payment"
	CatSecurity    SensitiveCategory = "security"
	CatInternal    SensitiveCategory = "internal"
	CatConfig      SensitiveCategory = "config"
	CatDataExport  SensitiveCategory = "data_export"
	CatHealthCheck SensitiveCategory = "health_check"
	CatDebug       SensitiveCategory = "debug"
	CatFileUpload  SensitiveCategory = "file_upload"
	CatWebhook     SensitiveCategory = "webhook"
	CatThirdParty  SensitiveCategory = "third_party"
)

type SensitiveAPI struct {
	Endpoint     *APIEndpoint
	Sensitivity  SensitivityLevel
	Categories   []SensitiveCategory
	SensitiveParams []string
	Reason       string
	RiskScore    float64
}

var sensitivePathPatterns = []struct {
	pattern  *regexp.Regexp
	level    SensitivityLevel
	category SensitiveCategory
	reason   string
}{
	{regexp.MustCompile(`(?i)/admin($|/)`), SensHigh, CatAdmin, "管理后台接口"},
	{regexp.MustCompile(`(?i)/manage(r)?($|/)`), SensHigh, CatAdmin, "管理接口"},
	{regexp.MustCompile(`(?i)/dashboard($|/)`), SensMedium, CatAdmin, "仪表盘接口"},
	{regexp.MustCompile(`(?i)/login($|/)`), SensCritical, CatAuth, "登录接口"},
	{regexp.MustCompile(`(?i)/logout($|/)`), SensHigh, CatAuth, "登出接口"},
	{regexp.MustCompile(`(?i)/register($|/)`), SensMedium, CatAuth, "注册接口"},
	{regexp.MustCompile(`(?i)/auth($|/)`), SensCritical, CatAuth, "认证接口"},
	{regexp.MustCompile(`(?i)/oauth($|/)`), SensCritical, CatAuth, "OAuth接口"},
	{regexp.MustCompile(`(?i)/token($|/)`), SensCritical, CatAuth, "Token接口"},
	{regexp.MustCompile(`(?i)/password($|/)`), SensCritical, CatAuth, "密码操作接口"},
	{regexp.MustCompile(`(?i)/reset($|/)`), SensCritical, CatAuth, "密码重置接口"},
	{regexp.MustCompile(`(?i)/user($|/)`), SensHigh, CatUser, "用户数据接口"},
	{regexp.MustCompile(`(?i)/profile($|/)`), SensHigh, CatUser, "个人信息接口"},
	{regexp.MustCompile(`(?i)/account($|/)`), SensHigh, CatUser, "账户接口"},
	{regexp.MustCompile(`(?i)/permission($|/)`), SensHigh, CatUser, "权限接口"},
	{regexp.MustCompile(`(?i)/role($|/)`), SensHigh, CatUser, "角色接口"},
	{regexp.MustCompile(`(?i)/payment($|/)`), SensCritical, CatPayment, "支付接口"},
	{regexp.MustCompile(`(?i)/pay($|/)`), SensCritical, CatPayment, "支付接口"},
	{regexp.MustCompile(`(?i)/order($|/)`), SensHigh, CatPayment, "订单接口"},
	{regexp.MustCompile(`(?i)/wallet($|/)`), SensCritical, CatPayment, "钱包接口"},
	{regexp.MustCompile(`(?i)/transaction($|/)`), SensHigh, CatPayment, "交易接口"},
	{regexp.MustCompile(`(?i)/balance($|/)`), SensHigh, CatPayment, "余额接口"},
	{regexp.MustCompile(`(?i)/invoice($|/)`), SensMedium, CatPayment, "发票接口"},
	{regexp.MustCompile(`(?i)/transfer($|/)`), SensCritical, CatPayment, "转账接口"},
	{regexp.MustCompile(`(?i)/config($|/)`), SensHigh, CatConfig, "配置接口"},
	{regexp.MustCompile(`(?i)/setting($|/)`), SensMedium, CatConfig, "设置接口"},
	{regexp.MustCompile(`(?i)/secret($|/)`), SensCritical, CatSecurity, "密钥接口"},
	{regexp.MustCompile(`(?i)/key($|/)`), SensCritical, CatSecurity, "密钥接口"},
	{regexp.MustCompile(`(?i)/certificate($|/)`), SensHigh, CatSecurity, "证书接口"},
	{regexp.MustCompile(`(?i)/internal($|/)`), SensHigh, CatInternal, "内部接口"},
	{regexp.MustCompile(`(?i)/private($|/)`), SensHigh, CatInternal, "私有接口"},
	{regexp.MustCompile(`(?i)/export($|/)`), SensHigh, CatDataExport, "数据导出接口"},
	{regexp.MustCompile(`(?i)/download($|/)`), SensMedium, CatDataExport, "下载接口"},
	{regexp.MustCompile(`(?i)/backup($|/)`), SensHigh, CatDataExport, "备份接口"},
	{regexp.MustCompile(`(?i)/health($|/)`), SensLow, CatHealthCheck, "健康检查接口"},
	{regexp.MustCompile(`(?i)/status($|/)`), SensLow, CatHealthCheck, "状态接口"},
	{regexp.MustCompile(`(?i)/debug($|/)`), SensCritical, CatDebug, "调试接口"},
	{regexp.MustCompile(`(?i)/test($|/)`), SensHigh, CatDebug, "测试接口"},
	{regexp.MustCompile(`(?i)/upload($|/)`), SensHigh, CatFileUpload, "文件上传接口"},
	{regexp.MustCompile(`(?i)/file($|/)`), SensMedium, CatFileUpload, "文件操作接口"},
	{regexp.MustCompile(`(?i)/webhook($|/)`), SensCritical, CatWebhook, "Webhook接口"},
	{regexp.MustCompile(`(?i)/callback($|/)`), SensCritical, CatWebhook, "回调接口"},
	{regexp.MustCompile(`(?i)/sso($|/)`), SensCritical, CatThirdParty, "单点登录接口"},
	{regexp.MustCompile(`(?i)/integration($|/)`), SensHigh, CatThirdParty, "集成接口"},
	{regexp.MustCompile(`(?i)/graphql`), SensHigh, CatDataExport, "GraphQL接口"},
	{regexp.MustCompile(`(?i)/query($|/)`), SensMedium, CatDataExport, "查询接口"},
	{regexp.MustCompile(`(?i)/search($|/)`), SensMedium, CatDataExport, "搜索接口"},
	{regexp.MustCompile(`(?i)/batch($|/)`), SensHigh, CatDataExport, "批量操作接口"},
	{regexp.MustCompile(`(?i)/import($|/)`), SensHigh, CatDataExport, "导入接口"},
	{regexp.MustCompile(`(?i)/bulk($|/)`), SensHigh, CatDataExport, "批量接口"},
}

var sensitiveParamPatterns = []struct {
	name     *regexp.Regexp
	level    SensitivityLevel
	category SensitiveCategory
	reason   string
}{
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key)`), SensCritical, CatSecurity, "密钥参数"},
	{regexp.MustCompile(`(?i)(token|auth[_-]?token|bearer|jwt|access[_-]?token)`), SensCritical, CatAuth, "Token参数"},
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|credentials)`), SensCritical, CatAuth, "密码/凭证参数"},
	{regexp.MustCompile(`(?i)(ssn|social[_-]?security|id[_-]?card|idcard)`), SensCritical, CatUser, "身份标识参数"},
	{regexp.MustCompile(`(?i)(credit[_-]?card|card[_-]?number|cc[_-]?number|pan)`), SensCritical, CatPayment, "银行卡参数"},
	{regexp.MustCompile(`(?i)(cvv|cvc|cid|cvv2)`), SensCritical, CatPayment, "CVV参数"},
	{regexp.MustCompile(`(?i)(account[_-]?number|routing[_-]?number|iban|swift)`), SensCritical, CatPayment, "银行账户参数"},
	{regexp.MustCompile(`(?i)(phone|mobile|cellphone|telephone)`), SensHigh, CatUser, "手机号参数"},
	{regexp.MustCompile(`(?i)(email|mail|e[-_]?mail)`), SensHigh, CatUser, "邮箱参数"},
	{regexp.MustCompile(`(?i)(address|addr|location|zip[_-]?code|postal)`), SensMedium, CatUser, "地址参数"},
	{regexp.MustCompile(`(?i)(ip[_-]?address|ip_addr|client[_-]?ip)`), SensMedium, CatUser, "IP地址参数"},
	{regexp.MustCompile(`(?i)(birth|birthday|dob|age)`), SensMedium, CatUser, "出生日期参数"},
	{regexp.MustCompile(`(?i)(role|permission|privilege|is[_-]?admin|is[_-]?superuser)`), SensCritical, CatAdmin, "权限参数"},
	{regexp.MustCompile(`(?i)(debug|verbose|trace|xdebug)`), SensCritical, CatDebug, "调试参数"},
	{regexp.MustCompile(`(?i)(callback|redirect[_-]?url|return[_-]?url|next[_-]?url)`), SensHigh, CatWebhook, "回调/重定向参数"},
	{regexp.MustCompile(`(?i)(amount|price|cost|fee|charge|total)`), SensHigh, CatPayment, "金额参数"},
	{regexp.MustCompile(`(?i)(sql|query|filter|where|sort|order[_-]?by)`), SensHigh, CatDataExport, "查询/过滤参数"},
	{regexp.MustCompile(`(?i)(limit|offset|page|per[_-]?page|page[_-]?size)`), SensMedium, CatDataExport, "分页参数"},
}

var sensitiveMethodPaths = []struct {
	methodMap map[string]SensitivityLevel
	pathRe    *regexp.Regexp
}{
	{
		map[string]SensitivityLevel{"DELETE": SensCritical, "PUT": SensHigh, "PATCH": SensHigh},
		regexp.MustCompile(`(?i)/(user|account|profile|order|payment)`),
	},
	{
		map[string]SensitivityLevel{"POST": SensCritical},
		regexp.MustCompile(`(?i)/(login|auth|token|oauth|register)`),
	},
}

func ClassifySensitiveAPI(endpoint *APIEndpoint) *SensitiveAPI {
	sa := &SensitiveAPI{
		Endpoint:    endpoint,
		Sensitivity: SensNone,
	}

	path := endpoint.Path
	method := endpointMethod(endpoint)

	for _, sp := range sensitivePathPatterns {
		if sp.pattern.MatchString(path) {
			sa.Categories = append(sa.Categories, sp.category)
			sa.Reason += sp.reason + "; "
			if ordLevel(sp.level) > ordLevel(sa.Sensitivity) {
				sa.Sensitivity = sp.level
			}
		}
	}

	for _, smp := range sensitiveMethodPaths {
		if smp.pathRe.MatchString(path) {
			if lv, ok := smp.methodMap[method]; ok {
				if ordLevel(lv) > ordLevel(sa.Sensitivity) {
					sa.Sensitivity = lv
					sa.Reason += "敏感方法操作 (" + method + "); "
				}
			}
		}
	}

	if sa.Sensitivity != SensNone {
		sa.RiskScore = sensitivityScore(sa.Sensitivity)
	}

	return sa
}

func ClassifySensitiveAPIs(endpoints []*APIEndpoint) []*SensitiveAPI {
	result := make([]*SensitiveAPI, 0)
	for _, ep := range endpoints {
		sa := ClassifySensitiveAPI(ep)
		if sa.Sensitivity != SensNone {
			result = append(result, sa)
		}
	}
	return result
}

func AnalyzeSensitiveParameters(params url.Values) []SensitiveAPI {
	var results []SensitiveAPI
	for name := range params {
		for _, sp := range sensitiveParamPatterns {
			if sp.name.MatchString(name) {
				results = append(results, SensitiveAPI{
					Sensitivity:    sp.level,
					Categories:     []SensitiveCategory{sp.category},
					SensitiveParams: []string{name},
					Reason:         sp.reason + " (" + name + ")",
					RiskScore:      sensitivityScore(sp.level),
				})
				break
			}
		}
	}
	return results
}

func AnalyzeEndpointParams(endpoint *APIEndpoint) *SensitiveAPI {
	sa := ClassifySensitiveAPI(endpoint)

	rawURL := endpoint.Path
	if endpoint.Host != "" {
		rawURL = "http://" + endpoint.Host + endpoint.Path
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return sa
	}

	q := u.Query()
	for name := range q {
		for _, sp := range sensitiveParamPatterns {
			if sp.name.MatchString(name) {
				sa.SensitiveParams = append(sa.SensitiveParams, name)
				sa.Categories = append(sa.Categories, sp.category)
				sa.Reason += sp.reason + " (" + name + "); "
				if ordLevel(sp.level) > ordLevel(sa.Sensitivity) {
					sa.Sensitivity = sp.level
				}
				break
			}
		}
	}

	if sa.Sensitivity != SensNone {
		sa.RiskScore = sensitivityScore(sa.Sensitivity)
	}

	return sa
}

func FilterBySensitivity(sas []*SensitiveAPI, minLevel SensitivityLevel) []*SensitiveAPI {
	var result []*SensitiveAPI
	for _, sa := range sas {
		if ordLevel(sa.Sensitivity) >= ordLevel(minLevel) {
			result = append(result, sa)
		}
	}
	return result
}

func GroupBySensitivityCategory(sas []*SensitiveAPI) map[SensitiveCategory][]*SensitiveAPI {
	groups := make(map[SensitiveCategory][]*SensitiveAPI)
	for _, sa := range sas {
		for _, cat := range sa.Categories {
			groups[cat] = append(groups[cat], sa)
		}
	}
	return groups
}

func SensitiveSummary(sas []*SensitiveAPI) string {
	if len(sas) == 0 {
		return "未发现敏感API"
	}

	m := make(map[SensitivityLevel]int)
	cats := make(map[SensitiveCategory]int)

	for _, sa := range sas {
		m[sa.Sensitivity]++
		for _, cat := range sa.Categories {
			cats[cat]++
		}
	}

	order := []SensitivityLevel{SensCritical, SensHigh, SensMedium, SensLow, SensInfo}
	var lines []string
	for _, l := range order {
		if c := m[l]; c > 0 {
			lines = append(lines, strings.Title(string(l))+": "+itoa(c)+"个")
		}
	}

	var catLines []string
	for cat, c := range cats {
		catLines = append(catLines, string(cat)+":"+itoa(c)+"个")
	}

	return "敏感API总数: " + itoa(len(sas)) + "\n  按级别: " + strings.Join(lines, ", ") + "\n  按类别: " + strings.Join(catLines, ", ")
}

func sensitivityScore(lv SensitivityLevel) float64 {
	switch lv {
	case SensCritical:
		return 90
	case SensHigh:
		return 70
	case SensMedium:
		return 50
	case SensLow:
		return 25
	case SensInfo:
		return 10
	default:
		return 0
	}
}

func ordLevel(lv SensitivityLevel) int {
	switch lv {
	case SensCritical:
		return 5
	case SensHigh:
		return 3
	case SensMedium:
		return 2
	case SensLow:
		return 1
	case SensInfo:
		return 0
	default:
		return -1
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}