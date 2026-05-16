package api

import (
	"regexp"
	"strings"
)

type ParameterRisk string

const (
	ParamRiskCritical ParameterRisk = "critical"
	ParamRiskHigh     ParameterRisk = "high"
	ParamRiskMedium   ParameterRisk = "medium"
	ParamRiskLow      ParameterRisk = "low"
	ParamRiskNone     ParameterRisk = "none"
)

type ParamAnalysis struct {
	Endpoint        *APIEndpoint
	Parameters      []AnalysedParam
	RiskLevel       ParameterRisk
	RiskScore       float64
	Issues          []string
	SensitiveParams []SensitiveParam
}

type AnalysedParam struct {
	Name           string
	TypeHint       string
	Required       bool
	RiskScore      float64
	Category       string
	InjectionRisks []string
}

type SensitiveParam struct {
	Param       string
	Risk        ParameterRisk
	Category    string
	Description string
}

type APICompareResult struct {
	Added    []*APIEndpoint
	Removed  []*APIEndpoint
	Modified []*APIEndpoint
	Same     []*APIEndpoint
}

var paramTypeHints = []struct {
	pattern *regexp.Regexp
	hint    string
}{
	{regexp.MustCompile(`(?i)^id$`), "identifier"},
	{regexp.MustCompile(`(?i)_id$`), "foreign_key"},
	{regexp.MustCompile(`(?i)^is_|^has_|^can_|^should_|^enable_|^disable_`), "boolean"},
	{regexp.MustCompile(`(?i)^date$|^timestamp$|_at$|_on$|^created|^updated`), "datetime"},
	{regexp.MustCompile(`(?i)^email`), "email"},
	{regexp.MustCompile(`(?i)^phone|^mobile`), "phone"},
	{regexp.MustCompile(`(?i)^url$|^link$|^href$|_url$|_link$|_href$`), "url"},
	{regexp.MustCompile(`(?i)^status$|^state$|^type$|^kind$`), "enum"},
	{regexp.MustCompile(`(?i)^count$|^total$|^sum$|^amount$|^price$|^quantity$|_count$|_total$`), "number"},
	{regexp.MustCompile(`(?i)^file$|^image$|^photo$|^avatar$|^attachment$`), "file"},
}

var injectionPatterns = []struct {
	paramPattern *regexp.Regexp
	risk         ParameterRisk
	description  string
}{
	{regexp.MustCompile(`(?i)(search|query|filter|keyword|find)`), ParamRiskHigh, "搜索/查询参数，可能存在注入风险"},
	{regexp.MustCompile(`(?i)(id|user_id|order_id|product_id|item_id)`), ParamRiskHigh, "ID参数，可能存在越权风险"},
	{regexp.MustCompile(`(?i)(sort|order_by|sort_by|sort_direction)`), ParamRiskMedium, "排序参数，可能存在注入风险"},
	{regexp.MustCompile(`(?i)(limit|offset|page|page_size|per_page)`), ParamRiskLow, "分页参数，可能存在DoS风险"},
	{regexp.MustCompile(`(?i)(callback|redirect|return_url|next|redirect_uri)`), ParamRiskHigh, "重定向参数，可能存在SSRF风险"},
	{regexp.MustCompile(`(?i)(file|path|filename|filepath)`), ParamRiskCritical, "文件路径参数，可能存在路径遍历风险"},
	{regexp.MustCompile(`(?i)(url|link|href|src|url_to)`), ParamRiskHigh, "URL参数，可能存在SSRF风险"},
	{regexp.MustCompile(`(?i)(format|output|type|content_type)`), ParamRiskMedium, "格式参数，可能存在注入风险"},
}

func AnalyzeParamDetails(endpoint *APIEndpoint) *ParamAnalysis {
	pa := &ParamAnalysis{
		Endpoint: endpoint,
	}

	for _, param := range endpoint.Parameters {
		ap := AnalysedParam{
			Name:     param.Name,
			Required: param.Required,
		}

		if param.Type != "" {
			ap.TypeHint = param.Type
		} else {
			ap.TypeHint = guessParamType(param.Name)
		}

		ap.Category = guessParamCategory(param.Name)

		var risks []string
		for _, ip := range injectionPatterns {
			if ip.paramPattern.MatchString(param.Name) {
				risks = append(risks, ip.description)
			}
		}
		ap.InjectionRisks = risks

		ap.RiskScore = calculateParamRisk(ap)
		pa.RiskScore += ap.RiskScore
		pa.Parameters = append(pa.Parameters, ap)
	}

	if len(pa.Parameters) > 0 {
		pa.RiskLevel = classifyParamRisk(pa.RiskScore / float64(len(pa.Parameters)))
	} else {
		pa.RiskLevel = ParamRiskNone
	}
	return pa
}

func guessParamType(name string) string {
	for _, hint := range paramTypeHints {
		if hint.pattern.MatchString(name) {
			return hint.hint
		}
	}
	return "string"
}

func guessParamCategory(name string) string {
	lower := strings.ToLower(name)

	switch {
	case strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "key"):
		return "credential"
	case strings.Contains(lower, "email") || strings.Contains(lower, "phone") || strings.Contains(lower, "address") || strings.Contains(lower, "name"):
		return "pii"
	case strings.Contains(lower, "amount") || strings.Contains(lower, "price") || strings.Contains(lower, "card") || strings.Contains(lower, "account"):
		return "financial"
	case strings.Contains(lower, "id"):
		return "identifier"
	case strings.Contains(lower, "file") || strings.Contains(lower, "image") || strings.Contains(lower, "photo"):
		return "file"
	case strings.Contains(lower, "url") || strings.Contains(lower, "link") || strings.Contains(lower, "redirect"):
		return "url"
	case strings.Contains(lower, "query") || strings.Contains(lower, "search") || strings.Contains(lower, "filter"):
		return "query"
	case strings.Contains(lower, "sort") || strings.Contains(lower, "order") || strings.Contains(lower, "limit") || strings.Contains(lower, "offset") || strings.Contains(lower, "page"):
		return "pagination"
	default:
		return "general"
	}
}

func calculateParamRisk(ap AnalysedParam) float64 {
	risk := 0.0

	switch ap.Category {
	case "credential":
		risk += 25
	case "pii":
		risk += 15
	case "financial":
		risk += 20
	case "file":
		risk += 18
	case "url":
		risk += 15
	}

	if ap.Required {
		risk += 5
	}

	for range ap.InjectionRisks {
		risk += 10
	}

	return risk
}

func classifyParamRisk(avg float64) ParameterRisk {
	switch {
	case avg >= 50:
		return ParamRiskCritical
	case avg >= 35:
		return ParamRiskHigh
	case avg >= 20:
		return ParamRiskMedium
	case avg >= 10:
		return ParamRiskLow
	default:
		return ParamRiskNone
	}
}

func DetectSensitiveParams(endpoints []*APIEndpoint) []SensitiveParam {
	var result []SensitiveParam

	seen := make(map[string]bool)
	for _, ep := range endpoints {
		for _, param := range ep.Parameters {
			cat := guessParamCategory(param.Name)
			if cat == "general" {
				continue
			}

			key := param.Name + "@" + cat
			if seen[key] {
				continue
			}
			seen[key] = true

			risk := ParamRiskLow
			switch cat {
			case "credential":
				risk = ParamRiskCritical
			case "financial":
				risk = ParamRiskCritical
			case "pii":
				risk = ParamRiskHigh
			case "file":
				risk = ParamRiskHigh
			case "url":
				risk = ParamRiskMedium
			}
			result = append(result, SensitiveParam{
				Param:       param.Name,
				Risk:        risk,
				Category:    cat,
				Description: "敏感参数: " + cat,
			})
		}
	}
	return result
}

func CompareAPIVersions(old []*APIEndpoint, new []*APIEndpoint) *APICompareResult {
	oldMap := make(map[string]*APIEndpoint)
	newMap := make(map[string]*APIEndpoint)

	for _, ep := range old {
		key := ep.Path + "|" + endpointMethod(ep)
		oldMap[key] = ep
	}
	for _, ep := range new {
		key := ep.Path + "|" + endpointMethod(ep)
		newMap[key] = ep
	}

	result := &APICompareResult{}

	for key, ep := range oldMap {
		if _, ok := newMap[key]; !ok {
			result.Removed = append(result.Removed, ep)
		}
	}

	for key, ep := range newMap {
		if oldEp, ok := oldMap[key]; ok {
			if len(ep.Parameters) != len(oldEp.Parameters) {
				result.Modified = append(result.Modified, ep)
			} else {
				result.Same = append(result.Same, ep)
			}
		} else {
			result.Added = append(result.Added, ep)
		}
	}

	return result
}

func AnalyzeMultiVersionAPIs(baseEndpoints []*APIEndpoint, compareWith []*APIEndpoint) *APICompareResult {
	baseMap := make(map[string]*APIEndpoint)
	for _, ep := range baseEndpoints {
		baseMap[ep.Path] = ep
	}

	compareMap := make(map[string]*APIEndpoint)
	for _, ep := range compareWith {
		compareMap[ep.Path] = ep
	}

	result := &APICompareResult{}

	for path, ep := range compareMap {
		if _, ok := baseMap[path]; !ok {
			result.Added = append(result.Added, ep)
		}
	}

	for path, ep := range baseMap {
		if _, ok := compareMap[path]; !ok {
			result.Removed = append(result.Removed, ep)
		}
	}

	return result
}

func ParamAnalysisSummary(pa *ParamAnalysis) string {
	if pa == nil || len(pa.Parameters) == 0 {
		return "无参数分析数据"
	}

	result := "参数分析摘要:\n"
	result += "  参数总数: " + itoa(len(pa.Parameters)) + "\n"
	result += "  风险等级: " + string(pa.RiskLevel) + "\n"

	required := 0
	hasInjection := 0
	for _, p := range pa.Parameters {
		if p.Required {
			required++
		}
		if len(p.InjectionRisks) > 0 {
			hasInjection++
		}
	}
	result += "  必填参数: " + itoa(required) + "\n"
	result += "  注入风险参数: " + itoa(hasInjection)

	return result
}