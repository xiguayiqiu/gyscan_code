package api

import (
	"fmt"

	"github.com/xiguayiqiu/gyscan_code/httpclient"
)

type APIProbeResult struct {
	Endpoint     *APIEndpoint
	Method       string
	URL          string
	StatusCode   int
	ResponseSize int
	ContentType  string
	IsAccessible bool
	IsJSON       bool
	ResponseBody string
	Error        string
}

type APISecurityTest struct {
	Endpoint      *APIEndpoint
	TestName      string
	Method        string
	URL           string
	Payload       string
	StatusCode    int
	IsVulnerable  bool
	Description   string
}

func ProbeEndpointWithHTTP(endpoint *APIEndpoint, baseURL string) *APIProbeResult {
	url := baseURL + endpoint.Path
	if endpoint.Host != "" {
		url = "http://" + endpoint.Host + endpoint.Path
	}

	result := &APIProbeResult{
		Endpoint: endpoint,
		URL:      url,
	}

	resp, err := httpclient.Type(url)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.ContentType
	result.ResponseSize = resp.Size
	result.IsAccessible = resp.StatusCode > 0 && resp.StatusCode < 600

	if resp.Kind == httpclient.KindJSON {
		result.IsJSON = true
		result.ResponseBody = resp.Text
	}

	return result
}

func ProbeEndpointsWithHTTP(endpoints []*APIEndpoint, baseURL string) []*APIProbeResult {
	var results []*APIProbeResult
	for _, ep := range endpoints {
		results = append(results, ProbeEndpointWithHTTP(ep, baseURL))
	}
	return results
}

func ProbeEndpointMethods(endpoint *APIEndpoint, baseURL string) []*APIProbeResult {
	var results []*APIProbeResult
	url := baseURL + endpoint.Path
	if endpoint.Host != "" {
		url = "http://" + endpoint.Host + endpoint.Path
	}

	client := &httpclient.Simple{}

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"} {
		result := &APIProbeResult{
			Endpoint: endpoint,
			Method:   method,
			URL:      url,
		}

		var resp *httpclient.SimpleResponse
		var err error
		switch method {
		case "GET", "OPTIONS":
			resp, err = client.GetResp(url)
		case "POST":
			resp, err = client.PostResp(url, nil)
		case "PUT":
			resp, err = client.PutResp(url, nil)
		case "DELETE":
			resp, err = client.DeleteResp(url)
		}

		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		result.StatusCode = resp.StatusCode()
		result.ContentType = resp.ContentType()
		result.ResponseSize = len(resp.Text())
		result.IsAccessible = resp.StatusCode() > 0 && resp.StatusCode() < 600
		result.ResponseBody = resp.Text()
		ct := resp.ContentType()
		if len(ct) >= 16 && ct[:16] == "application/json" {
			result.IsJSON = true
		}
		results = append(results, result)
	}
	return results
}

func TestAuthenticationBypass(endpoint *APIEndpoint, baseURL string) []*APISecurityTest {
	url := baseURL + endpoint.Path
	if endpoint.Host != "" {
		url = "http://" + endpoint.Host + endpoint.Path
	}

	var tests []*APISecurityTest

	test := &APISecurityTest{
		Endpoint: endpoint,
		TestName: "无认证访问测试",
		Method:   "GET",
		URL:      url,
	}

	resp, err := httpclient.Type(url)
	if err != nil {
		test.Description = "请求失败: " + err.Error()
		tests = append(tests, test)
		return tests
	}

	test.StatusCode = resp.StatusCode
	if resp.StatusCode == 200 {
		test.IsVulnerable = true
		test.Description = "无需认证即可访问敏感API"
	} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
		test.Description = "需要认证（正常）"
	} else if resp.StatusCode == 404 {
		test.Description = "端点不存在"
	} else {
		test.Description = fmt.Sprintf("返回状态码: %d", resp.StatusCode)
	}

	tests = append(tests, test)
	return tests
}

func TestAllAuthBypass(endpoints []*SensitiveAPI, baseURL string) []*APISecurityTest {
	var results []*APISecurityTest

	authAPIs := FilterBySensitivity(endpoints, SensHigh)
	for _, sa := range authAPIs {
		tests := TestAuthenticationBypass(sa.Endpoint, baseURL)
		results = append(results, tests...)
	}
	return results
}

func ProbeStatusCounts(results []*APIProbeResult) map[int]int {
	counts := make(map[int]int)
	for _, r := range results {
		counts[r.StatusCode]++
	}
	return counts
}

func ProbeAccessibleCount(results []*APIProbeResult) int {
	count := 0
	for _, r := range results {
		if r.IsAccessible {
			count++
		}
	}
	return count
}

func ProbeJSONCount(results []*APIProbeResult) int {
	count := 0
	for _, r := range results {
		if r.IsJSON {
			count++
		}
	}
	return count
}

func ProbeSummary(results []*APIProbeResult) string {
	if len(results) == 0 {
		return "无探测结果"
	}

	accessible := ProbeAccessibleCount(results)
	jsonCount := ProbeJSONCount(results)
	statusCounts := ProbeStatusCounts(results)

	result := "HTTP探测摘要:\n"
	result += "  总探测端点: " + itoa(len(results)) + " 个\n"
	result += "  可访问: " + itoa(accessible) + " 个\n"
	result += "  JSON响应: " + itoa(jsonCount) + " 个\n"

	for code, count := range statusCounts {
		result += "  HTTP " + itoa(code) + ": " + itoa(count) + " 个\n"
	}

	return result
}