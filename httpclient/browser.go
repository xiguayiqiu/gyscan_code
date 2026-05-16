package httpclient

import (
	"math/rand/v2"
	"net/http"
	"strings"
)

// BrowserProfile 浏览器配置文件
type BrowserProfile struct {
	Name            string
	UserAgent       string
	Platform        string
	Accept          string
	AcceptLanguage  string
	AcceptEncoding  string
	CacheControl    string
	SecFetchDest    string
	SecFetchMode    string
	SecFetchSite    string
	SecFetchUser    string
	UpgradeInsecure string
	Connection      string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	Pragma          string
	DNT             string
	TE              string
	ViewportWidth   string
	ExtraHeaders    map[string]string
}

// Headers 生成 HTTP 头
func (p *BrowserProfile) Headers() http.Header {
	h := make(http.Header)

	h.Set("User-Agent", p.UserAgent)
	h.Set("Accept", p.Accept)
	h.Set("Accept-Language", p.AcceptLanguage)
	h.Set("Accept-Encoding", p.AcceptEncoding)
	h.Set("Cache-Control", p.CacheControl)
	h.Set("Sec-Fetch-Dest", p.SecFetchDest)
	h.Set("Sec-Fetch-Mode", p.SecFetchMode)
	h.Set("Sec-Fetch-Site", p.SecFetchSite)
	h.Set("Sec-Fetch-User", p.SecFetchUser)
	h.Set("Upgrade-Insecure-Requests", p.UpgradeInsecure)
	h.Set("Connection", p.Connection)

	if p.SecChUa != "" {
		h.Set("Sec-Ch-Ua", p.SecChUa)
	}
	if p.SecChUaMobile != "" {
		h.Set("Sec-Ch-Ua-Mobile", p.SecChUaMobile)
	}
	if p.SecChUaPlatform != "" {
		h.Set("Sec-Ch-Ua-Platform", p.SecChUaPlatform)
	}
	if p.Pragma != "" {
		h.Set("Pragma", p.Pragma)
	}
	if p.DNT != "" {
		h.Set("DNT", p.DNT)
	}
	if p.TE != "" {
		h.Set("TE", p.TE)
	}

	for k, v := range p.ExtraHeaders {
		h.Set(k, v)
	}

	return h
}

// Apply 将浏览器配置应用到请求
func (p *BrowserProfile) Apply(r *Request) {
	h := p.Headers()
	for k, vs := range h {
		for _, v := range vs {
			r.Headers.Set(k, v)
		}
	}
}

// AsSession 创建一个使用该浏览器配置的会话
func (p *BrowserProfile) AsSession() *Session {
	s := NewSession()
	p.ApplySession(s)
	return s
}

// ApplySession 将浏览器配置应用到会话
func (p *BrowserProfile) ApplySession(s *Session) {
	h := p.Headers()
	for k, vs := range h {
		for _, v := range vs {
			s.DefaultHeaders[k] = v
		}
	}
}

// WithProfile 创建使用指定浏览器配置的请求选项
func WithProfile(p *BrowserProfile) RequestOption {
	return func(r *Request) {
		p.Apply(r)
	}
}

// WithProfileHeaders 创建使用指定浏览器配置和额外头的请求选项
func WithProfileHeaders(p *BrowserProfile, extra map[string]string) RequestOption {
	return func(r *Request) {
		p.Apply(r)
		for k, v := range extra {
			r.Headers.Set(k, v)
		}
	}
}

// ChromeProfile Chrome 浏览器配置
func ChromeProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:            "Chrome",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Platform:        "Windows",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage:  "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
		AcceptEncoding:  "gzip, deflate, br, zstd",
		CacheControl:    "max-age=0",
		SecFetchDest:    "document",
		SecFetchMode:    "navigate",
		SecFetchSite:    "none",
		SecFetchUser:    "?1",
		UpgradeInsecure: "1",
		Connection:      "keep-alive",
		SecChUa:         `"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Pragma:          "no-cache",
	}
}

// FirefoxProfile Firefox 浏览器配置
func FirefoxProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:            "Firefox",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
		Platform:        "Windows",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:  "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		AcceptEncoding:  "gzip, deflate, br",
		CacheControl:    "max-age=0",
		SecFetchDest:    "document",
		SecFetchMode:    "navigate",
		SecFetchSite:    "none",
		SecFetchUser:    "?1",
		UpgradeInsecure: "1",
		Connection:      "keep-alive",
		TE:              "trailers",
		DNT:             "1",
	}
}

// SafariProfile Safari 浏览器配置
func SafariProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:            "Safari",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
		Platform:        "macOS",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage:  "zh-CN,zh-Hans;q=0.9",
		AcceptEncoding:  "gzip, deflate, br",
		CacheControl:    "max-age=0",
		SecFetchDest:    "document",
		SecFetchMode:    "navigate",
		SecFetchSite:    "none",
		SecFetchUser:    "?1",
		UpgradeInsecure: "1",
		Connection:      "keep-alive",
	}
}

// EdgeProfile Edge 浏览器配置
func EdgeProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:            "Edge",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		Platform:        "Windows",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage:  "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
		AcceptEncoding:  "gzip, deflate, br, zstd",
		CacheControl:    "max-age=0",
		SecFetchDest:    "document",
		SecFetchMode:    "navigate",
		SecFetchSite:    "none",
		SecFetchUser:    "?1",
		UpgradeInsecure: "1",
		Connection:      "keep-alive",
		SecChUa:         `"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}
}

// MobileChromeProfile 移动端 Chrome 浏览器配置
func MobileChromeProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:            "MobileChrome",
		UserAgent:       "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
		Platform:        "Android",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage:  "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
		AcceptEncoding:  "gzip, deflate, br",
		CacheControl:    "max-age=0",
		SecFetchDest:    "document",
		SecFetchMode:    "navigate",
		SecFetchSite:    "none",
		SecFetchUser:    "?1",
		UpgradeInsecure: "1",
		Connection:      "keep-alive",
		SecChUa:         `"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?1",
		SecChUaPlatform: `"Android"`,
		ViewportWidth:   "412",
	}
}

// IPhoneProfile iPhone Safari 浏览器配置
func IPhoneProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:            "iPhone",
		UserAgent:       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
		Platform:        "iOS",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage:  "zh-CN,zh-Hans;q=0.9",
		AcceptEncoding:  "gzip, deflate, br",
		CacheControl:    "max-age=0",
		SecFetchDest:    "document",
		SecFetchMode:    "navigate",
		SecFetchSite:    "none",
		SecFetchUser:    "?1",
		UpgradeInsecure: "1",
		Connection:      "keep-alive",
		ViewportWidth:   "390",
	}
}

// profiles 所有可用浏览器配置
var profiles = []*BrowserProfile{
	ChromeProfile(),
	FirefoxProfile(),
	SafariProfile(),
	EdgeProfile(),
	MobileChromeProfile(),
	IPhoneProfile(),
}

// RandomProfile 随机获取一个浏览器配置
func RandomProfile() *BrowserProfile {
	return profiles[rand.IntN(len(profiles))]
}

// ProfileByName 根据名称获取浏览器配置
func ProfileByName(name string) *BrowserProfile {
	lower := strings.ToLower(name)
	for _, p := range profiles {
		if strings.ToLower(p.Name) == lower {
			return p
		}
	}
	return ChromeProfile()
}
