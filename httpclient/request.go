package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxRedirects = 30

// Request HTTP 请求对象
type Request struct {
	Method         string
	URL            string
	Params         map[string]string
	Headers        http.Header
	Cookies        map[string]string
	Data           interface{}
	JSON           interface{}
	Files          map[string]interface{}
	Auth           *Auth
	Timeout        time.Duration
	AllowRedirects bool
	MaxRedirects   int
	Proxies        map[string]string
	Verify         interface{}
	Stream         bool
}

// RequestOption 请求选项函数
type RequestOption func(*Request)

// NewRequest 创建新的请求对象
func NewRequest(method, url string, opts ...RequestOption) *Request {
	req := &Request{
		Method:         method,
		URL:            url,
		Params:         make(map[string]string),
		Headers:        make(http.Header),
		Cookies:        make(map[string]string),
		AllowRedirects: true,
		MaxRedirects:   maxRedirects,
	}

	req.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Headers.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req.Headers.Set("Connection", "keep-alive")
	req.Headers.Set("Upgrade-Insecure-Requests", "1")
	req.Headers.Set("Sec-Fetch-Dest", "document")
	req.Headers.Set("Sec-Fetch-Mode", "navigate")
	req.Headers.Set("Sec-Fetch-Site", "none")
	req.Headers.Set("Sec-Fetch-User", "?1")
	req.Headers.Set("Cache-Control", "max-age=0")
	req.Headers.Set("User-Agent", RandomUserAgent())

	for _, opt := range opts {
		opt(req)
	}

	return req
}

// WithParams 设置 URL 查询参数
func WithParams(params map[string]string) RequestOption {
	return func(r *Request) {
		r.Params = params
	}
}

// WithHeaders 设置多个请求头
func WithHeaders(headers map[string]string) RequestOption {
	return func(r *Request) {
		for k, v := range headers {
			r.Headers.Set(k, v)
		}
	}
}

// WithHeader 设置单个请求头
func WithHeader(key, value string) RequestOption {
	return func(r *Request) {
		r.Headers.Set(key, value)
	}
}

// WithCookies 设置多个 Cookie
func WithCookies(cookies map[string]string) RequestOption {
	return func(r *Request) {
		for k, v := range cookies {
			r.Cookies[k] = v
		}
	}
}

// WithCookie 设置单个 Cookie
func WithCookie(key, value string) RequestOption {
	return func(r *Request) {
		r.Cookies[key] = value
	}
}

// WithData 设置表单数据
func WithData(data map[string]string) RequestOption {
	return func(r *Request) {
		r.Data = data
	}
}

// WithRawBody 设置原始请求体
func WithRawBody(body []byte) RequestOption {
	return func(r *Request) {
		r.Data = body
	}
}

// WithJSON 设置 JSON 请求体
func WithJSON(data interface{}) RequestOption {
	return func(r *Request) {
		r.JSON = data
	}
}

// WithAuth 设置 Basic Auth
func WithAuth(username, password string) RequestOption {
	return func(r *Request) {
		r.Auth = &Auth{
			Type:     AuthBasic,
			Username: username,
			Password: password,
		}
	}
}

// WithDigestAuth 设置 Digest Auth
func WithDigestAuth(username, password string) RequestOption {
	return func(r *Request) {
		r.Auth = &Auth{
			Type:     AuthDigest,
			Username: username,
			Password: password,
		}
	}
}

// WithBearerToken 设置 Bearer Token
func WithBearerToken(token string) RequestOption {
	return func(r *Request) {
		r.Auth = &Auth{
			Type:  AuthBearer,
			Token: token,
		}
	}
}

// WithTokenAuth 设置自定义 Token 认证
func WithTokenAuth(scheme, token string) RequestOption {
	return func(r *Request) {
		r.Auth = &Auth{
			Type:   AuthToken,
			Scheme: scheme,
			Token:  token,
		}
	}
}

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) RequestOption {
	return func(r *Request) {
		r.Timeout = timeout
	}
}

// WithRedirects 设置是否跟随重定向
func WithRedirects(allow bool) RequestOption {
	return func(r *Request) {
		r.AllowRedirects = allow
	}
}

// WithProxy 设置代理
func WithProxy(proxyURL string) RequestOption {
	return func(r *Request) {
		if r.Proxies == nil {
			r.Proxies = make(map[string]string)
		}
		r.Proxies["http"] = proxyURL
		r.Proxies["https"] = proxyURL
	}
}

// WithProxies 设置多个代理
func WithProxies(proxies map[string]string) RequestOption {
	return func(r *Request) {
		r.Proxies = proxies
	}
}

// WithVerify 设置 SSL 验证
func WithVerify(verify interface{}) RequestOption {
	return func(r *Request) {
		r.Verify = verify
	}
}

// WithInsecureSkipVerify 跳过 SSL 验证
func WithInsecureSkipVerify() RequestOption {
	return func(r *Request) {
		r.Verify = false
	}
}

// WithStream 设置流式响应
func WithStream(stream bool) RequestOption {
	return func(r *Request) {
		r.Stream = stream
	}
}

// WithUserAgent 设置 User-Agent
func WithUserAgent(ua string) RequestOption {
	return func(r *Request) {
		r.Headers.Set("User-Agent", ua)
	}
}

// WithReferer 设置 Referer
func WithReferer(referer string) RequestOption {
	return func(r *Request) {
		r.Headers.Set("Referer", referer)
	}
}

// WithContentType 设置 Content-Type
func WithContentType(ct string) RequestOption {
	return func(r *Request) {
		r.Headers.Set("Content-Type", ct)
	}
}

// WithFile 设置单个上传文件
func WithFile(fieldName, filePath string) RequestOption {
	return func(r *Request) {
		if r.Files == nil {
			r.Files = make(map[string]interface{})
		}
		r.Files[fieldName] = &fileEntry{FieldName: fieldName, FilePath: filePath}
	}
}

// WithFiles 设置多个上传文件
func WithFiles(fields map[string]string) RequestOption {
	return func(r *Request) {
		if r.Files == nil {
			r.Files = make(map[string]interface{})
		}
		for fieldName, filePath := range fields {
			r.Files[fieldName] = &fileEntry{FieldName: fieldName, FilePath: filePath}
		}
	}
}

// fileEntry 文件上传项
type fileEntry struct {
	FieldName string
	FilePath  string
}

// buildURL 构建最终请求 URL
func (r *Request) buildURL() (string, error) {
	parsedURL, err := url.Parse(r.URL)
	if err != nil {
		return "", fmt.Errorf("httpclient: invalid url %s: %w", r.URL, err)
	}

	query := parsedURL.Query()
	for k, v := range r.Params {
		query.Set(k, v)
	}
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// buildHTTPBody 构建 HTTP 请求体
func (r *Request) buildHTTPBody() (io.Reader, string, error) {
	if r.Files != nil && len(r.Files) > 0 {
		return r.buildMultipartBody()
	}

	if r.JSON != nil {
		jsonBytes, err := json.Marshal(r.JSON)
		if err != nil {
			return nil, "", fmt.Errorf("httpclient: json marshal: %w", err)
		}
		return bytes.NewReader(jsonBytes), "application/json", nil
	}

	if r.Data != nil {
		switch v := r.Data.(type) {
		case map[string]string:
			form := url.Values{}
			for k, val := range v {
				form.Set(k, val)
			}
			return strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", nil
		case []byte:
			return bytes.NewReader(v), "", nil
		case string:
			return strings.NewReader(v), "", nil
		}
	}

	return nil, "", nil
}

// buildMultipartBody 构建多部分表单请求体
func (r *Request) buildMultipartBody() (io.Reader, string, error) {
	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)

	for _, f := range r.Files {
		fe, ok := f.(*fileEntry)
		if !ok {
			continue
		}

		file, err := os.Open(fe.FilePath)
		if err != nil {
			return nil, "", fmt.Errorf("httpclient: open file %s: %w", fe.FilePath, err)
		}
		defer file.Close()

		part, err := writer.CreateFormFile(fe.FieldName, filepath.Base(fe.FilePath))
		if err != nil {
			return nil, "", err
		}

		io.Copy(part, file)
	}

	if r.Data != nil {
		if dataMap, ok := r.Data.(map[string]string); ok {
			for k, v := range dataMap {
				writer.WriteField(k, v)
			}
		}
	}

	contentType := writer.FormDataContentType()
	writer.Close()

	return buf, contentType, nil
}

// applyCookies 应用 Cookie 到请求
func (r *Request) applyCookies(httpReq *http.Request) {
	for k, v := range r.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}
}

// buildHTTPRequest 构建完整的 http.Request 对象
func (r *Request) buildHTTPRequest(sessionCookies map[string]string) (*http.Request, error) {
	finalURL, err := r.buildURL()
	if err != nil {
		return nil, err
	}

	bodyReader, contentType, err := r.buildHTTPBody()
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(r.Method, finalURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("httpclient: create request: %w", err)
	}

	httpReq.Header = r.Headers.Clone()

	r.applyCookies(httpReq)

	for k, v := range sessionCookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}

	if r.Auth != nil && r.Auth.Type == AuthBasic {
		httpReq.Header.Set("Authorization", "Basic "+basicAuth(r.Auth.Username, r.Auth.Password))
	}
	if r.Auth != nil && r.Auth.Type == AuthBearer {
		httpReq.Header.Set("Authorization", "Bearer "+r.Auth.Token)
	}
	if r.Auth != nil && r.Auth.Type == AuthToken {
		scheme := r.Auth.Scheme
		if scheme == "" {
			scheme = "Bearer"
		}
		httpReq.Header.Set("Authorization", scheme+" "+r.Auth.Token)
	}

	return httpReq, nil
}
