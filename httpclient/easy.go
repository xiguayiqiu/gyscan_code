package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/html/charset"
)

// SimpleResponse 提供简单的响应访问接口，与 Python requests 体验一致
type SimpleResponse struct {
	statusCode int               // HTTP 状态码
	headers    map[string]string // 响应头
	cookies    map[string]string // Cookie
	text       string            // 响应文本（已解码）
	content    []byte            // 原始字节
	url        string            // 最终 URL
	reason     string            // 状态原因
	ok         bool              // 是否 2xx 成功
	encoding   string            // 检测到的编码
}

// StatusCode 返回 HTTP 状态码
func (r *SimpleResponse) StatusCode() int {
	return r.statusCode
}

// Text 返回响应文本
func (r *SimpleResponse) Text() string {
	return r.text
}

// Bytes 返回原始响应字节
func (r *SimpleResponse) Bytes() []byte {
	return r.content
}

// ContentType 返回 Content-Type 头
func (r *SimpleResponse) ContentType() string {
	if ct, ok := r.headers["Content-Type"]; ok {
		return ct
	}
	return ""
}

// IsBinary 判断内容是否为二进制
func (r *SimpleResponse) IsBinary() bool {
	ct := r.ContentType()
	binaryTypes := []string{
		"video/", "audio/", "image/",
		"application/octet-stream",
		"application/pdf", "application(zip",
		"application/x-rar", "application/x-7z",
		"application/x-tar", "application/gzip",
	}
	ctLower := strings.ToLower(ct)
	for _, t := range binaryTypes {
		if strings.Contains(ctLower, t) {
			return true
		}
	}

	if len(r.content) > 0 {
		for _, b := range r.content[:min(512, len(r.content))] {
			if b == 0 {
				return true
			}
		}
	}
	return false
}

// TextWithEncoding 使用指定编码解析响应文本
func (r *SimpleResponse) TextWithEncoding(enc string) string {
	text, _ := decodeBodyString(r.content, enc)
	return text
}

// Ok 返回是否成功（2xx）
func (r *SimpleResponse) Ok() bool {
	return r.ok
}

// Url 返回最终请求 URL
func (r *SimpleResponse) Url() string {
	return r.url
}

// Reason 返回状态原因
func (r *SimpleResponse) Reason() string {
	return r.reason
}

// Headers 返回响应头
func (r *SimpleResponse) Headers() map[string]string {
	return r.headers
}

// Cookies 返回 Cookie
func (r *SimpleResponse) Cookies() map[string]string {
	return r.cookies
}

// Content 返回原始响应字节（别名）
func (r *SimpleResponse) Content() []byte {
	return r.content
}

// Encoding 返回检测到的编码
func (r *SimpleResponse) Encoding() string {
	return r.encoding
}

// Format 格式化 JSON 或 HTML 输出
func (r *SimpleResponse) Format() string {
	return Format(r.text)
}

// Save 保存响应内容到文件
func (r *SimpleResponse) Save(filename string) error {
	return SaveData(filename, r.content)
}

// SaveData 保存字节数据到文件
func SaveData(filename string, data []byte) error {
	if data == nil || len(data) == 0 {
		return fmt.Errorf("save: no data to save")
	}
	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(filename, data, 0644)
}

// SaveText 保存文本到文件
func SaveText(filename string, text string) error {
	return SaveData(filename, []byte(text))
}

// Download 下载 URL 内容到文件
func Download(url string, filename string) error {
	resp, err := FetchResponse(url)
	if err != nil {
		return err
	}
	return resp.Save(filename)
}

// Save 下载 URL 内容到文件（别名）
func Save(url string, filename string) error {
	url = addProtocol(url)
	resp, err := defaultSimple.GetResp(url)
	if err != nil {
		return err
	}
	return resp.Save(filename)
}

// Format 格式化 JSON 或 HTML 文本
func Format(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}

	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		var obj interface{}
		if err := json.Unmarshal([]byte(text), &obj); err == nil {
			out, err := json.MarshalIndent(obj, "", "  ")
			if err == nil {
				return string(out)
			}
		}
	}

	text = formatHTML(text)

	return text
}

// formatHTML 简化格式化 HTML
func formatHTML(html string) string {
	html = strings.TrimSpace(html)
	if !strings.Contains(html, "<") {
		return html
	}

	if len(html) > 50000 {
		return html
	}

	var result strings.Builder
	lines := strings.Split(html, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if i > 0 {
			result.WriteString("\n")
		}

		if strings.HasPrefix(line, "</") || strings.HasPrefix(line, "<!") {
			result.WriteString(line)
		} else if strings.HasPrefix(line, "<") {
			if !strings.HasSuffix(line, "/>") && !strings.HasSuffix(line, ">") {
				result.WriteString(line)
			} else {
				result.WriteString(line)
			}
		} else {
			result.WriteString(line)
		}
	}

	output := result.String()
	output = strings.ReplaceAll(output, ">\n<", ">\n<")
	output = strings.ReplaceAll(output, "\n\n", "\n")

	return output
}

// extractTagName 提取标签名
func extractTagName(tag string) string {
	tag = strings.TrimPrefix(tag, "<")
	tag = strings.TrimPrefix(tag, "/")
	parts := strings.Split(tag, " ")
	if len(parts) > 0 {
		tag = parts[0]
	}
	tag = strings.TrimSuffix(tag, ">")
	return strings.ToLower(tag)
}

// isSelfClosingTag 判断是否自闭合标签
func isSelfClosingTag(name string) bool {
	selfClosing := map[string]bool{
		"br": true, "hr": true, "img": true, "input": true,
		"meta": true, "link": true, "area": true, "base": true,
		"col": true, "embed": true, "param": true, "source": true,
		"track": true, "wbr": true,
	}
	return selfClosing[name]
}

// decodeBodyString 使用指定编码解码字节
func decodeBodyString(body []byte, enc string) (string, error) {
	reader, err := charset.NewReaderLabel(enc, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// detectEncodingString 从响应头和内容检测编码
func detectEncodingString(respHeaders map[string]string, body []byte) string {
	for k, v := range respHeaders {
		if strings.ToLower(k) == "content-type" {
			if idx := strings.Index(strings.ToLower(v), "charset="); idx != -1 {
				enc := strings.TrimSpace(v[idx+7:])
				enc = strings.Trim(enc, "\"'`= \t")
				return enc
			}
		}
	}
	_, name, _ := charset.DetermineEncoding(body, "")
	if name != "" {
		return name
	}
	return "utf-8"
}

// defaultSimple 默认的 Simple 客户端
var defaultSimple = newSimpleClient()

// newSimpleClient 创建新的 Simple 客户端
func newSimpleClient() *Simple {
	return &Simple{
		timeout: 30 * time.Second,
		ua:      Random(),
		headers: make(map[string]string),
		cookies: make(map[string]string),
	}
}

// Simple 提供简单链式 API，与 Python requests 体验一致
type Simple struct {
	timeout  time.Duration     // 超时
	proxy    string            // 代理
	ua       string            // User-Agent
	encoding string            // 编码
	headers  map[string]string // 请求头
	cookies  map[string]string // Cookie
}

// Timeout 设置超时
func (s *Simple) Timeout(d time.Duration) *Simple {
	s.timeout = d
	return s
}

// Proxy 设置代理
func (s *Simple) Proxy(p string) *Simple {
	s.proxy = p
	return s
}

// UA 设置 User-Agent
func (s *Simple) UA(u string) *Simple {
	s.ua = u
	return s
}

// Encoding 设置编码
func (s *Simple) Encoding(enc string) *Simple {
	s.encoding = enc
	return s
}

// Header 设置请求头
func (s *Simple) Header(key, value string) *Simple {
	s.headers[key] = value
	return s
}

// Cookie 设置 Cookie
func (s *Simple) Cookie(key, value string) *Simple {
	s.cookies[key] = value
	return s
}

// Cookies 设置多个 Cookie
func (s *Simple) Cookies(m map[string]string) *Simple {
	for k, v := range m {
		s.cookies[k] = v
	}
	return s
}

// Get 发送 GET 请求
func (s *Simple) Get(url string) *SimpleResponse {
	resp, _ := s.GetResp(url)
	return resp
}

// Post 发送 POST 请求
func (s *Simple) Post(url string, data interface{}) *SimpleResponse {
	resp, _ := s.PostResp(url, data)
	return resp
}

// Put 发送 PUT 请求
func (s *Simple) Put(url string, data interface{}) *SimpleResponse {
	resp, _ := s.PutResp(url, data)
	return resp
}

// Delete 发送 DELETE 请求
func (s *Simple) Delete(url string) *SimpleResponse {
	resp, _ := s.DeleteResp(url)
	return resp
}

// Head 发送 HEAD 请求
func (s *Simple) Head(url string) *SimpleResponse {
	resp, _ := s.HeadResp(url)
	return resp
}

// GetResp 发送 GET 请求并返回响应对象和错误
func (s *Simple) GetResp(url string) (*SimpleResponse, error) {
	return s.do("GET", url, nil)
}

// PostResp 发送 POST 请求并返回响应对象和错误
func (s *Simple) PostResp(url string, data interface{}) (*SimpleResponse, error) {
	return s.do("POST", url, data)
}

// PutResp 发送 PUT 请求并返回响应对象和错误
func (s *Simple) PutResp(url string, data interface{}) (*SimpleResponse, error) {
	return s.do("PUT", url, data)
}

// DeleteResp 发送 DELETE 请求并返回响应对象和错误
func (s *Simple) DeleteResp(url string) (*SimpleResponse, error) {
	return s.do("DELETE", url, nil)
}

// HeadResp 发送 HEAD 请求并返回响应对象和错误
func (s *Simple) HeadResp(url string) (*SimpleResponse, error) {
	return s.do("HEAD", url, nil)
}

// do 执行 HTTP 请求
func (s *Simple) do(method, url string, data interface{}) (*SimpleResponse, error) {
	url = addProtocol(url)

	session := NewSession()
	session.DefaultTimeout = s.timeout
	session.DefaultHeaders["User-Agent"] = s.ua
	for k, v := range s.headers {
		session.DefaultHeaders[k] = v
	}
	for k, v := range s.cookies {
		session.DefaultCookies[k] = v
	}

	req := NewRequest(method, url)

	if data != nil {
		switch v := data.(type) {
		case string:
			req.Data = v
		case map[string]interface{}:
			req.JSON = v
		default:
			req.Data = v
		}
	}

	resp, err := session.Do(req)
	if err != nil {
		return &SimpleResponse{}, err
	}

	headers := make(map[string]string)
	for k, v := range resp.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	cookies := make(map[string]string)
	for _, c := range resp.Cookies {
		cookies[c.Name] = c.Value
	}

	enc := s.encoding
	if enc == "" {
		enc = resp.Encoding
		if enc == "" {
			enc = detectEncodingString(headers, resp.Content)
		}
	}
	text := resp.Text

	return &SimpleResponse{
		statusCode: resp.StatusCode,
		headers:    headers,
		cookies:    cookies,
		text:       text,
		content:    resp.Content,
		url:        resp.URL,
		reason:     resp.Reason,
		ok:         resp.Ok,
		encoding:   enc,
	}, nil
}

// Fetch 获取 URL 内容，自动识别二进制
func Fetch(url string) []byte {
	url = addProtocol(url)
	resp, _ := defaultSimple.GetResp(url)
	if resp.IsBinary() {
		return resp.Bytes()
	}
	return []byte(resp.Text())
}

// FetchText 获取 URL 内容，返回文本
func FetchText(url string) string {
	url = addProtocol(url)
	resp, _ := defaultSimple.GetResp(url)
	return resp.Text()
}

// addProtocol 为 URL 缺少协议时添加 https://
func addProtocol(url string) string {
	if url == "" {
		return "https://"
	}
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}
	return url
}

// FetchResponse 获取响应对象
func FetchResponse(url string) (*SimpleResponse, error) {
	return defaultSimple.GetResp(url)
}

// SimpleClient 创建一个新的 Simple 客户端
func SimpleClient() *Simple {
	return newSimpleClient()
}
