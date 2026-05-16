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

type SimpleResponse struct {
	statusCode int
	headers    map[string]string
	cookies    map[string]string
	text       string
	content    []byte
	url        string
	reason     string
	ok         bool
	encoding   string
}

func (r *SimpleResponse) StatusCode() int {
	return r.statusCode
}

func (r *SimpleResponse) Text() string {
	return r.text
}

func (r *SimpleResponse) Bytes() []byte {
	return r.content
}

func (r *SimpleResponse) ContentType() string {
	if ct, ok := r.headers["Content-Type"]; ok {
		return ct
	}
	return ""
}

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

func (r *SimpleResponse) TextWithEncoding(enc string) string {
	text, _ := decodeBodyString(r.content, enc)
	return text
}

func (r *SimpleResponse) Ok() bool {
	return r.ok
}

func (r *SimpleResponse) Url() string {
	return r.url
}

func (r *SimpleResponse) Reason() string {
	return r.reason
}

func (r *SimpleResponse) Headers() map[string]string {
	return r.headers
}

func (r *SimpleResponse) Cookies() map[string]string {
	return r.cookies
}

func (r *SimpleResponse) Content() []byte {
	return r.content
}

func (r *SimpleResponse) Encoding() string {
	return r.encoding
}

func (r *SimpleResponse) Format() string {
	return Format(r.text)
}

func (r *SimpleResponse) Save(filename string) error {
	return SaveData(filename, r.content)
}

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

func SaveText(filename string, text string) error {
	return SaveData(filename, []byte(text))
}

func Download(url string, filename string) error {
	resp, err := FetchResponse(url)
	if err != nil {
		return err
	}
	return resp.Save(filename)
}

func Save(url string, filename string) error {
	url = addProtocol(url)
	resp, err := defaultSimple.GetResp(url)
	if err != nil {
		return err
	}
	return resp.Save(filename)
}

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

func isSelfClosingTag(name string) bool {
	selfClosing := map[string]bool{
		"br": true, "hr": true, "img": true, "input": true,
		"meta": true, "link": true, "area": true, "base": true,
		"col": true, "embed": true, "param": true, "source": true,
		"track": true, "wbr": true,
	}
	return selfClosing[name]
}

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

var defaultSimple = newSimpleClient()

func newSimpleClient() *Simple {
	return &Simple{
		timeout: 30 * time.Second,
		ua:      Random(),
		headers: make(map[string]string),
		cookies: make(map[string]string),
	}
}

type Simple struct {
	timeout  time.Duration
	proxy    string
	ua       string
	encoding string
	headers  map[string]string
	cookies  map[string]string
}

func (s *Simple) Timeout(d time.Duration) *Simple {
	s.timeout = d
	return s
}

func (s *Simple) Proxy(p string) *Simple {
	s.proxy = p
	return s
}

func (s *Simple) UA(u string) *Simple {
	s.ua = u
	return s
}

func (s *Simple) Encoding(enc string) *Simple {
	s.encoding = enc
	return s
}

func (s *Simple) Header(key, value string) *Simple {
	s.headers[key] = value
	return s
}

func (s *Simple) Cookie(key, value string) *Simple {
	s.cookies[key] = value
	return s
}

func (s *Simple) Cookies(m map[string]string) *Simple {
	for k, v := range m {
		s.cookies[k] = v
	}
	return s
}

func (s *Simple) Get(url string) *SimpleResponse {
	resp, _ := s.GetResp(url)
	return resp
}

func (s *Simple) Post(url string, data interface{}) *SimpleResponse {
	resp, _ := s.PostResp(url, data)
	return resp
}

func (s *Simple) Put(url string, data interface{}) *SimpleResponse {
	resp, _ := s.PutResp(url, data)
	return resp
}

func (s *Simple) Delete(url string) *SimpleResponse {
	resp, _ := s.DeleteResp(url)
	return resp
}

func (s *Simple) Head(url string) *SimpleResponse {
	resp, _ := s.HeadResp(url)
	return resp
}

func (s *Simple) GetResp(url string) (*SimpleResponse, error) {
	return s.do("GET", url, nil)
}

func (s *Simple) PostResp(url string, data interface{}) (*SimpleResponse, error) {
	return s.do("POST", url, data)
}

func (s *Simple) PutResp(url string, data interface{}) (*SimpleResponse, error) {
	return s.do("PUT", url, data)
}

func (s *Simple) DeleteResp(url string) (*SimpleResponse, error) {
	return s.do("DELETE", url, nil)
}

func (s *Simple) HeadResp(url string) (*SimpleResponse, error) {
	return s.do("HEAD", url, nil)
}

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

func Fetch(url string) []byte {
	url = addProtocol(url)
	resp, _ := defaultSimple.GetResp(url)
	if resp.IsBinary() {
		return resp.Bytes()
	}
	return []byte(resp.Text())
}

func FetchText(url string) string {
	url = addProtocol(url)
	resp, _ := defaultSimple.GetResp(url)
	return resp.Text()
}

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

func FetchResponse(url string) (*SimpleResponse, error) {
	return defaultSimple.GetResp(url)
}

func SimpleClient() *Simple {
	return newSimpleClient()
}