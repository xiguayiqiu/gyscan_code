package httpclient

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html/charset"
)

// Response HTTP 响应对象
type Response struct {
	StatusCode int
	Headers    http.Header
	Cookies    []*http.Cookie
	Text       string
	Content    []byte
	URL        string
	Elapsed    time.Duration
	Reason     string
	Encoding   string
	Ok         bool
	IsRedirect bool
	Raw        *http.Response
}

// buildResponse 从 http.Response 构建 Response
func buildResponse(rawResp *http.Response, elapsed time.Duration) (*Response, error) {
	body, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response body: %w", err)
	}
	rawResp.Body.Close()

	body, err = decompressBody(body, rawResp.Header.Get("Content-Encoding"))
	if err != nil {
		return nil, fmt.Errorf("httpclient: decompress body: %w", err)
	}

	enc := detectEncoding(rawResp.Header.Get("Content-Type"), body)
	text, err := decodeBody(body, enc)
	if err != nil {
		text = string(body)
	}

	statusOK := rawResp.StatusCode >= 200 && rawResp.StatusCode < 300
	isRedirect := rawResp.StatusCode >= 300 && rawResp.StatusCode < 400 && rawResp.StatusCode != 304

	reason := strings.TrimPrefix(rawResp.Status, fmt.Sprintf("%d ", rawResp.StatusCode))

	respURL := rawResp.Request.URL.String()
	if respURL == "" {
		respURL = ""
	}

	return &Response{
		StatusCode: rawResp.StatusCode,
		Headers:    rawResp.Header,
		Cookies:    rawResp.Cookies(),
		Text:       text,
		Content:    body,
		URL:        respURL,
		Elapsed:    elapsed,
		Reason:     reason,
		Encoding:   enc,
		Ok:         statusOK,
		IsRedirect: isRedirect,
		Raw:        rawResp,
	}, nil
}

// String 返回响应文本
func (r *Response) String() string {
	return r.Text
}

// Json 解析 JSON 响应为 map[string]interface{}
func (r *Response) Json() (map[string]interface{}, error) {
	var result map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(r.Content))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("httpclient: json decode: %w", err)
	}
	return result, nil
}

// JsonArray 解析 JSON 响应为 []interface{}
func (r *Response) JsonArray() ([]interface{}, error) {
	var result []interface{}
	decoder := json.NewDecoder(bytes.NewReader(r.Content))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("httpclient: json decode: %w", err)
	}
	return result, nil
}

// decompressBody 解压 gzip 等压缩内容
func decompressBody(body []byte, contentEncoding string) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))

	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, nil
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "deflate", "br":
		return body, nil
	default:
		return body, nil
	}
}

// detectEncoding 检测响应编码
func detectEncoding(contentType string, body []byte) string {
	contentType = strings.ToLower(contentType)
	if contentType != "" {
		if _, name, ok := strings.Cut(contentType, "charset="); ok {
			name = strings.TrimSpace(name)
			name = strings.Trim(name, "\"'`= \t")
			if name != "" {
				return name
			}
		}
	}

	_, name, _ := charset.DetermineEncoding(body, contentType)
	if name != "" && name != "windows-1252" {
		return name
	}

	if bytes.Contains(body, []byte("<meta")) || bytes.Contains(body, []byte("<html")) {
		if bytes.Contains(body, []byte("charset=utf-8")) ||
		   bytes.Contains(body, []byte("charset=UTF-8")) ||
		   bytes.Contains(body, []byte("content=\"text/html")) {
			return "utf-8"
		}
		if bytes.Contains(body, []byte("charset=gb")) {
			return "gbk"
		}
	}

	return "utf-8"
}

// decodeBody 使用指定编码解码响应体
func decodeBody(body []byte, enc string) (string, error) {
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
