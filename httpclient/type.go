package httpclient

import (
	"encoding/json"
	"strings"
)

// ResourceKind 表示资源类型
type ResourceKind int

const (
	// KindUnknown 未知类型
	KindUnknown ResourceKind = iota
	// KindHTML HTML 文档
	KindHTML
	// KindJSON JSON 数据
	KindJSON
	// KindXML XML 数据
	KindXML
	// KindImage 图片
	KindImage
	// KindAudio 音频
	KindAudio
	// KindVideo 视频
	KindVideo
	// KindPDF PDF 文档
	KindPDF
	// KindText 文本
	KindText
	// KindBinary 二进制
	KindBinary
)

// String 返回资源类型的字符串表示
func (k ResourceKind) String() string {
	switch k {
	case KindHTML:
		return "html"
	case KindJSON:
		return "json"
	case KindXML:
		return "xml"
	case KindImage:
		return "image"
	case KindAudio:
		return "audio"
	case KindVideo:
		return "video"
	case KindPDF:
		return "pdf"
	case KindText:
		return "text"
	case KindBinary:
		return "binary"
	default:
		return "unknown"
	}
}

// TypedResource 表示已分类的资源，包含类型信息和解析后的数据
type TypedResource struct {
	URL         string      // 请求的 URL
	StatusCode  int         // HTTP 状态码
	Kind        ResourceKind // 资源类型
	ContentType string      // Content-Type 头
	Size        int         // 响应大小（字节）
	Text        string      // 原始响应文本
	Parsed      interface{} // JSON 解析后的数据（仅 KindJSON 时有效）
	Raw         []byte      // 原始响应字节
}

// Type 获取资源并自动分类
func Type(url string) (*TypedResource, error) {
	return defaultSimple.TypeResp(url)
}

// Type 获取资源并自动分类
func (s *Simple) Type(url string) *TypedResource {
	resp, _ := s.TypeResp(url)
	return resp
}

// TypeResp 获取资源并自动分类，返回错误
func (s *Simple) TypeResp(url string) (*TypedResource, error) {
	resp, err := s.GetResp(url)
	if err != nil {
		return nil, err
	}

	ct := resp.ContentType()
	raw := resp.Bytes()

	tr := &TypedResource{
		URL:         resp.Url(),
		StatusCode:  resp.StatusCode(),
		Kind:        classifyContentType(ct, raw),
		ContentType: ct,
		Size:        len(raw),
		Text:        resp.Text(),
		Raw:         raw,
	}

	if tr.Kind == KindJSON {
		var parsed interface{}
		if err := json.Unmarshal(raw, &parsed); err == nil {
			tr.Parsed = parsed
		}
	}

	return tr, nil
}

// classifyContentType 根据 Content-Type 和内容体判断资源类型
func classifyContentType(ct string, body []byte) ResourceKind {
	ct = strings.ToLower(strings.TrimSpace(ct))

	switch {
	case ct == "" || ct == "application/octet-stream":
		return detectBinary(body)
	case strings.Contains(ct, "text/html"):
		return KindHTML
	case strings.Contains(ct, "application/json"), strings.Contains(ct, "text/json"):
		return KindJSON
	case strings.Contains(ct, "/xml"):
		return KindXML
	case strings.HasPrefix(ct, "image/"):
		return KindImage
	case strings.HasPrefix(ct, "audio/"):
		return KindAudio
	case strings.HasPrefix(ct, "video/"):
		return KindVideo
	case strings.Contains(ct, "application/pdf"):
		return KindPDF
	case strings.HasPrefix(ct, "text/"):
		return KindText
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		return KindText
	default:
		return detectBinary(body)
	}
}

// detectBinary 通过检查内容是否包含 null 字节来判断是否为二进制
func detectBinary(body []byte) ResourceKind {
	if len(body) == 0 {
		return KindUnknown
	}
	n := len(body)
	if n > 1024 {
		n = 1024
	}
	for _, b := range body[:n] {
		if b == 0 {
			return KindBinary
		}
	}
	return KindText
}
