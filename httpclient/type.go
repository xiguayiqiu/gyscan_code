package httpclient

import (
	"encoding/json"
	"strings"
)

type ResourceKind int

const (
	KindUnknown ResourceKind = iota
	KindHTML
	KindJSON
	KindXML
	KindImage
	KindAudio
	KindVideo
	KindPDF
	KindText
	KindBinary
)

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

type TypedResource struct {
	URL         string
	StatusCode  int
	Kind        ResourceKind
	ContentType string
	Size        int
	Text        string
	Parsed      interface{}
	Raw         []byte
}

func Type(url string) (*TypedResource, error) {
	return defaultSimple.TypeResp(url)
}

func (s *Simple) Type(url string) *TypedResource {
	resp, _ := s.TypeResp(url)
	return resp
}

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
