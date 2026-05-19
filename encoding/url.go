package encoding

import (
	"net/url"
)

func URLEncode(s string) string {
	return url.QueryEscape(s)
}

func URLDecode(s string) (string, error) {
	return url.QueryUnescape(s)
}

func URLComponentEncode(s string) string {
	return url.PathEscape(s)
}

func URLComponentDecode(s string) (string, error) {
	return url.PathUnescape(s)
}