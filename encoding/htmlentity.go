package encoding

import (
	"html"
	"strings"
)

var htmlEntityMap = map[string]string{
	"&": "&amp;", "<": "&lt;", ">": "&gt;",
	"\"": "&quot;", "'": "&#39;",
}

var htmlEntityReverse = map[string]string{}

func init() {
	for k, v := range htmlEntityMap {
		htmlEntityReverse[v] = k
	}
}

func HTMLEntityEncode(s string) string {
	return html.EscapeString(s)
}

func HTMLEntityDecode(s string) string {
	return html.UnescapeString(s)
}

func HTMLEntityEncodeAll(s string) string {
	var builder strings.Builder
	for _, r := range s {
		if entity, ok := htmlEntityMap[string(r)]; ok {
			builder.WriteString(entity)
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func HTMLEntityDecodeAll(s string) string {
	result := html.UnescapeString(s)
	return result
}