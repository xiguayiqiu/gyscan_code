package scanner

import (
	"fmt"
	"net/http"
)

var statusText = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	102: "Processing",
	103: "Early Hints",

	200: "OK",
	201: "Created",
	202: "Accepted",
	203: "Non-Authoritative Information",
	204: "No Content",
	205: "Reset Content",
	206: "Partial Content",
	207: "Multi-Status",
	208: "Already Reported",
	226: "IM Used",

	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	305: "Use Proxy",
	307: "Temporary Redirect",
	308: "Permanent Redirect",

	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	409: "Conflict",
	410: "Gone",
	411: "Length Required",
	412: "Precondition Failed",
	413: "Payload Too Large",
	414: "URI Too Long",
	415: "Unsupported Media Type",
	416: "Range Not Satisfiable",
	417: "Expectation Failed",
	418: "I'm a Teapot",
	421: "Misdirected Request",
	422: "Unprocessable Entity",
	423: "Locked",
	424: "Failed Dependency",
	425: "Too Early",
	426: "Upgrade Required",
	428: "Precondition Required",
	429: "Too Many Requests",
	431: "Request Header Fields Too Large",
	451: "Unavailable For Legal Reasons",

	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
	505: "HTTP Version Not Supported",
	506: "Variant Also Negotiates",
	507: "Insufficient Storage",
	508: "Loop Detected",
	510: "Not Extended",
	511: "Network Authentication Required",
}

func StatusText(code int) string {
	if text, ok := statusText[code]; ok {
		return text
	}
	return http.StatusText(code)
}

func Status(code int) string {
	return fmt.Sprintf("%d %s", code, StatusText(code))
}

func IsSuccess(code int) bool {
	return code >= 200 && code < 300
}

func IsRedirect(code int) bool {
	return code >= 300 && code < 400
}

func IsClientError(code int) bool {
	return code >= 400 && code < 500
}

func IsServerError(code int) bool {
	return code >= 500 && code < 600
}

func IsError(code int) bool {
	return code >= 400
}

func PrintStatus(code int) {
	fmt.Printf("状态: %s\n", Status(code))
}

func ExplainStatus(code int) string {
	switch {
	case IsSuccess(code):
		return "请求成功"
	case IsRedirect(code):
		return "重定向"
	case code == 401:
		return "需要认证"
	case code == 403:
		return "禁止访问"
	case code == 404:
		return "资源不存在"
	case code == 429:
		return "请求过于频繁"
	case code == 500:
		return "服务器内部错误"
	case code == 502:
		return "网关错误"
	case code == 503:
		return "服务不可用"
	case code == 504:
		return "网关超时"
	case IsClientError(code):
		return "客户端错误"
	case IsServerError(code):
		return "服务器错误"
	default:
		return "未知状态"
	}
}
