package httpclient

import (
	"net/http"
	"net/url"
	"strings"
)

type CookieJar struct {
	cookies map[string]map[string]*http.Cookie
}

func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string]map[string]*http.Cookie),
	}
}

func (j *CookieJar) Set(u *url.URL, cookie *http.Cookie) {
	key := cookieKey(u)
	if j.cookies[key] == nil {
		j.cookies[key] = make(map[string]*http.Cookie)
	}
	j.cookies[key][cookie.Name] = cookie
}

func (j *CookieJar) Get(u *url.URL, name string) *http.Cookie {
	key := cookieKey(u)
	if j.cookies[key] == nil {
		return nil
	}
	return j.cookies[key][name]
}

func (j *CookieJar) All(u *url.URL) []*http.Cookie {
	key := cookieKey(u)
	var result []*http.Cookie
	if j.cookies[key] == nil {
		return result
	}
	for _, c := range j.cookies[key] {
		result = append(result, c)
	}
	return result
}

func (j *CookieJar) Remove(u *url.URL, name string) {
	key := cookieKey(u)
	if j.cookies[key] != nil {
		delete(j.cookies[key], name)
	}
}

func (j *CookieJar) Clear() {
	j.cookies = make(map[string]map[string]*http.Cookie)
}

func (j *CookieJar) ExportString(u *url.URL) string {
	key := cookieKey(u)
	var parts []string
	if j.cookies[key] != nil {
		for _, c := range j.cookies[key] {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func (j *CookieJar) ExportHeader(u *url.URL) string {
	parts := j.ExportString(u)
	if parts == "" {
		return ""
	}
	return "Cookie: " + parts
}

func (j *CookieJar) ImportString(u *url.URL, cookieStr string) {
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}
		name := part[:idx]
		value := part[idx+1:]
		j.Set(u, &http.Cookie{Name: name, Value: value})
	}
}

func (j *CookieJar) ImportCookies(u *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		j.Set(u, c)
	}
}

func (j *CookieJar) ToMap(u *url.URL) map[string]string {
	key := cookieKey(u)
	result := make(map[string]string)
	if j.cookies[key] != nil {
		for name, c := range j.cookies[key] {
			result[name] = c.Value
		}
	}
	return result
}

func cookieKey(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}