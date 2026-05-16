package httpclient

import (
	"net/url"
	"time"
)

type RequestBuilder struct {
	req     *Request
	session *Session
}

func NewBuilder(method, url string) *RequestBuilder {
	return &RequestBuilder{
		req: NewRequest(method, url),
	}
}

func R() *RequestBuilder {
	return NewBuilder("GET", "")
}

func (b *RequestBuilder) Get(url string) *RequestBuilder {
	b.req.Method = "GET"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Post(url string) *RequestBuilder {
	b.req.Method = "POST"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Put(url string) *RequestBuilder {
	b.req.Method = "PUT"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Delete(url string) *RequestBuilder {
	b.req.Method = "DELETE"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Head(url string) *RequestBuilder {
	b.req.Method = "HEAD"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Options(url string) *RequestBuilder {
	b.req.Method = "OPTIONS"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Patch(url string) *RequestBuilder {
	b.req.Method = "PATCH"
	b.req.URL = url
	return b
}

func (b *RequestBuilder) Param(key, value string) *RequestBuilder {
	b.req.Params[key] = value
	return b
}

func (b *RequestBuilder) Params(params map[string]string) *RequestBuilder {
	for k, v := range params {
		b.req.Params[k] = v
	}
	return b
}

func (b *RequestBuilder) Query(query string) *RequestBuilder {
	q, _ := url.ParseQuery(query)
	for k, vs := range q {
		for _, v := range vs {
			b.req.Params[k] = v
		}
	}
	return b
}

func (b *RequestBuilder) Header(key, value string) *RequestBuilder {
	b.req.Headers.Set(key, value)
	return b
}

func (b *RequestBuilder) Headers(headers map[string]string) *RequestBuilder {
	for k, v := range headers {
		b.req.Headers.Set(k, v)
	}
	return b
}

func (b *RequestBuilder) Cookie(key, value string) *RequestBuilder {
	b.req.Cookies[key] = value
	return b
}

func (b *RequestBuilder) Cookies(cookies map[string]string) *RequestBuilder {
	for k, v := range cookies {
		b.req.Cookies[k] = v
	}
	return b
}

func (b *RequestBuilder) Form(data map[string]string) *RequestBuilder {
	b.req.Data = data
	return b
}

func (b *RequestBuilder) JSON(data interface{}) *RequestBuilder {
	b.req.JSON = data
	return b
}

func (b *RequestBuilder) Body(body []byte) *RequestBuilder {
	b.req.Data = body
	return b
}

func (b *RequestBuilder) BodyString(body string) *RequestBuilder {
	b.req.Data = body
	return b
}

func (b *RequestBuilder) Auth(user, pass string) *RequestBuilder {
	b.req.Auth = &Auth{
		Type:     AuthBasic,
		Username: user,
		Password: pass,
	}
	return b
}

func (b *RequestBuilder) Bearer(token string) *RequestBuilder {
	b.req.Auth = &Auth{
		Type:  AuthBearer,
		Token: token,
	}
	return b
}

func (b *RequestBuilder) Token(scheme, token string) *RequestBuilder {
	b.req.Auth = &Auth{
		Type:   AuthToken,
		Scheme: scheme,
		Token:  token,
	}
	return b
}

func (b *RequestBuilder) Timeout(d time.Duration) *RequestBuilder {
	b.req.Timeout = d
	return b
}

func (b *RequestBuilder) Proxy(proxyURL string) *RequestBuilder {
	if b.req.Proxies == nil {
		b.req.Proxies = make(map[string]string)
	}
	b.req.Proxies["http"] = proxyURL
	b.req.Proxies["https"] = proxyURL
	return b
}

func (b *RequestBuilder) NoVerify() *RequestBuilder {
	b.req.Verify = false
	return b
}

func (b *RequestBuilder) NoRedirect() *RequestBuilder {
	b.req.AllowRedirects = false
	return b
}

func (b *RequestBuilder) MaxRedirects(n int) *RequestBuilder {
	b.req.MaxRedirects = n
	return b
}

func (b *RequestBuilder) Stream() *RequestBuilder {
	b.req.Stream = true
	return b
}

func (b *RequestBuilder) File(fieldName, filePath string) *RequestBuilder {
	if b.req.Files == nil {
		b.req.Files = make(map[string]interface{})
	}
	b.req.Files[fieldName] = &fileEntry{FieldName: fieldName, FilePath: filePath}
	return b
}

func (b *RequestBuilder) Files(fields map[string]string) *RequestBuilder {
	if b.req.Files == nil {
		b.req.Files = make(map[string]interface{})
	}
	for fieldName, filePath := range fields {
		b.req.Files[fieldName] = &fileEntry{FieldName: fieldName, FilePath: filePath}
	}
	return b
}

func (b *RequestBuilder) Profile(p *BrowserProfile) *RequestBuilder {
	p.Apply(b.req)
	return b
}

func (b *RequestBuilder) UA(ua string) *RequestBuilder {
	b.req.Headers.Set("User-Agent", ua)
	return b
}

func (b *RequestBuilder) Referer(referer string) *RequestBuilder {
	b.req.Headers.Set("Referer", referer)
	return b
}

func (b *RequestBuilder) ContentType(ct string) *RequestBuilder {
	b.req.Headers.Set("Content-Type", ct)
	return b
}

func (b *RequestBuilder) With(cb func(r *Request)) *RequestBuilder {
	cb(b.req)
	return b
}

func (b *RequestBuilder) Build() *Request {
	return b.req
}

func (b *RequestBuilder) Do() (*Response, error) {
	if b.session != nil {
		return b.session.Do(b.req)
	}
	return defaultSession.Do(b.req)
}

func (b *RequestBuilder) WithSession(s *Session) *RequestBuilder {
	b.session = s
	return b
}