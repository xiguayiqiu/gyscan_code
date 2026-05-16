package httpclient

import (
	"net/url"
	"time"
)

// RequestBuilder 链式请求构建器
type RequestBuilder struct {
	req     *Request
	session *Session
}

// NewBuilder 创建新的请求构建器
func NewBuilder(method, url string) *RequestBuilder {
	return &RequestBuilder{
		req: NewRequest(method, url),
	}
}

// R 创建默认 GET 请求构建器（快捷方式）
func R() *RequestBuilder {
	return NewBuilder("GET", "")
}

// Get 设置 GET 请求
func (b *RequestBuilder) Get(url string) *RequestBuilder {
	b.req.Method = "GET"
	b.req.URL = url
	return b
}

// Post 设置 POST 请求
func (b *RequestBuilder) Post(url string) *RequestBuilder {
	b.req.Method = "POST"
	b.req.URL = url
	return b
}

// Put 设置 PUT 请求
func (b *RequestBuilder) Put(url string) *RequestBuilder {
	b.req.Method = "PUT"
	b.req.URL = url
	return b
}

// Delete 设置 DELETE 请求
func (b *RequestBuilder) Delete(url string) *RequestBuilder {
	b.req.Method = "DELETE"
	b.req.URL = url
	return b
}

// Head 设置 HEAD 请求
func (b *RequestBuilder) Head(url string) *RequestBuilder {
	b.req.Method = "HEAD"
	b.req.URL = url
	return b
}

// Options 设置 OPTIONS 请求
func (b *RequestBuilder) Options(url string) *RequestBuilder {
	b.req.Method = "OPTIONS"
	b.req.URL = url
	return b
}

// Patch 设置 PATCH 请求
func (b *RequestBuilder) Patch(url string) *RequestBuilder {
	b.req.Method = "PATCH"
	b.req.URL = url
	return b
}

// Param 设置单个查询参数
func (b *RequestBuilder) Param(key, value string) *RequestBuilder {
	b.req.Params[key] = value
	return b
}

// Params 设置多个查询参数
func (b *RequestBuilder) Params(params map[string]string) *RequestBuilder {
	for k, v := range params {
		b.req.Params[k] = v
	}
	return b
}

// Query 从查询字符串设置参数
func (b *RequestBuilder) Query(query string) *RequestBuilder {
	q, _ := url.ParseQuery(query)
	for k, vs := range q {
		for _, v := range vs {
			b.req.Params[k] = v
		}
	}
	return b
}

// Header 设置单个请求头
func (b *RequestBuilder) Header(key, value string) *RequestBuilder {
	b.req.Headers.Set(key, value)
	return b
}

// Headers 设置多个请求头
func (b *RequestBuilder) Headers(headers map[string]string) *RequestBuilder {
	for k, v := range headers {
		b.req.Headers.Set(k, v)
	}
	return b
}

// Cookie 设置单个 Cookie
func (b *RequestBuilder) Cookie(key, value string) *RequestBuilder {
	b.req.Cookies[key] = value
	return b
}

// Cookies 设置多个 Cookie
func (b *RequestBuilder) Cookies(cookies map[string]string) *RequestBuilder {
	for k, v := range cookies {
		b.req.Cookies[k] = v
	}
	return b
}

// Form 设置表单数据
func (b *RequestBuilder) Form(data map[string]string) *RequestBuilder {
	b.req.Data = data
	return b
}

// JSON 设置 JSON 数据
func (b *RequestBuilder) JSON(data interface{}) *RequestBuilder {
	b.req.JSON = data
	return b
}

// Body 设置原始请求体
func (b *RequestBuilder) Body(body []byte) *RequestBuilder {
	b.req.Data = body
	return b
}

// BodyString 设置字符串请求体
func (b *RequestBuilder) BodyString(body string) *RequestBuilder {
	b.req.Data = body
	return b
}

// Auth 设置 Basic Auth
func (b *RequestBuilder) Auth(user, pass string) *RequestBuilder {
	b.req.Auth = &Auth{
		Type:     AuthBasic,
		Username: user,
		Password: pass,
	}
	return b
}

// Bearer 设置 Bearer Token
func (b *RequestBuilder) Bearer(token string) *RequestBuilder {
	b.req.Auth = &Auth{
		Type:  AuthBearer,
		Token: token,
	}
	return b
}

// Token 设置自定义 Token 认证
func (b *RequestBuilder) Token(scheme, token string) *RequestBuilder {
	b.req.Auth = &Auth{
		Type:   AuthToken,
		Scheme: scheme,
		Token:  token,
	}
	return b
}

// Timeout 设置超时
func (b *RequestBuilder) Timeout(d time.Duration) *RequestBuilder {
	b.req.Timeout = d
	return b
}

// Proxy 设置代理
func (b *RequestBuilder) Proxy(proxyURL string) *RequestBuilder {
	if b.req.Proxies == nil {
		b.req.Proxies = make(map[string]string)
	}
	b.req.Proxies["http"] = proxyURL
	b.req.Proxies["https"] = proxyURL
	return b
}

// NoVerify 跳过 SSL 验证
func (b *RequestBuilder) NoVerify() *RequestBuilder {
	b.req.Verify = false
	return b
}

// NoRedirect 禁用重定向
func (b *RequestBuilder) NoRedirect() *RequestBuilder {
	b.req.AllowRedirects = false
	return b
}

// MaxRedirects 设置最大重定向次数
func (b *RequestBuilder) MaxRedirects(n int) *RequestBuilder {
	b.req.MaxRedirects = n
	return b
}

// Stream 启用流式响应
func (b *RequestBuilder) Stream() *RequestBuilder {
	b.req.Stream = true
	return b
}

// File 设置单个上传文件
func (b *RequestBuilder) File(fieldName, filePath string) *RequestBuilder {
	if b.req.Files == nil {
		b.req.Files = make(map[string]interface{})
	}
	b.req.Files[fieldName] = &fileEntry{FieldName: fieldName, FilePath: filePath}
	return b
}

// Files 设置多个上传文件
func (b *RequestBuilder) Files(fields map[string]string) *RequestBuilder {
	if b.req.Files == nil {
		b.req.Files = make(map[string]interface{})
	}
	for fieldName, filePath := range fields {
		b.req.Files[fieldName] = &fileEntry{FieldName: fieldName, FilePath: filePath}
	}
	return b
}

// Profile 应用浏览器配置
func (b *RequestBuilder) Profile(p *BrowserProfile) *RequestBuilder {
	p.Apply(b.req)
	return b
}

// UA 设置 User-Agent
func (b *RequestBuilder) UA(ua string) *RequestBuilder {
	b.req.Headers.Set("User-Agent", ua)
	return b
}

// Referer 设置 Referer
func (b *RequestBuilder) Referer(referer string) *RequestBuilder {
	b.req.Headers.Set("Referer", referer)
	return b
}

// ContentType 设置 Content-Type
func (b *RequestBuilder) ContentType(ct string) *RequestBuilder {
	b.req.Headers.Set("Content-Type", ct)
	return b
}

// With 自定义修改请求
func (b *RequestBuilder) With(cb func(r *Request)) *RequestBuilder {
	cb(b.req)
	return b
}

// Build 构建请求对象
func (b *RequestBuilder) Build() *Request {
	return b.req
}

// Do 执行请求
func (b *RequestBuilder) Do() (*Response, error) {
	if b.session != nil {
		return b.session.Do(b.req)
	}
	return defaultSession.Do(b.req)
}

// WithSession 关联会话
func (b *RequestBuilder) WithSession(s *Session) *RequestBuilder {
	b.session = s
	return b
}
