package httpclient

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

// defaultSession 默认会话
var defaultSession *Session

func init() {
	defaultSession = NewSession()
}

// Get 使用默认会话发送 GET 请求
func Get(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Get(url, opts...)
}

// Post 使用默认会话发送 POST 请求
func Post(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Post(url, opts...)
}

// Put 使用默认会话发送 PUT 请求
func Put(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Put(url, opts...)
}

// Delete 使用默认会话发送 DELETE 请求
func Delete(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Delete(url, opts...)
}

// Head 使用默认会话发送 HEAD 请求
func Head(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Head(url, opts...)
}

// Options 使用默认会话发送 OPTIONS 请求
func Options(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Options(url, opts...)
}

// Patch 使用默认会话发送 PATCH 请求
func Patch(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Patch(url, opts...)
}

// Client HTTP 客户端封装
type Client struct {
	s *Session
}

// Config 客户端配置
type Config struct {
	Timeout            time.Duration // 超时时间
	FollowRedirects    bool          // 是否跟随重定向
	InsecureSkipVerify bool          // 是否跳过 TLS 验证
	ProxyURL           string        // 代理 URL
}

// New 创建一个新的 Client
func New(config *Config) (*Client, error) {
	s := NewSession()

	if config != nil {
		if config.Timeout > 0 {
			s.DefaultTimeout = config.Timeout
		}
		if !config.FollowRedirects {
			s.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
		if config.InsecureSkipVerify {
			s.DefaultVerify = false
			s.transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
		if config.ProxyURL != "" {
			s.DefaultProxies = map[string]string{
				"http":  config.ProxyURL,
				"https": config.ProxyURL,
			}
		}
	}

	return &Client{s: s}, nil
}

// Get 发送 GET 请求
func (c *Client) Get(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Get(url, opts...)
}

// Post 发送 POST 请求
func (c *Client) Post(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Post(url, opts...)
}

// Put 发送 PUT 请求
func (c *Client) Put(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Put(url, opts...)
}

// Delete 发送 DELETE 请求
func (c *Client) Delete(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Delete(url, opts...)
}

// Head 发送 HEAD 请求
func (c *Client) Head(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Head(url, opts...)
}

// Options 发送 OPTIONS 请求
func (c *Client) Options(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Options(url, opts...)
}

// Patch 发送 PATCH 请求
func (c *Client) Patch(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Patch(url, opts...)
}

// Do 执行自定义请求
func (c *Client) Do(req *Request) (*Response, error) {
	return c.s.Do(req)
}

// Cookies 获取 URL 对应的 Cookie
func (c *Client) Cookies(u *url.URL) []*http.Cookie {
	return c.s.Cookies(u)
}

// SetCookies 设置 URL 对应的 Cookie
func (c *Client) SetCookies(u *url.URL, cookies []*http.Cookie) {
	c.s.SetCookies(u, cookies)
}
