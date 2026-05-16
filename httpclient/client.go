package httpclient

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

var defaultSession *Session

func init() {
	defaultSession = NewSession()
}

func Get(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Get(url, opts...)
}

func Post(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Post(url, opts...)
}

func Put(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Put(url, opts...)
}

func Delete(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Delete(url, opts...)
}

func Head(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Head(url, opts...)
}

func Options(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Options(url, opts...)
}

func Patch(url string, opts ...RequestOption) (*Response, error) {
	return defaultSession.Patch(url, opts...)
}

type Client struct {
	s *Session
}

type Config struct {
	Timeout            time.Duration
	FollowRedirects    bool
	InsecureSkipVerify bool
	ProxyURL           string
}

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

func (c *Client) Get(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Get(url, opts...)
}

func (c *Client) Post(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Post(url, opts...)
}

func (c *Client) Put(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Put(url, opts...)
}

func (c *Client) Delete(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Delete(url, opts...)
}

func (c *Client) Head(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Head(url, opts...)
}

func (c *Client) Options(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Options(url, opts...)
}

func (c *Client) Patch(url string, opts ...RequestOption) (*Response, error) {
	return c.s.Patch(url, opts...)
}

func (c *Client) Do(req *Request) (*Response, error) {
	return c.s.Do(req)
}

func (c *Client) Cookies(u *url.URL) []*http.Cookie {
	return c.s.Cookies(u)
}

func (c *Client) SetCookies(u *url.URL, cookies []*http.Cookie) {
	c.s.SetCookies(u, cookies)
}
