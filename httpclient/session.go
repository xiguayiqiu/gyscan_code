package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

type Session struct {
	hc              *http.Client
	transport       *http.Transport
	DefaultHeaders  map[string]string
	DefaultCookies  map[string]string
	DefaultTimeout  time.Duration
	DefaultProxies  map[string]string
	DefaultVerify   interface{}
}

func NewSession() *Session {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
		MaxIdleConns:    100,
		MaxConnsPerHost: 10,
		IdleConnTimeout: 90 * time.Second,
	}

	s := &Session{
		transport:      transport,
		DefaultHeaders: make(map[string]string),
		DefaultCookies: make(map[string]string),
		DefaultTimeout: 30 * time.Second,
		DefaultVerify:  true,
	}

	s.hc = &http.Client{
		Jar:       jar,
		Transport: transport,
	}

	return s
}

func (s *Session) applyDefaults(r *Request) {
	for k, v := range s.DefaultHeaders {
		if r.Headers.Get(k) == "" {
			r.Headers.Set(k, v)
		}
	}

	if r.Timeout == 0 {
		r.Timeout = s.DefaultTimeout
	}

	if r.Proxies == nil && s.DefaultProxies != nil {
		r.Proxies = s.DefaultProxies
	}

	if r.Verify == nil {
		r.Verify = s.DefaultVerify
	}
}

func (s *Session) buildRequest(method, url string, opts ...RequestOption) *Request {
	r := NewRequest(method, url, opts...)
	s.applyDefaults(r)
	for k, v := range s.DefaultCookies {
		if _, exists := r.Cookies[k]; !exists {
			r.Cookies[k] = v
		}
	}
	return r
}

func (s *Session) configureClient(r *Request) {
	s.transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !s.shouldVerify(r),
	}

	if r.Proxies != nil {
		if proxyURL, ok := r.Proxies["https"]; ok {
			u, err := url.Parse(proxyURL)
			if err == nil {
				s.transport.Proxy = http.ProxyURL(u)
			}
		} else if proxyURL, ok := r.Proxies["http"]; ok {
			u, err := url.Parse(proxyURL)
			if err == nil {
				s.transport.Proxy = http.ProxyURL(u)
			}
		}
	} else {
		s.transport.Proxy = nil
	}

	if r.Timeout > 0 {
		s.hc.Timeout = r.Timeout
	}

	maxRedirects := 5
	if r.MaxRedirects > 0 {
		maxRedirects = r.MaxRedirects
	}
	if !r.AllowRedirects {
		s.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		s.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("httpclient: stopped after %d redirects", maxRedirects)
			}
			return nil
		}
	}
}

func (s *Session) shouldVerify(r *Request) bool {
	if r.Verify == nil {
		return true
	}
	if v, ok := r.Verify.(bool); ok {
		return v
	}
	return true
}

func (s *Session) Do(r *Request) (*Response, error) {
	s.configureClient(r)

	httpReq, err := r.buildHTTPRequest(s.DefaultCookies)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	httpResp, err := s.hc.Do(httpReq)
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("httpclient: %w", err)
	}

	if r.Auth != nil && r.Auth.Type == AuthDigest && httpResp.StatusCode == http.StatusUnauthorized {
		httpResp.Body.Close()
		httpReq, err := r.buildHTTPRequest(s.DefaultCookies)
		if err != nil {
			return nil, err
		}
		applyDigestAuth(httpReq, httpResp, r.Auth.Username, r.Auth.Password)
		start = time.Now()
		httpResp, err = s.hc.Do(httpReq)
		elapsed = time.Since(start)
		if err != nil {
			return nil, fmt.Errorf("httpclient: %w", err)
		}
	}

	return buildResponse(httpResp, elapsed)
}

func (s *Session) Get(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("GET", url, opts...))
}

func (s *Session) Post(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("POST", url, opts...))
}

func (s *Session) Put(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("PUT", url, opts...))
}

func (s *Session) Delete(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("DELETE", url, opts...))
}

func (s *Session) Head(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("HEAD", url, opts...))
}

func (s *Session) Options(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("OPTIONS", url, opts...))
}

func (s *Session) Patch(url string, opts ...RequestOption) (*Response, error) {
	return s.Do(s.buildRequest("PATCH", url, opts...))
}

func (s *Session) Cookies(u *url.URL) []*http.Cookie {
	return s.hc.Jar.Cookies(u)
}

func (s *Session) SetCookies(u *url.URL, cookies []*http.Cookie) {
	s.hc.Jar.SetCookies(u, cookies)
}