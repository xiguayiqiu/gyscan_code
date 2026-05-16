package scanner

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Target   string
	Found    string
	Type     ResultType
	Status   int
	Length   int
	Duration time.Duration
	Error    string
}

type ResultType int

const (
	ResultSubdomain ResultType = iota
	ResultDir
	ResultFile
	ResultParam
)

func (r ResultType) String() string {
	switch r {
	case ResultSubdomain:
		return "subdomain"
	case ResultDir:
		return "directory"
	case ResultFile:
		return "file"
	case ResultParam:
		return "parameter"
	default:
		return "unknown"
	}
}

func (r Result) String() string {
	if r.Error != "" {
		return fmt.Sprintf("[%s] %s - ERROR: %s", r.Type, r.Found, r.Error)
	}
	return fmt.Sprintf("[%d] [%s] %s (%s) %d bytes in %v",
		r.Status, r.Type, r.Found, r.Target, r.Length, r.Duration)
}

type ScannerConfig struct {
	Threads     int
	Timeout     time.Duration
	FollowRedirects bool
	InsecureSkipVerify bool
	Proxy       string
	UserAgent   string
	Delay       time.Duration
	Retries     int
	StatusCodes []int
	ExcludeCodes []int
}

func DefaultConfig() *ScannerConfig {
	return &ScannerConfig{
		Threads:          50,
		Timeout:          10 * time.Second,
		FollowRedirects:  false,
		InsecureSkipVerify: false,
		Retries:          0,
		StatusCodes:      []int{200, 201, 204, 301, 302, 303, 307, 308},
	}
}

func (c *ScannerConfig) Validate() {
	if c.Threads <= 0 {
		c.Threads = 50
	}
	if c.Threads > 500 {
		c.Threads = 500
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Delay < 0 {
		c.Delay = 0
	}
}

type EventHandler func(*Result)

type EventHandlerGroup struct {
	handlers []EventHandler
	mu       sync.Mutex
}

func NewEventHandlerGroup() *EventHandlerGroup {
	return &EventHandlerGroup{}
}

func (g *EventHandlerGroup) Add(handler EventHandler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handlers = append(g.handlers, handler)
}

func (g *EventHandlerGroup) Handle(r *Result) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, h := range g.handlers {
		h(r)
	}
}

type Progress struct {
	Total     int
	Current   int
	Found     int
	StartTime time.Time
	mu        sync.Mutex
}

func NewProgress(total int) *Progress {
	return &Progress{
		Total:     total,
		StartTime: time.Now(),
	}
}

func (p *Progress) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Current++
}

func (p *Progress) FoundOne() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Found++
}

func (p *Progress) Speed() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	elapsed := time.Since(p.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(p.Current) / elapsed
}

func (p *Progress) Percent() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Total == 0 {
		return 0
	}
	return float64(p.Current) / float64(p.Total) * 100
}

func (p *Progress) ETA() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Current == 0 {
		return 0
	}
	elapsed := time.Since(p.StartTime)
	remain := float64(p.Total - p.Current)
	speed := float64(p.Current) / elapsed.Seconds()
	if speed == 0 {
		return 0
	}
	return time.Duration(remain/speed) * time.Second
}

func (p *Progress) String() string {
	return fmt.Sprintf("%.1f%% (%d/%d) [found:%d] [speed:%.1f/s] [eta:%s]",
		p.Percent(), p.Current, p.Total, p.Found, p.Speed(), p.ETA())
}

type WordList struct {
	items []string
	mu    sync.RWMutex
}

func NewWordList(items []string) *WordList {
	unique := make(map[string]struct{})
	for _, item := range items {
		if item != "" {
			unique[item] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for item := range unique {
		result = append(result, item)
	}
	sort.Strings(result)
	return &WordList{items: result}
}

func (w *WordList) Len() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.items)
}

func (w *WordList) Get(index int) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if index < 0 || index >= len(w.items) {
		return "", false
	}
	return w.items[index], true
}

func (w *WordList) All() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]string, len(w.items))
	copy(result, w.items)
	return result
}

func (w *WordList) Filter(predicate func(string) bool) *WordList {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var filtered []string
	for _, item := range w.items {
		if predicate(item) {
			filtered = append(filtered, item)
		}
	}
	return &WordList{items: filtered}
}

func (w *WordList) Prefix(prefix string) *WordList {
	return w.Filter(func(item string) bool {
		return strings.HasPrefix(item, prefix)
	})
}

func (w *WordList) Suffix(suffix string) *WordList {
	return w.Filter(func(item string) bool {
		return strings.HasSuffix(item, suffix)
	})
}

func (w *WordList) Contains(substr string) *WordList {
	return w.Filter(func(item string) bool {
		return strings.Contains(item, substr)
	})
}

func (w *WordList) Regex(pattern string) (*WordList, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return w.Filter(func(item string) bool {
		return re.MatchString(item)
	}), nil
}

type ResultStore struct {
	mu      sync.Mutex
	results map[string]*Result
}

func NewResultStore() *ResultStore {
	return &ResultStore{
		results: make(map[string]*Result),
	}
}

func (s *ResultStore) Add(r *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.Found] = r
}

func (s *ResultStore) Get(key string) (*Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[key]
	return r, ok
}

func (s *ResultStore) All() []*Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := make([]*Result, 0, len(s.results))
	for _, r := range s.results {
		results = append(results, r)
	}
	return results
}

func (s *ResultStore) Filter(predicate func(*Result) bool) []*Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	var filtered []*Result
	for _, r := range s.results {
		if predicate(r) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (s *ResultStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}

func (s *ResultStore) ByType(t ResultType) []*Result {
	return s.Filter(func(r *Result) bool {
		return r.Type == t
	})
}

func (s *ResultStore) Success() []*Result {
	return s.Filter(func(r *Result) bool {
		return r.Status >= 200 && r.Status < 400
	})
}

func (s *ResultStore) ByStatus(code int) []*Result {
	return s.Filter(func(r *Result) bool {
		return r.Status == code
	})
}

func CombinePath(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return base
	}
	return base + "/" + path
}

func NormalizeURL(baseURL, path string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	path = strings.TrimPrefix(path, "/")
	return baseURL + "/" + path
}

type ResultChannel struct {
	ch chan *Result
}

func NewResultChannel(buffer int) *ResultChannel {
	if buffer <= 0 {
		buffer = 100
	}
	return &ResultChannel{ch: make(chan *Result, buffer)}
}

func (rc *ResultChannel) Send(r *Result) {
	select {
	case rc.ch <- r:
	default:
	}
}

func (rc *ResultChannel) Recv() <-chan *Result {
	return rc.ch
}

func (rc *ResultChannel) Close() {
	close(rc.ch)
}
