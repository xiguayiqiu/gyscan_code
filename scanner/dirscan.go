package scanner

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xiguayiqiu/gyscan_code/httpclient"
)

type DirScanConfig struct {
	Threads            int
	Timeout            time.Duration
	FollowRedirects    bool
	InsecureSkipVerify bool
	Proxy              string
	UserAgent          string
	Delay              time.Duration
	Retries            int
	StatusCodes        []int
	ExcludeCodes       []int
	Extensions         []string
	Recursive          bool
	MaxDepth           int
	StopOnFirst        bool
}

func DefaultDirScanConfig() *DirScanConfig {
	return &DirScanConfig{
		Threads:            50,
		Timeout:            10 * time.Second,
		FollowRedirects:    false,
		InsecureSkipVerify: false,
		Delay:              0,
		Retries:            0,
		StatusCodes:        []int{200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 500},
		Extensions:         []string{""},
		Recursive:          false,
		MaxDepth:           3,
		StopOnFirst:        false,
	}
}

func (c *DirScanConfig) Validate() {
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

type DirScanResult struct {
	URL      string
	Status   int
	Length   int
	Duration time.Duration
	Type     ResultType
	Error    string
}

func (r *DirScanResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("[%d] %s - ERROR: %s", r.Status, r.URL, r.Error)
	}
	return fmt.Sprintf("[%d] [%s] %s (%d bytes) %v",
		r.Status, r.Type, r.URL, r.Length, r.Duration)
}

type DirScanner struct {
	config   *DirScanConfig
	client   *httpclient.Client
	wordlist *WordList
	store    *ResultStore
	handlers *EventHandlerGroup
	progress *Progress
	mu       sync.Mutex
	stopped  bool
}

func NewDirScanner(target string, wordlist []string, config *DirScanConfig) *DirScanner {
	if config == nil {
		config = DefaultDirScanConfig()
	}
	config.Validate()

	var proxy string
	if config.Proxy != "" {
		proxy = config.Proxy
	}

	clientConfig := &httpclient.Config{
		Timeout:            config.Timeout,
		FollowRedirects:    config.FollowRedirects,
		InsecureSkipVerify: config.InsecureSkipVerify,
		ProxyURL:           proxy,
	}

	var ua string
	if config.UserAgent != "" {
		ua = config.UserAgent
	} else {
		ua = httpclient.Random()
	}

	client := mustNewClientDir(clientConfig, ua)

	target = strings.TrimSuffix(target, "/")

	return &DirScanner{
		config:   config,
		client:   client,
		wordlist: NewWordList(wordlist),
		store:    NewResultStore(),
		handlers: NewEventHandlerGroup(),
	}
}

func mustNewClientDir(config *httpclient.Config, ua string) *httpclient.Client {
	c, err := httpclient.New(config)
	if err != nil {
		panic(err)
	}
	return c
}

func (s *DirScanner) OnResult(handler EventHandler) {
	s.handlers.Add(handler)
}

func (s *DirScanner) OnProgress(handler func(*Progress)) {
	s.handlers.Add(func(r *Result) {
		handler(s.progress)
	})
}

func (s *DirScanner) Scan(target string) []*DirScanResult {
	target = normalizeTarget(target)
	s.progress = NewProgress(s.wordlist.Len())

	results := s.scan(target, 0)

	s.progress.Current = s.progress.Total
	return results
}

func (s *DirScanner) scan(target string, depth int) []*DirScanResult {
	if s.stopped {
		return nil
	}

	if s.config.MaxDepth > 0 && depth > s.config.MaxDepth {
		return nil
	}

	results := make([]*DirScanResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, s.config.Threads)

	for i := 0; i < s.wordlist.Len(); i++ {
		if s.stopped {
			break
		}

		item, ok := s.wordlist.Get(i)
		if !ok {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(path string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if s.config.Delay > 0 {
				time.Sleep(s.config.Delay)
			}

			url := NormalizeURL(target, path)
			result := s.checkURL(url)

			mu.Lock()
			s.progress.Increment()
			if s.shouldInclude(result) {
				results = append(results, result)
				s.storeResult(result)
				s.handlers.Handle(&Result{
					Target:   target,
					Found:    url,
					Type:     result.Type,
					Status:   result.Status,
					Length:   result.Length,
					Duration: result.Duration,
				})
				s.progress.FoundOne()
			}
			mu.Unlock()
		}(item)
	}

	wg.Wait()

	if s.config.Recursive && depth < s.config.MaxDepth {
		recursiveResults := s.scanRecursive(target, depth+1)
		results = append(results, recursiveResults...)
	}

	return results
}

func (s *DirScanner) scanRecursive(target string, depth int) []*DirScanResult {
	if s.stopped || depth > s.config.MaxDepth {
		return nil
	}

	dirs := s.store.Filter(func(r *Result) bool {
		return r.Type == ResultDir && r.Status >= 200 && r.Status < 400
	})

	results := make([]*DirScanResult, 0)
	for _, dir := range dirs {
		subResults := s.scan(dir.Found, depth)
		results = append(results, subResults...)
	}

	return results
}

func (s *DirScanner) checkURL(url string) *DirScanResult {
	result := &DirScanResult{URL: url}

	start := time.Now()
	resp, err := s.client.Get(url,
		httpclient.WithTimeout(s.config.Timeout),
	)
	result.Duration = time.Since(start)

	if err != nil {
		result.Status = 0
		result.Error = err.Error()
		return result
	}

	result.Status = resp.StatusCode
	result.Length = len(resp.Content)

	result.Type = classifyPath(url)

	return result
}

func classifyPath(url string) ResultType {
	url = strings.ToLower(url)

	ext := getExtension(url)
	if ext != "" {
		imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp"}
		for _, e := range imageExts {
			if ext == e {
				return ResultFile
			}
		}

		scriptExts := []string{".js", ".jsx", ".ts", ".tsx", ".php", ".asp", ".aspx", ".jsp", ".jspx"}
		for _, e := range scriptExts {
			if ext == e {
				return ResultFile
			}
		}

		cssExts := []string{".css", ".scss", ".sass", ".less"}
		for _, e := range cssExts {
			if ext == e {
				return ResultFile
			}
		}

		docExts := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".yaml", ".yml", ".xml", ".json"}
		for _, e := range docExts {
			if ext == e {
				return ResultFile
			}
		}

		if !strings.Contains(url, ".") {
			return ResultDir
		}
		return ResultFile
	}

	if isLikelyFile(url) {
		return ResultFile
	}

	return ResultDir
}

func getExtension(url string) string {
	url = strings.TrimSuffix(url, "/")

	for _, ext := range []string{".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".do", ".action"} {
		if strings.HasSuffix(url, ext) {
			return ext
		}
	}

	re := regexp.MustCompile(`\.([a-zA-Z0-9]{1,10})(?:\?|$|#)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return "." + matches[1]
	}

	return ""
}

func isLikelyFile(url string) bool {
	filePatterns := []string{
		`/[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,6}$`,
		`/download/`,
		`/file/`,
		`/upload/`,
		`/static/`,
		`/assets/`,
		`/media/`,
		`/images/`,
		`/css/`,
		`/js/`,
		`/fonts/`,
	}

	for _, pattern := range filePatterns {
		if matched, _ := regexp.MatchString(pattern, url); matched {
			return true
		}
	}

	return false
}

func (s *DirScanner) shouldInclude(result *DirScanResult) bool {
	if result.Error != "" {
		return false
	}

	if len(s.config.ExcludeCodes) > 0 {
		for _, code := range s.config.ExcludeCodes {
			if result.Status == code {
				return false
			}
		}
	}

	if len(s.config.StatusCodes) > 0 {
		for _, code := range s.config.StatusCodes {
			if result.Status == code {
				return true
			}
		}
		return false
	}

	return result.Status >= 200 && result.Status < 600
}

func (s *DirScanner) storeResult(result *DirScanResult) {
	s.store.Add(&Result{
		Found:  result.URL,
		Type:   result.Type,
		Status: result.Status,
		Length: result.Length,
	})
}

func (s *DirScanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
}

func (s *DirScanner) Results() []*DirScanResult {
	all := s.store.All()
	results := make([]*DirScanResult, 0, len(all))
	for _, r := range all {
		results = append(results, &DirScanResult{
			URL:      r.Found,
			Status:   r.Status,
			Length:   r.Length,
			Type:     r.Type,
			Duration: r.Duration,
		})
	}
	return results
}

func (s *DirScanner) Progress() *Progress {
	return s.progress
}

func (s *DirScanner) FoundDirs() []*DirScanResult {
	all := s.Results()
	dirs := make([]*DirScanResult, 0)
	for _, r := range all {
		if r.Type == ResultDir && r.Status >= 200 && r.Status < 400 {
			dirs = append(dirs, r)
		}
	}
	return dirs
}

func (s *DirScanner) FoundFiles() []*DirScanResult {
	all := s.Results()
	files := make([]*DirScanResult, 0)
	for _, r := range all {
		if r.Type == ResultFile {
			files = append(files, r)
		}
	}
	return files
}

func (s *DirScanner) ByStatus(code int) []*DirScanResult {
	all := s.Results()
	var results []*DirScanResult
	for _, r := range all {
		if r.Status == code {
			results = append(results, r)
		}
	}
	return results
}

func (s *DirScanner) ByStatusRange(min, max int) []*DirScanResult {
	all := s.Results()
	results := make([]*DirScanResult, 0)
	for _, r := range all {
		if r.Status >= min && r.Status <= max {
			results = append(results, r)
		}
	}
	return results
}

func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimSuffix(target, "/")

	if !strings.Contains(target, "/") {
		target = target + "/"
	}

	return target
}

type DirScanEnumerator struct {
	Scanner *DirScanner
}

func NewDirScanEnumerator(target string, wordlist []string, config *DirScanConfig) *DirScanEnumerator {
	return &DirScanEnumerator{
		Scanner: NewDirScanner(target, wordlist, config),
	}
}

func (e *DirScanEnumerator) Scan() []*DirScanResult {
	return e.Scanner.Scan("")
}

func (e *DirScanEnumerator) OnResult(handler EventHandler) {
	e.Scanner.OnResult(handler)
}

func ScanDir(target string, wordlist []string, config *DirScanConfig) []*DirScanResult {
	scanner := NewDirScanner(target, wordlist, config)
	return scanner.Scan(target)
}

func QuickDirScan(target string) []*DirScanResult {
	return ScanDir(target, nil, nil)
}

func ScanDirWithChan(target string, wordlist []string, config *DirScanConfig) <-chan *DirScanResult {
	ch := make(chan *DirScanResult, 100)

	go func() {
		defer close(ch)
		results := ScanDir(target, wordlist, config)
		for _, r := range results {
			select {
			case ch <- r:
			default:
			}
		}
	}()

	return ch
}

func ScanDirBatch(targets []string, wordlist []string, config *DirScanConfig) map[string][]*DirScanResult {
	results := make(map[string][]*DirScanResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			scanResults := ScanDir(t, wordlist, config)
			mu.Lock()
			results[t] = scanResults
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return results
}

var defaultDirWordlist = []string{
	"",
	"admin",
	"login",
	"wp-login.php",
	"administrator",
	"admin.php",
	"admin/login.php",
	"panel",
	"cpanel",
	"whm",
	"dashboard",
	"webmail",
	"files",
	"images",
	"img",
	"assets",
	"static",
	"css",
	"js",
	"javascript",
	"media",
	"uploads",
	"upload",
	"download",
	"downloads",
	"docs",
	"documents",
	"api",
	"api/v1",
	"api/v2",
	"api/admin",
	"v1",
	"v2",
	"v3",
	"console",
	"swagger",
	"swagger-ui",
	"swagger-ui.html",
	"api-docs",
	"redoc",
	"graphql",
	"graphiql",
	"altair",
	"playground",
	"phpmyadmin",
	"pma",
	"adminer",
	"mysql",
	"mysql-admin",
	"database",
	"db",
	"pgadmin",
	"postgresql",
	"mongo",
	"mongodb",
	"redis",
	"memcached",
	"elastic",
	"elasticsearch",
	"kibana",
	"grafana",
	"prometheus",
	"adminconsole",
	"management",
	"manage",
	"manager",
	"cp",
	"account",
	"accounts",
	"user",
	"users",
	"user/login",
	"user/register",
	"auth",
	"login/auth",
	"signin",
	"signup",
	"register",
	"auth/login",
	"auth/signin",
	"oauth",
	"oauth2",
	"oauth/authorize",
	"token",
	"access_token",
	"refresh_token",
	"logout",
	"signout",
	"exit",
	"secure",
	"security",
	"security.txt",
	".well-known/security.txt",
	".well-known",
	".well-known/host-meta",
	".well-known/webfinger",
	".well-known/dns-conf",
	".well-known/sshfp",
	".well-known/openid-configuration",
	".well-known/assetlinks.json",
	".well-known/apple-app-site-association",
	"robots.txt",
	"humans.txt",
	"ads.txt",
	"app-ads.txt",
	"sitemap.xml",
	"sitemap.xml.gz",
	"crossdomain.xml",
	"clientaccesspolicy.xml",
	".htaccess",
	".htpasswd",
	".env",
	".env.local",
	".env.production",
	".env.backup",
	"config",
	"config.php",
	"configuration",
	"settings",
	"options",
	"preferences",
	"configuration.php",
	"db.php",
	"database.php",
	"connect.php",
	"conn.php",
	"include.php",
	"includes.php",
	"init.php",
	"bootstrap.php",
	"autoload.php",
	"setup",
	"install",
	"installer",
	"setup.php",
	"install.php",
	"upgrade.php",
	"update.php",
	"migration.php",
	"migrate",
	"backup",
	"backups",
	"backup.php",
	"backups.php",
	"dump.sql",
	"database.sql",
	"db.sql",
	"data.sql",
	"export",
	"import",
	"migrate",
	"migration",
	"phpinfo.php",
	"info.php",
	"server-info",
	"server-status",
	"server-status",
	"status",
	"health",
	"healthz",
	"ping",
	"ready",
	"live",
	"up",
	"down",
	"error",
	"errors",
	"404",
	"404.html",
	"404.php",
	"500.html",
	"500.php",
	"403",
	"403.html",
	"index",
	"index.php",
	"index.html",
	"index.htm",
	"home",
	"home.php",
	"home.html",
	"default",
	"default.aspx",
	"main",
	"main.php",
	"main.html",
	"portal",
	"portals",
	"app",
	"apps",
	"application",
	"cp",
	"control",
	"controlpanel",
	"host",
	"hosting",
	"webhost",
	"site",
	"sites",
	"website",
	"websites",
	"blog",
	"blogs",
	"news",
	"news.php",
	"press",
	"press.php",
	"media",
	"gallery",
	"photo",
	"photos",
	"picture",
	"pictures",
	"video",
	"videos",
	"music",
	"audio",
	"download",
	"forum",
	"forums",
	"community",
	"communities",
	"board",
	"boards",
	"social",
	"profile",
	"profiles",
	"member",
	"members",
	"user",
	"users",
	"customer",
	"customers",
	"client",
	"clients",
	"partner",
	"partners",
	"vendor",
	"vendors",
	"shop",
	"shops",
	"store",
	"stores",
	"cart",
	"checkout",
	"order",
	"orders",
	"product",
	"products",
	"catalog",
	"category",
	"categories",
	"search",
	"find",
	"query",
	"filter",
	"tag",
	"tags",
	"comment",
	"comments",
	"review",
	"reviews",
	"rating",
	"vote",
	"poll",
	"polls",
	"survey",
	"surveys",
	"form",
	"forms",
	"contact",
	"contact.php",
	"contact-us",
	"about",
	"about-us",
	"about.php",
	"company",
	"aboutus",
	"help",
	"help.php",
	"support",
	"support.php",
	"faq",
	"faq.php",
	"docs",
	"documentation",
	"wiki",
	"knowledgebase",
	"kb",
	"manual",
	"guide",
	"guides",
	"tutorial",
	"tutorials",
	"faq",
	"terms",
	"terms.php",
	"privacy",
	"privacy.php",
	"policy",
	"policy.php",
	"legal",
	"cookies",
	"cookies.php",
	"redirect",
	"redirect.php",
	"send",
	"send.php",
	"submit",
	"submit.php",
	"post",
	"post.php",
	"new",
	"new.php",
	"add",
	"add.php",
	"create",
	"create.php",
	"edit",
	"edit.php",
	"update",
	"update.php",
	"delete",
	"delete.php",
	"remove",
	"remove.php",
	"reset",
	"reset.php",
	"change",
	"change.php",
	"modify",
	"modify.php",
	"save",
	"save.php",
	"cancel",
	"cancel.php",
	"abort",
	"abort.php",
	"test",
	"test.php",
	"testing",
	"testing.php",
	"debug",
	"debug.php",
	"demo",
	"demo.php",
	"sandbox",
	"tmp",
	"temp",
	"temporary",
	"cache",
	"logs",
	"log",
	"audit",
	"monitor",
	"monitoring",
	"watch",
	"debug",
}

func DefaultDirWordlist() []string {
	result := make([]string, len(defaultDirWordlist))
	copy(result, defaultDirWordlist)
	return result
}

type DirWordlistGenerator struct {
	commonDirs []string
}

func NewDirWordlistGenerator() *DirWordlistGenerator {
	return &DirWordlistGenerator{
		commonDirs: defaultDirWordlist,
	}
}

func (g *DirWordlistGenerator) Generate() []string {
	return g.commonDirs
}

func (g *DirWordlistGenerator) WithExtensions(exts ...string) []string {
	var result []string
	for _, dir := range g.commonDirs {
		dir = strings.TrimSuffix(dir, "/")
		result = append(result, dir)
		for _, ext := range exts {
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			result = append(result, dir+ext)
		}
	}
	return result
}

func (g *DirWordlistGenerator) WithCommonFiles() []string {
	commonFiles := []string{
		"README.md", "readme.md", "Readme.md",
		"LICENSE.md", "license.md",
		"CHANGELOG.md", "changelog.md",
		"TODO.md", "todo.md",
		"CONTRIBUTING.md", "contributing.md",
		"package.json", "package-lock.json",
		"requirements.txt", "Pipfile", "poetry.lock",
		"Gemfile", "Gemfile.lock",
		"Cargo.toml", "Cargo.lock",
		"go.mod", "go.sum",
		"composer.json", "composer.lock",
		"web.config", ".web.config",
		".DS_Store", "Thumbs.db",
		"*.bak", "*.backup", "*.old", "*.swp", "*.tmp",
		".git/config", ".git/HEAD", ".gitignore",
		".svn/entries",
		".hg/requires",
		"wp-config.php", "wp-config.php.bak",
		"configuration.php~", "configuration.php.bak",
		"config.php~", "config.php.old",
		"settings.py.bak", "settings.pyc",
		".env.bak", ".env.old", ".env.save",
	}

	result := make([]string, len(g.commonDirs), len(g.commonDirs)+len(commonFiles))
	copy(result, g.commonDirs)
	result = append(result, commonFiles...)
	return result
}

func (g *DirWordlistGenerator) GenerateNumbers(start, end, step int) []string {
	var nums []string
	for i := start; i <= end; i += step {
		nums = append(nums, fmt.Sprintf("%d", i))
	}
	return nums
}

func GenerateStatusCodeWordlist() []string {
	var codes []string
	for i := 100; i <= 600; i += 100 {
		codes = append(codes, fmt.Sprintf("%d", i))
	}
	return codes
}

func GenerateNumericWordlist(min, max, digits int) []string {
	var result []string
	format := fmt.Sprintf("%%0%dd", digits)
	for i := min; i <= max; i++ {
		result = append(result, fmt.Sprintf(format, i))
	}
	return result
}

func GenerateAlphanumericWordlist(length int) []string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	n := int(math.Pow(float64(len(chars)), float64(length)))
	if n > 100000 {
		n = 100000
	}

	result := make([]string, 0, n)
	added := make(map[string]bool)

	for len(result) < n {
		s := randomString(chars, length)
		if !added[s] {
			added[s] = true
			result = append(result, s)
		}
	}

	return result
}

func randomString(chars string, length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[len(chars)-1]
	}
	return string(result)
}
