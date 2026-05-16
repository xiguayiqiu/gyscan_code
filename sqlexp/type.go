package sqlexp

import "strings"

type DBType int

const (
	MySQL      DBType = iota
	PostgreSQL
	MSSQL
	Oracle
	SQLite
	Access
)

func (d DBType) String() string {
	switch d {
	case MySQL:
		return "mysql"
	case PostgreSQL:
		return "postgresql"
	case MSSQL:
		return "mssql"
	case Oracle:
		return "oracle"
	case SQLite:
		return "sqlite"
	case Access:
		return "access"
	default:
		return "unknown"
	}
}

type Method int

const (
	ErrorBased Method = iota
	UnionBased
	BooleanBlind
	TimeBlind
	StackedQuery
	InlineQuery
	OutOfBand
)

func (m Method) String() string {
	switch m {
	case ErrorBased:
		return "error"
	case UnionBased:
		return "union"
	case BooleanBlind:
		return "boolean"
	case TimeBlind:
		return "time"
	case StackedQuery:
		return "stacked"
	case InlineQuery:
		return "inline"
	case OutOfBand:
		return "oob"
	default:
		return "unknown"
	}
}

type BypassType int

const (
	BypassCommentInline BypassType = iota
	BypassCaseVary
	BypassDoubleURL
	BypassHexEncode
	BypassWhitespace
	BypassNullByte
	BypassKeywordSplit
	BypassHTTPParam
)

func (b BypassType) String() string {
	switch b {
	case BypassCommentInline:
		return "comment_inline"
	case BypassCaseVary:
		return "case_vary"
	case BypassDoubleURL:
		return "double_url"
	case BypassHexEncode:
		return "hex_encode"
	case BypassWhitespace:
		return "whitespace"
	case BypassNullByte:
		return "null_byte"
	case BypassKeywordSplit:
		return "keyword_split"
	case BypassHTTPParam:
		return "http_param"
	default:
		return "unknown"
	}
}

type Payload struct {
	Raw         string
	Description string
	DB          DBType
	Method      Method
}

type PayloadSet struct {
	DB     DBType
	Method Method
	Items  []Payload
}

func (ps *PayloadSet) RawList() []string {
	list := make([]string, len(ps.Items))
	for i, p := range ps.Items {
		list[i] = p.Raw
	}
	return list
}

type Config struct {
	DB           DBType
	Method       Method
	Prefix       string
	Suffix       string
	Comment      string
	Encode       func(string) string
	ReplaceSpace string
	Threads      int
}

func DefaultConfig() *Config {
	return &Config{
		DB:           MySQL,
		Method:       UnionBased,
		Prefix:       "'",
		Suffix:       "-- -",
		Comment:      "-- -",
		ReplaceSpace: " ",
		Threads:      10,
	}
}

func (c *Config) Validate() *Config {
	if c.Threads < 1 {
		c.Threads = 1
	}
	if c.Threads > 100 {
		c.Threads = 100
	}
	return c
}

var commentSuffixes = map[DBType]string{
	MySQL:      "-- -",
	PostgreSQL: "-- -",
	MSSQL:      "--",
	Oracle:     "--",
	SQLite:     "--",
	Access:     "--",
}

func CommentFor(db DBType) string {
	if c, ok := commentSuffixes[db]; ok {
		return c
	}
	return "-- -"
}

var strConcats = map[DBType]string{
	MySQL:      "CONCAT(%s)",
	PostgreSQL: "CONCAT(%s)",
	MSSQL:      "%s",
	Oracle:     "CONCAT(%s)",
	SQLite:     "%s",
}

func StrConcatFor(db DBType, parts ...string) string {
	tmpl, ok := strConcats[db]
	if !ok {
		tmpl = "CONCAT(%s)"
	}
	if tmpl == "%s" {
		return strings.Join(parts, "+")
	}
	return formatConcat(tmpl, parts...)
}

func formatConcat(tmpl string, parts ...string) string {
	joined := strings.Join(parts, ",")
	return strings.Replace(tmpl, "%s", joined, 1)
}