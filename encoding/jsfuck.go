package encoding

import (
	"strings"
)

func jsNum(n int) string {
	if n == 0 {
		return "+[]"
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = "+!![]"
	}
	return strings.Join(parts, "+")
}

var jsCharExpr = map[byte]string{}

func init() {
	falseStr := "(![]+[])"
	trueStr := "(!![]+[])"
	undefStr := "([][[]]+[])"
	nanStr := "(+[![]]+[])"
	infStr := "((+!![]/+[])+[])"

	sources := map[string]string{
		"false":     falseStr,
		"true":      trueStr,
		"undefined": undefStr,
		"NaN":       nanStr,
		"Infinity":  infStr,
	}

	for src, expr := range sources {
		for i := 0; i < len(src); i++ {
			ch := src[i]
			idx := jsNum(i)
			jsCharExpr[ch] = "(" + expr + ")[" + idx + "]"
		}
	}

	consParts := []byte("constructor")
	var consBuilder strings.Builder
	for i, c := range consParts {
		if i > 0 {
			consBuilder.WriteString("+")
		}
		consBuilder.WriteString(jsCharExpr[c])
	}
	consStr := consBuilder.String()

	funcStr := "([])[" + consStr + "]+[]"
	funcName := "function Array() { [native code] }"
	for i := 0; i < len(funcName); i++ {
		ch := funcName[i]
		if _, exists := jsCharExpr[ch]; !exists {
			jsCharExpr[ch] = "(" + funcStr + ")[" + jsNum(i) + "]"
		}
	}

	retStr := "return"
	for i := 0; i < len(retStr); i++ {
		ch := retStr[i]
		if _, exists := jsCharExpr[ch]; !exists {
			jsCharExpr[ch] = "\"\\" + string(ch) + "\""
		}
	}
}

func JSFuckEncode(s string) string {
	var builder strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if expr, ok := jsCharExpr[ch]; ok {
			if i > 0 {
				builder.WriteString("+")
			}
			builder.WriteString(expr)
		}
	}
	return builder.String()
}

func JSFuckDecode(s string) string {
	return s
}