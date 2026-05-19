package encoding

import (
	"strings"
)

func jotherNum(n int) string {
	if n == 0 {
		return "+[]"
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = "+!![]"
	}
	return strings.Join(parts, "+")
}

var jotherCharExpr = map[byte]string{}

func init() {
	falseStr := "(![]+[])"
	trueStr := "(!![]+[])"
	undefStr := "([][[]]+[])"
	objStr := "([]+{})"
	nanStr := "(+[![]]+[])"
	infStr := "((+!![]/+[])+[])"

	sources := map[string]string{
		"false":     falseStr,
		"true":      trueStr,
		"undefined": undefStr,
		"object":    objStr,
		"NaN":       nanStr,
		"Infinity":  infStr,
	}

	for src, expr := range sources {
		for i := 0; i < len(src); i++ {
			ch := src[i]
			idx := jotherNum(i)
			jotherCharExpr[ch] = "(" + expr + ")[" + idx + "]"
		}
	}

	consParts := []struct{ ch byte }{
		{'c'}, {'o'}, {'n'}, {'s'}, {'t'}, {'r'}, {'u'}, {'c'}, {'t'}, {'o'}, {'r'},
	}
	var consBuilder strings.Builder
	for _, p := range consParts {
		consBuilder.WriteString(jotherCharExpr[p.ch] + "+")
	}
	consStr := consBuilder.String()
	consStr = consStr[:len(consStr)-1]

	funcStr := "([])[" + consStr + "]+[]"
	funcName := "function Array() { [native code] }"
	for i := 0; i < len(funcName); i++ {
		ch := funcName[i]
		if _, exists := jotherCharExpr[ch]; !exists {
			jotherCharExpr[ch] = "(" + funcStr + ")[" + jotherNum(i) + "]"
		}
	}

	retStr := "return"
	for i := 0; i < len(retStr); i++ {
		ch := retStr[i]
		if _, exists := jotherCharExpr[ch]; !exists {
			jotherCharExpr[ch] = "\"\\" + string(ch) + "\""
		}
	}
}

func JotherEncode(s string) string {
	var builder strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if expr, ok := jotherCharExpr[ch]; ok {
			if i > 0 {
				builder.WriteString("+")
			}
			builder.WriteString(expr)
		}
	}
	return builder.String()
}

func JotherDecode(s string) string {
	return s
}