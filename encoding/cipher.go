package encoding

import (
	"fmt"
	"strings"
	"unicode"
)

func CaesarEncode(s string, shift int) string {
	var builder strings.Builder
	for _, r := range s {
		if unicode.IsUpper(r) {
			builder.WriteRune('A' + (r-'A'+rune(shift))%26)
		} else if unicode.IsLower(r) {
			builder.WriteRune('a' + (r-'a'+rune(shift))%26)
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func CaesarDecode(s string, shift int) string {
	return CaesarEncode(s, 26-shift%26)
}

func CaesarBruteForce(s string) []string {
	results := make([]string, 26)
	for i := 0; i < 26; i++ {
		results[i] = fmt.Sprintf("shift %2d: %s", i, CaesarDecode(s, i))
	}
	return results
}

func VigenereEncode(s string, key string) string {
	key = strings.ToUpper(key)
	if len(key) == 0 {
		return s
	}
	var builder strings.Builder
	keyIdx := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			shift := key[keyIdx%len(key)] - 'A'
			builder.WriteRune('A' + (r-'A'+rune(shift))%26)
			keyIdx++
		} else if unicode.IsLower(r) {
			shift := key[keyIdx%len(key)] - 'A'
			builder.WriteRune('a' + (r-'a'+rune(shift))%26)
			keyIdx++
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func VigenereDecode(s string, key string) string {
	key = strings.ToUpper(key)
	if len(key) == 0 {
		return s
	}
	var builder strings.Builder
	keyIdx := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			shift := key[keyIdx%len(key)] - 'A'
			builder.WriteRune('A' + (r-'A'-rune(shift)+26)%26)
			keyIdx++
		} else if unicode.IsLower(r) {
			shift := key[keyIdx%len(key)] - 'A'
			builder.WriteRune('a' + (r-'a'-rune(shift)+26)%26)
			keyIdx++
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func RailFenceEncode(s string, rails int) string {
	if rails <= 1 {
		return s
	}
	chars := []rune(s)
	n := len(chars)
	fence := make([][]rune, rails)
	for i := range fence {
		fence[i] = make([]rune, 0, n/rails+1)
	}
	row, step := 0, 1
	for _, ch := range chars {
		fence[row] = append(fence[row], ch)
		row += step
		if row == 0 || row == rails-1 {
			step = -step
		}
	}
	var builder strings.Builder
	for _, rowChars := range fence {
		builder.WriteString(string(rowChars))
	}
	return builder.String()
}

func RailFenceDecode(s string, rails int) string {
	if rails <= 1 {
		return s
	}
	chars := []rune(s)
	n := len(chars)
	mark := make([]int, n)
	row, step := 0, 1
	for i := 0; i < n; i++ {
		mark[i] = row
		row += step
		if row == 0 || row == rails-1 {
			step = -step
		}
	}
	pos := make([]int, rails)
	rows := make([][]rune, rails)
	for i := 0; i < rails; i++ {
		cnt := 0
		for _, m := range mark {
			if m == i {
				cnt++
			}
		}
		rows[i] = chars[pos[i] : pos[i]+cnt]
		if i+1 < rails {
			pos[i+1] = pos[i] + cnt
		}
	}
	result := make([]rune, n)
	for i := 0; i < n; i++ {
		r := mark[i]
		result[i] = rows[r][0]
		rows[r] = rows[r][1:]
	}
	return string(result)
}

func RailFenceWEncode(s string, rails int) string {
	if rails <= 1 {
		return s
	}
	chars := []rune(s)
	fence := make([][]rune, rails)
	for i := range fence {
		fence[i] = make([]rune, 0)
	}
	row, step := 0, 1
	for _, ch := range chars {
		fence[row] = append(fence[row], ch)
		row += step
		if row == 0 || row == rails-1 {
			step = -step
		}
	}
	var builder strings.Builder
	for _, rowChars := range fence {
		builder.WriteString(string(rowChars))
	}
	return builder.String()
}

func RailFenceWDecode(s string, rails int) string {
	return RailFenceDecode(s, rails)
}