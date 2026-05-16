package passwd

import (
	"crypto/rand"
	"math/big"
)

const (
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits    = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
	ambiguous = "il1Lo0O"
)

func Generate(length int) string {
	return GenerateWith(length, true, true, true, false)
}

func GenerateStrong(length int) string {
	return GenerateWith(length, true, true, true, true)
}

func GenerateN(length, count int) []string {
	if count <= 0 {
		return nil
	}
	result := make([]string, count)
	for i := 0; i < count; i++ {
		result[i] = Generate(length)
	}
	return result
}

func GenerateWith(length int, upper, lower, digit, special bool) string {
	if length <= 0 {
		length = 16
	}

	charset := ""
	if upper {
		charset += uppercase
	}
	if lower {
		charset += lowercase
	}
	if digit {
		charset += digits
	}
	if special {
		charset += specialChars
	}
	if charset == "" {
		charset = lowercase + digits
	}

	chars := []rune(charset)
	maxIdx := big.NewInt(int64(len(chars)))

	result := make([]rune, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, maxIdx)
		if err != nil {
			result[i] = 'a'
			continue
		}
		result[i] = chars[idx.Int64()]
	}

	return string(result)
}
