package passwd

import (
	"fmt"
	"strings"
)

type Profile struct {
	FirstName string
	LastName  string
	Nickname  string
	BirthDate string
	Partner   string
	Pet       string
	Company   string
	Keywords  []string
}

func CUPP(profile *Profile) []string {
	if profile == nil {
		return nil
	}

	seen := make(map[string]bool)
	var result []string

	add := func(ss ...string) {
		for _, s := range ss {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			result = append(result, s)
		}
	}

	bases := collectBases(profile)
	years := extractYears(profile.BirthDate)
	commonYears := []string{"0", "1", "12", "123", "1234", "2000", "2020", "2021", "2022", "2023", "2024", "2025", "2026"}
	suffixes := []string{"123", "123!", "1234", "!", "@", "#", "2025", "2026"}

	for _, base := range bases {
		if base == "" {
			continue
		}
		add(base)
		add(strings.ToLower(base))
		add(strings.ToUpper(base))
		add(Capitalize(base))
		add(Reverse(base))

		for _, suf := range suffixes {
			add(base+suf, suf+base)
		}

		for _, y := range years {
			add(base+y, y+base)
		}

		for _, y := range commonYears {
			add(base+y, y+base)
		}
	}

	for i := 0; i < len(bases); i++ {
		for j := i + 1; j < len(bases); j++ {
			a, b := bases[i], bases[j]
			if a == "" || b == "" {
				continue
			}
			add(a+b, b+a, a+"_"+b, b+"_"+a, Capitalize(a)+b, a+Capitalize(b))

			for _, y := range years {
				add(a+b+y, b+a+y)
			}
		}
	}

	for _, base := range bases {
		if len(base) > 8 || base == "" {
			continue
		}
		leet := LeetSpeak(base)
		if leet != base {
			add(leet)
			for _, suf := range suffixes[:4] {
				add(leet + suf)
			}
		}
	}

	for _, y := range years {
		add(y)
	}

	return result
}

func collectBases(profile *Profile) []string {
	var bases []string
	for _, s := range []string{profile.FirstName, profile.LastName, profile.Nickname, profile.Partner, profile.Pet, profile.Company} {
		if s != "" {
			bases = append(bases, s)
		}
	}
	bases = append(bases, profile.Keywords...)

	if profile.BirthDate != "" {
		parts := strings.Split(profile.BirthDate, "-")
		if len(parts) == 3 {
			bases = append(bases, parts[1], parts[2])
		}
	}

	return bases
}

func extractYears(birthDate string) []string {
	var years []string
	if birthDate == "" {
		return years
	}
	parts := strings.Split(birthDate, "-")
	if len(parts) != 3 {
		return years
	}
	y := parts[0]
	if len(y) == 4 {
		years = append(years, y, y[2:])
	}
	years = append(years, parts[1]+parts[2], parts[2]+parts[1])
	years = append(years, y+parts[1]+parts[2], y[2:]+parts[1]+parts[2])
	return years
}

func LeetSpeak(s string) string {
	replacer := strings.NewReplacer(
		"a", "4", "A", "4",
		"e", "3", "E", "3",
		"i", "1", "I", "1",
		"o", "0", "O", "0",
		"s", "5", "S", "5",
		"t", "7", "T", "7",
		"b", "8", "B", "8",
	)
	return replacer.Replace(s)
}

func Capitalize(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	return strings.ToUpper(string(runes[0])) + string(runes[1:])
}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func CUPPInfo(profile *Profile) string {
	pwds := CUPP(profile)
	return fmt.Sprintf("CUPP: %d passwords generated from profile", len(pwds))
}
