package scanner

import (
	"fmt"
	"strings"
)

func Path(url string) string {
	url = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://"), "/")
	return url
}

func NPath(url string) string {
	return Path(url)
}

func FormatPath(base string, paths []string) []string {
	base = strings.TrimSuffix(base, "/")
	results := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimPrefix(p, "/")
		if p == "" {
			results = append(results, base)
		} else {
			results = append(results, base+"/"+p)
		}
	}
	return results
}

func NPaths(base string, paths []string) []string {
	return FormatPath(base, paths)
}

func PrintPaths(paths []string) {
	for _, p := range paths {
		fmt.Println(p)
	}
}

func PrintPortResults(results []*PortResult) {
	for _, r := range results {
		fmt.Println(r.String())
	}
}

func PrintResults(results []*Result) {
	for _, r := range results {
		fmt.Println(r.String())
	}
}
