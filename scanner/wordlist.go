package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func ReadWordlist(filename string) ([]string, error) {
	ext := strings.ToLower(filepath.Ext(filename))

	switch ext {
	case ".lst", ".txt", ".db", ".dict", ".wordlist":
		return readTextFile(filename)
	default:
		return readTextFile(filename)
	}
}

func readTextFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func Wordlist(filename string) []string {
	lines, _ := ReadWordlist(filename)
	return lines
}

func LoadDict(filename string) []string {
	return Wordlist(filename)
}

func Lines(filename string) []string {
	return Wordlist(filename)
}
