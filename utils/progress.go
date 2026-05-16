package utils

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type ProgressBar struct {
	total     int
	current   int
	width     int
	prefix    string
	mu        sync.Mutex
	startTime time.Time
	style     string
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		width:     50,
		prefix:    "",
		startTime: time.Now(),
		style:     "block",
	}
}

func (p *ProgressBar) SetPrefix(prefix string) *ProgressBar {
	p.prefix = prefix
	return p
}

func (p *ProgressBar) SetWidth(width int) *ProgressBar {
	p.width = width
	return p
}

func (p *ProgressBar) SetStyle(style string) *ProgressBar {
	p.style = style
	return p
}

func (p *ProgressBar) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	p.render()
}

func (p *ProgressBar) Set(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = current
	p.render()
}

func (p *ProgressBar) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = p.total
	p.render()
	fmt.Println()
}

func (p *ProgressBar) render() {
	if p.total == 0 {
		return
	}

	percent := float64(p.current) / float64(p.total)
	filled := int(float64(p.width) * percent)

	var bar string
	switch p.style {
	case "block":
		empty := p.width - filled
		bar = strings.Repeat("█", filled) + strings.Repeat("░", empty)
	case "arrow":
		empty := p.width - filled - 1
		if empty < 0 {
			empty = 0
		}
		bar = strings.Repeat("=", filled) + ">" + strings.Repeat(" ", empty)
	case "dot":
		empty := p.width - filled
		bar = strings.Repeat("●", filled) + strings.Repeat("○", empty)
	case "line":
		empty := p.width - filled
		bar = strings.Repeat("━", filled) + strings.Repeat("─", empty)
	case "slash":
		empty := p.width - filled
		bar = strings.Repeat("/", filled) + strings.Repeat(".", empty)
	case "pipe":
		empty := p.width - filled
		bar = strings.Repeat("█", filled) + strings.Repeat("▒", empty)
	case "star":
		empty := p.width - filled
		bar = strings.Repeat("★", filled) + strings.Repeat("☆", empty)
	case "hash":
		empty := p.width - filled
		bar = strings.Repeat("#", filled) + strings.Repeat("-", empty)
	case "braille":
		bar = brailleBar(filled, p.width)
	case "box":
		bar = boxBar(filled, p.width)
	case "diamond":
		empty := p.width - filled
		bar = strings.Repeat("◆", filled) + strings.Repeat("◇", empty)
	case "heart":
		empty := p.width - filled
		bar = strings.Repeat("♥", filled) + strings.Repeat("♡", empty)
	case "smile":
		empty := p.width - filled
		bar = strings.Repeat("█", filled) + strings.Repeat(" ", empty)
		if filled > p.width/2 {
			bar += "😊"
		} else {
			bar += "😢"
		}
	case "percent":
		bar = fmt.Sprintf("%3.0f%%", percent*100)
	case "reverse":
		empty := p.width - filled
		bar = strings.Repeat("░", empty) + strings.Repeat("█", filled)
	case "cyber":
		empty := p.width - filled
		bar = strings.Repeat("█", filled) + strings.Repeat("░", empty)
		bar = "[" + bar + "]"
		bar += fmt.Sprintf(" %3.0f%%", percent)
		if filled > p.width/2 {
			bar += " ▓▒░"
		} else {
			bar += " ░▒▓"
		}
	default:
		empty := p.width - filled
		bar = strings.Repeat("█", filled) + strings.Repeat("░", empty)
	}

	elapsed := time.Since(p.startTime)
	speed := float64(p.current) / elapsed.Seconds()

	fmt.Printf("\r%s [%s] %.1f%% [%d/%d] %.1f/s", p.prefix, bar, percent*100, p.current, p.total, speed)
}

func brailleBar(filled, width int) string {
	var result strings.Builder
	for i := 0; i < width; i++ {
		if i < filled {
			result.WriteString("⣿")
		} else {
			result.WriteString("⠂")
		}
	}
	return result.String()
}

func boxBar(filled, width int) string {
	empty := width - filled
	return strings.Repeat("┣", filled) + strings.Repeat("━", empty) + "┫"
}

func ProgressBar_(total int) {
	pb := NewProgressBar(total)
	for i := 0; i <= total; i++ {
		pb.Set(i)
		time.Sleep(10 * time.Millisecond)
	}
	pb.Finish()
}

func Progress(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressWithText(text string, current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Printf("\r%s [%s] %.1f%% [%d/%d]", text, bar, percent, current, total)
	if current == total {
		fmt.Println()
	}
}

func ProgressArrow(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled - 1
	if empty < 0 {
		empty = 0
	}
	bar := strings.Repeat("=", filled) + ">" + strings.Repeat(" ", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressDot(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("●", filled) + strings.Repeat("○", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressLine(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("━", filled) + strings.Repeat("─", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressSlash(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("/", filled) + strings.Repeat(".", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressStyle(style string, current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))

	var bar string
	empty := width - filled
	switch style {
	case "arrow":
		bar = strings.Repeat("=", filled) + ">" + strings.Repeat(" ", empty)
	case "dot":
		bar = strings.Repeat("●", filled) + strings.Repeat("○", empty)
	case "line":
		bar = strings.Repeat("━", filled) + strings.Repeat("─", empty)
	case "slash":
		bar = strings.Repeat("/", filled) + strings.Repeat(".", empty)
	case "pipe":
		bar = strings.Repeat("█", filled) + strings.Repeat("▒", empty)
	case "star":
		bar = strings.Repeat("★", filled) + strings.Repeat("☆", empty)
	case "hash":
		bar = strings.Repeat("#", filled) + strings.Repeat("-", empty)
	case "sharp":
		bar = strings.Repeat("#", filled) + strings.Repeat("-", empty)
	case "diamond":
		bar = strings.Repeat("◆", filled) + strings.Repeat("◇", empty)
	case "heart":
		bar = strings.Repeat("♥", filled) + strings.Repeat("♡", empty)
	case "reverse":
		bar = strings.Repeat("░", empty) + strings.Repeat("█", filled)
	case "box":
		bar = boxBar(filled, width)
	default:
		bar = strings.Repeat("█", filled) + strings.Repeat("░", empty)
	}

	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressWithSpeed(current, total int, speed float64) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Printf("\r[%s] %.1f%% [%d/%d] %.1f/s", bar, percent, current, total, speed)
	if current == total {
		fmt.Println()
	}
}

func ProgressMini(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	fmt.Printf("\r%.1f%%", percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressSimple() {
	fmt.Print("█▒▒▒▒▒▒▒▒▒▒ 10%")
}

func ProgressStar(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("★", filled) + strings.Repeat("☆", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressHash(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("#", filled) + strings.Repeat("-", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressSharp(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("#", filled) + strings.Repeat("-", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressPipe(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("▒", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressDiamond(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("◆", filled) + strings.Repeat("◇", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressHeart(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("♥", filled) + strings.Repeat("♡", empty)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressReverse(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("░", empty) + strings.Repeat("█", filled)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressBox(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	bar := boxBar(filled, width)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressCyber(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	bar = "[" + bar + "]"
	bar += fmt.Sprintf(" %3.0f%%", percent)
	if filled > width/2 {
		bar += " ▓▒░"
	} else {
		bar += " ░▒▓"
	}
	fmt.Printf("\r%s", bar)
	if current == total {
		fmt.Println()
	}
}

func ProgressBraille(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	bar := brailleBar(filled, width)
	fmt.Printf("\r[%s] %.1f%%", bar, percent)
	if current == total {
		fmt.Println()
	}
}

func ProgressColor(current, total int) {
	if total == 0 {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 50
	filled := int(float64(width) * float64(current) / float64(total))
	empty := width - filled

	var color string
	if percent < 30 {
		color = "\033[91m"
	} else if percent < 70 {
		color = "\033[93m"
	} else {
		color = "\033[92m"
	}
	reset := "\033[0m"

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Printf("\r%s[%s] %.1f%%%s", color, bar, percent, reset)
	if current == total {
		fmt.Println()
	}
}
