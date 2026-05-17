package binary_stream

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	keyEsc      = 27
	keyBs       = 127
	keyCtrlC    = 3
	keyCtrlD    = 4
	keyCtrlA    = 1
	keyCtrlE    = 5
	keyCtrlK    = 11
	keyCtrlU    = 21
	keyCtrlW    = 23
	keyTab      = 9
	keyEnter    = 13
	keyLineFeed = 10
)

type ReadLine struct {
	History     []string
	HistoryPos  int
	Prompt      string
	OldState    *term.State
	Completions map[string][]string
	width       int
	height      int
}

func NewReadLine(prompt string) (*ReadLine, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("binary_stream: raw mode: %w", err)
	}
	w, h := getTerminalWidthHeight()
	rl := &ReadLine{
		History:     make([]string, 0, 100),
		HistoryPos:  -1,
		Prompt:      prompt,
		OldState:    oldState,
		Completions: make(map[string][]string),
		width:       w,
		height:      h,
	}
	return rl, nil
}

func getTerminalWidthHeight() (width int, height int) {
	if f, err := os.Open("/dev/tty"); err == nil {
		width, height, _ = term.GetSize(int(f.Fd()))
		f.Close()
	}
	if width <= 0 || height <= 0 {
		width, height, _ = term.GetSize(int(os.Stdout.Fd()))
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	return width, height
}

func (rl *ReadLine) Restore() error {
	if rl.OldState != nil {
		return term.Restore(int(os.Stdin.Fd()), rl.OldState)
	}
	return nil
}

func (rl *ReadLine) AddHistory(line string) {
	if len(rl.History) > 0 && rl.History[len(rl.History)-1] == line {
		return
	}
	rl.History = append(rl.History, line)
	rl.HistoryPos = len(rl.History)
}

func (rl *ReadLine) Printf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	s = strings.ReplaceAll(s, "\n", "\r\n")
	os.Stdout.WriteString(s)
}

func (rl *ReadLine) Println(line string) {
	s := strings.ReplaceAll(line, "\n", "\r\n") + "\r\n"
	os.Stdout.WriteString(s)
}

func (rl *ReadLine) ReadLine() (string, error) {
	rl.HistoryPos = len(rl.History)
	var buf strings.Builder
	cursor := 0
	tempSaved := ""
	writePrompt(rl.Prompt)

	for {
		var b [4]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}

		switch {
		case b[0] == keyEsc && n >= 3 && b[1] == '[':
			switch b[2] {
			case 'A':
				rl.handleUp(&buf, &cursor, &tempSaved)
			case 'B':
				rl.handleDown(&buf, &cursor, &tempSaved)
			case 'C':
				rl.handleRight(&buf, &cursor)
			case 'D':
				rl.handleLeft(&buf, &cursor)
			case '3':
				if n >= 4 && b[3] == '~' {
					rl.handleDelete(&buf, &cursor)
				}
			}
		case b[0] == keyCtrlC:
			os.Stdout.WriteString("^C\r\n")
			return "", fmt.Errorf("interrupt")
		case b[0] == keyCtrlD:
			if buf.Len() == 0 {
				os.Stdout.WriteString("\r\n")
				return "", nil
			}
		case b[0] == keyCtrlA:
			rl.handleHome(&buf, &cursor)
		case b[0] == keyCtrlE:
			rl.handleEnd(&buf, &cursor)
		case b[0] == keyCtrlK:
			rl.handleKillToEnd(&buf, &cursor)
		case b[0] == keyCtrlU:
			rl.handleKillToStart(&buf, &cursor)
		case b[0] == keyCtrlW:
			rl.handleBackwardWord(&buf, &cursor)
		case b[0] == keyTab:
			rl.handleTab(&buf, &cursor)
		case b[0] == keyEnter || b[0] == keyLineFeed:
			os.Stdout.WriteString("\r\n")
			line := buf.String()
			if line != "" {
				rl.AddHistory(line)
			}
			return line, nil
		case b[0] == keyBs || b[0] == 8:
			rl.handleBackspace(&buf, &cursor)
		default:
			if b[0] >= 32 && b[0] < 127 {
				rl.handleInsert(&buf, &cursor, b[0])
			}
		}
	}
}

func (rl *ReadLine) handleUp(buf *strings.Builder, cursor *int, saved *string) {
	if len(rl.History) == 0 {
		return
	}
	if rl.HistoryPos == len(rl.History) {
		*saved = buf.String()
	}
	if rl.HistoryPos > 0 {
		rl.HistoryPos--
	}
	rl.replaceLine(buf, cursor, rl.History[rl.HistoryPos])
}

func (rl *ReadLine) handleDown(buf *strings.Builder, cursor *int, saved *string) {
	if rl.HistoryPos < len(rl.History)-1 {
		rl.HistoryPos++
		rl.replaceLine(buf, cursor, rl.History[rl.HistoryPos])
	} else if rl.HistoryPos == len(rl.History)-1 {
		rl.HistoryPos = len(rl.History)
		rl.replaceLine(buf, cursor, *saved)
	}
}

func (rl *ReadLine) replaceLine(buf *strings.Builder, cursor *int, text string) {
	lineLen := buf.Len()
	for i := 0; i < lineLen; i++ {
		os.Stdout.WriteString("\b \b")
	}
	buf.Reset()
	buf.WriteString(text)
	os.Stdout.WriteString(text)
	*cursor = len(text)
}

func (rl *ReadLine) handleLeft(buf *strings.Builder, cursor *int) {
	if *cursor > 0 {
		*cursor--
		os.Stdout.WriteString("\b")
	}
}

func (rl *ReadLine) handleRight(buf *strings.Builder, cursor *int) {
	if *cursor < buf.Len() {
		stdoutWriteByte(buf.String()[*cursor])
		*cursor++
	}
}

func (rl *ReadLine) handleBackspace(buf *strings.Builder, cursor *int) {
	if *cursor == 0 || buf.Len() == 0 {
		return
	}
	line := buf.String()
	*buf = strings.Builder{}
	buf.WriteString(line[:*cursor-1])
	buf.WriteString(line[*cursor:])
	*cursor--
	os.Stdout.WriteString("\b")
	os.Stdout.WriteString(line[*cursor:])
	stdoutWriteByte(' ')
	clearToEnd := len(line) - *cursor
	for i := 0; i < clearToEnd+1; i++ {
		os.Stdout.WriteString("\b")
	}
}

func (rl *ReadLine) handleDelete(buf *strings.Builder, cursor *int) {
	if *cursor >= buf.Len() {
		return
	}
	line := buf.String()
	*buf = strings.Builder{}
	buf.WriteString(line[:*cursor])
	buf.WriteString(line[*cursor+1:])
	os.Stdout.WriteString(line[*cursor+1:])
	stdoutWriteByte(' ')
	for i := *cursor + 1; i < len(line); i++ {
		os.Stdout.WriteString("\b")
	}
}

func (rl *ReadLine) handleHome(buf *strings.Builder, cursor *int) {
	for *cursor > 0 {
		os.Stdout.WriteString("\b")
		*cursor--
	}
}

func (rl *ReadLine) handleEnd(buf *strings.Builder, cursor *int) {
	line := buf.String()
	for *cursor < len(line) {
		stdoutWriteByte(line[*cursor])
		*cursor++
	}
}

func (rl *ReadLine) handleKillToEnd(buf *strings.Builder, cursor *int) {
	line := buf.String()
	killLen := len(line) - *cursor
	for i := 0; i < killLen; i++ {
		stdoutWriteByte(' ')
	}
	for i := 0; i < killLen; i++ {
		os.Stdout.WriteString("\b")
	}
	*buf = strings.Builder{}
	buf.WriteString(line[:*cursor])
}

func (rl *ReadLine) handleKillToStart(buf *strings.Builder, cursor *int) {
	line := buf.String()
	os.Stdout.WriteString("\r")
	writePrompt(rl.Prompt)
	os.Stdout.WriteString(line[*cursor:])
	for i := *cursor; i < len(line); i++ {
		os.Stdout.WriteString("\b")
	}
	*buf = strings.Builder{}
	buf.WriteString(line[*cursor:])
	*cursor = 0
}

func (rl *ReadLine) handleBackwardWord(buf *strings.Builder, cursor *int) {
	line := buf.String()
	start := *cursor
	for start > 0 && line[start-1] == ' ' {
		start--
	}
	for start > 0 && line[start-1] != ' ' {
		start--
	}
	for *cursor > start {
		os.Stdout.WriteString("\b")
		*cursor--
	}
}

func (rl *ReadLine) handleInsert(buf *strings.Builder, cursor *int, ch byte) {
	line := buf.String()
	*buf = strings.Builder{}
	buf.WriteString(line[:*cursor])
	buf.WriteByte(ch)
	buf.WriteString(line[*cursor:])
	*cursor++
	stdoutWriteByte(ch)
	os.Stdout.WriteString(line[*cursor-1:])
	for i := *cursor; i < len(line)+1; i++ {
		os.Stdout.WriteString("\b")
	}
}

func (rl *ReadLine) handleTab(buf *strings.Builder, cursor *int) {
	if rl.Completions == nil {
		return
	}
	line := buf.String()
	parts := strings.Fields(line)
	prefix := ""
	isCmd := true

	if len(parts) == 0 {
		if buf.Len() == 0 {
			prefix = ""
			isCmd = true
		} else {
			prefix = line
			isCmd = !strings.Contains(line, " ")
		}
	} else {
		prefix = parts[len(parts)-1]
		isCmd = !strings.Contains(line, " ")
	}

	var matches []string
	if isCmd {
		for _, cmd := range rl.allCommands() {
			if strings.HasPrefix(cmd, prefix) {
				matches = append(matches, cmd)
			}
		}
	} else {
		if args, ok := rl.Completions[parts[0]]; ok {
			for _, a := range args {
				if strings.HasPrefix(a, prefix) {
					matches = append(matches, a)
				}
			}
		}
	}

	if len(matches) == 0 {
		if prefix == "" {
			matches = rl.allCommands()
		}
		if len(matches) == 0 {
			os.Stdout.WriteString("\a")
			return
		}
	}

	if len(matches) == 1 {
		suffix := matches[0][len(prefix):]
		for i := 0; i < len(suffix); i++ {
			rl.handleInsert(buf, cursor, suffix[i])
		}
		return
	}

	common := commonPrefix(matches)
	if len(common) > len(prefix) {
		suffix := common[len(prefix):]
		for i := 0; i < len(suffix); i++ {
			rl.handleInsert(buf, cursor, suffix[i])
		}
		return
	}

	rl.printCompletions(matches)

	writePrompt(rl.Prompt)
	os.Stdout.WriteString(line)
	*cursor = len(line)
}

func (rl *ReadLine) allCommands() []string {
	seen := make(map[string]bool)
	var cmds []string
	for _, v := range rl.Completions[""] {
		if !seen[v] {
			seen[v] = true
			cmds = append(cmds, v)
		}
	}
	return cmds
}

func (rl *ReadLine) printCompletions(matches []string) {
	os.Stdout.WriteString("\r\n")
	cols := rl.width / 20
	if cols < 1 {
		cols = 1
	}
	colWidth := rl.width / cols
	if colWidth < 8 {
		colWidth = 8
	}

	for i, m := range matches {
		padding := colWidth - len(m)
		if i%cols == cols-1 || i == len(matches)-1 {
			os.Stdout.WriteString(m)
			os.Stdout.WriteString("\r\n")
		} else {
			os.Stdout.WriteString(m)
			for p := 0; p < padding; p++ {
				os.Stdout.WriteString(" ")
			}
		}
	}
}

func commonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	prefix := strs[0]
	for _, s := range strs[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func stdoutWriteByte(b byte) {
	os.Stdout.Write([]byte{b})
}

func writePrompt(prompt string) {
	os.Stdout.WriteString("\r\033[K")
	os.Stdout.WriteString(prompt)
}
