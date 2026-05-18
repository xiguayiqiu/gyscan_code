package binary_stream

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func ShellCode() error {
	bsPkg, err := findBSPackage()
	if err != nil {
		return fmt.Errorf("binary_stream: shellcode: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "hexsh_*")
	if err != nil {
		return fmt.Errorf("binary_stream: shellcode: create tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	modPath := filepath.Join(tmpDir, "go.mod")
	modContent := fmt.Sprintf(`module hexsh

go 1.26

require %s v0.0.0

replace %s => %s
`, bsPkg, bsPkg, findBSModuleRoot())

	if err := os.WriteFile(modPath, []byte(modContent), 0644); err != nil {
		return fmt.Errorf("binary_stream: shellcode: write go.mod: %w", err)
	}

	mainPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(buildMainGo(bsPkg, tmpDir)), 0644); err != nil {
		return fmt.Errorf("binary_stream: shellcode: write main.go: %w", err)
	}

	rcPath := filepath.Join(tmpDir, "bashrc")
	rcContent := fmt.Sprintf(`if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

alias hex='go run "%s/main.go"'

hex_help() {
    cat <<'EOF'
hex shell - 二进制编辑工具

命令:
  hex open <path>       打开文件
  hex save              保存到当前文件
  hex saveas <path>     另存为
  hex read <off> <n>    读取 n 字节（hex显示）
  hex str <off> <n>     读取 n 字节（字符串显示）
  hex write <off> <hex> 覆盖写入（定长）
  hex insert <off> <hex> 插入数据
  hex delete <off> <n>   删除 n 字节
  hex replace <s> <e> <hex> 替换范围数据
  hex hexdump [n]       十六进制转储
  hex find <hex>        搜索字节
  hex pos [off]         设置/显示位置
  hex seek <off> <w>    移动位置（0=头,1=当前,2=尾）
  hex len               显示长度
  hex info              显示文件信息
  hex truncate <len>    截断
  hex undo              撤销（重新加载）
  hex list              列出当前目录文件
  hex help              显示帮助

示例:
  hex open test.bin
  hex hexdump
  hex read 0 16
  hex insert 8 DEADBEEF
  hex save

EOF
}

hex_list() {
    echo "用法: ls 或 cd <目录>"
}

help() { hex_help; }
list() { hex_list; }

PS1="hex>> "
unset PROMPT_COMMAND 2>/dev/null
`, tmpDir)

	if err := os.WriteFile(rcPath, []byte(rcContent), 0644); err != nil {
		return fmt.Errorf("binary_stream: shellcode: write bashrc: %w", err)
	}

	exec.Command("go", "build", "-o", filepath.Join(tmpDir, "hexsh"), mainPath).Run()

	fmt.Println("+----------------------------------------------------------+")
	fmt.Println("|          hex shell  -  二进制编辑工具                    |")
	fmt.Println("+----------------------------------------------------------+")
	fmt.Println("")
	fmt.Println("  hex help              查看帮助")
	fmt.Println("  hex open <file>       打开文件")
	fmt.Println("  hex hexdump           查看十六进制")
	fmt.Println("  hex read <off> <n>    读取数据")
	fmt.Println("  输入 exit    退出")
	fmt.Println("")

	cmd := exec.Command("/bin/bash", "--rcfile", rcPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	return nil
}

func buildMainGo(bsPkg string, tmpDir string) string {
	return fmt.Sprintf(`package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"%s"
)

var stateFile = "%s/.hexsh_state"

type shellState struct {
	path   string
	dirty  bool
	stream *%s.Stream
}

func loadState() *shellState {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(string(data)), "|")
	if len(parts) < 3 {
		return nil
	}
	path := parts[0]
	dirty := parts[1] == "1"
	s, err := %s.NewFromFile(path)
	if err != nil {
		return nil
	}
	return &shellState{path: path, dirty: dirty, stream: s}
}

func saveState(s *shellState) {
	if s == nil || s.path == "" {
		return
	}
	dirty := "0"
	if s.dirty {
		dirty = "1"
	}
	os.WriteFile(stateFile, []byte(fmt.Sprintf("%%s|%%s", s.path, dirty)), 0644)
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	state := loadState()

	switch cmd {
	case "open", "load":
		cmdOpen(args)
	case "save":
		cmdSave(state)
	case "saveas":
		cmdSaveAs(state, args)
	case "read", "r":
		cmdRead(state, args)
	case "write", "w", "patch":
		cmdWrite(state, args)
	case "insert":
		cmdInsert(state, args)
	case "delete", "del", "d":
		cmdDelete(state, args)
	case "replace", "rep":
		cmdReplace(state, args)
	case "hexdump", "hd":
		cmdHexDump(state, args)
	case "find":
		cmdFind(state, args)
	case "pos", "p":
		cmdPos(state, args)
	case "seek":
		cmdSeek(state, args)
	case "len", "size":
		cmdLen(state)
	case "info":
		cmdInfo(state)
	case "truncate", "trunc":
		cmdTruncate(state, args)
	case "undo":
		cmdUndo(state)
	case "string", "str":
		cmdString(state, args)
	case "list", "ls":
		cmdList(args)
	case "help", "h", "?":
		showHelp()
	default:
		fmt.Printf("未知命令: %%s\n", cmd)
		showHelp()
	}
}

func showHelp() {
	fmt.Println("hex shell - 二进制编辑工具")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  hex open <path>       打开文件")
	fmt.Println("  hex save              保存到当前文件")
	fmt.Println("  hex saveas <path>     另存为")
	fmt.Println("  hex read <off> <n>    读取 n 字节（hex显示）")
	fmt.Println("  hex str <off> <n>     读取 n 字节（字符串显示）")
	fmt.Println("  hex write <off> <hex> 覆盖写入（定长）")
	fmt.Println("  hex insert <off> <hex> 插入数据")
	fmt.Println("  hex delete <off> <n>   删除 n 字节")
	fmt.Println("  hex replace <s> <e> <hex> 替换范围数据")
	fmt.Println("  hex hexdump [n]       十六进制转储")
	fmt.Println("  hex find <hex>        搜索字节")
	fmt.Println("  hex pos [off]         设置/显示位置")
	fmt.Println("  hex seek <off> <w>    移动位置（0=头,1=当前,2=尾）")
	fmt.Println("  hex len               显示长度")
	fmt.Println("  hex info              显示文件信息")
	fmt.Println("  hex truncate <len>    截断")
	fmt.Println("  hex undo              撤销（重新加载）")
	fmt.Println("  hex list              列出文件")
	fmt.Println("  hex help              显示帮助")
}

func parseNum(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return int(v), err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return int(v), err
}

func cmdOpen(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: hex open <文件路径>")
		return
	}
	s, err := %s.NewFromFile(args[0])
	if err != nil {
		fmt.Printf("打开失败: %%v\n", err)
		return
	}
	state := &shellState{path: args[0], dirty: false, stream: s}
	saveState(state)
	fmt.Printf("已加载: %%s (%%d bytes)\n", args[0], s.Len())
}

func cmdSave(state *shellState) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if err := state.stream.SaveToFile(state.path); err != nil {
		fmt.Printf("保存失败: %%v\n", err)
		return
	}
	state.dirty = false
	saveState(state)
	fmt.Printf("已保存: %%s (%%d bytes)\n", state.path, state.stream.Len())
}

func cmdSaveAs(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 1 {
		fmt.Println("用法: hex saveas <文件路径>")
		return
	}
	if err := state.stream.SaveToFile(args[0]); err != nil {
		fmt.Printf("保存失败: %%v\n", err)
		return
	}
	state.path = args[0]
	state.dirty = false
	saveState(state)
	fmt.Printf("已保存: %%s (%%d bytes)\n", state.path, state.stream.Len())
}

func cmdRead(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 2 {
		fmt.Println("用法: hex read <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		fmt.Printf("无效字节数: %%s\n", args[1])
		return
	}
	if off < 0 {
		off = 0
	}
	data := state.stream.Slice(off, off+n)
	if len(data) == 0 {
		fmt.Println("(无数据)")
		return
	}
	fmt.Print(formatHexDump(data, off))
	fmt.Printf("  (%%d bytes, offset 0x%%X-0x%%X)\n", len(data), off, off+len(data)-1)
}

func cmdWrite(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 2 {
		fmt.Println("用法: hex write <偏移> <十六进制数据>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %%s\n", args[1])
		return
	}
	if off < 0 || off+len(data) > state.stream.Len() {
		fmt.Printf("写入超出范围 (offset=%%d, size=%%d, total=%%d)\n", off, len(data), state.stream.Len())
		return
	}
	state.stream.Patch(off, data)
	if state.stream.Error() != nil {
		fmt.Printf("写入失败: %%v\n", state.stream.Error())
		state.stream.ClearError()
		return
	}
	state.dirty = true
	saveState(state)
	fmt.Printf("已写入 %%d bytes @ 0x%%X\n", len(data), off)
}

func cmdInsert(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 2 {
		fmt.Println("用法: hex insert <偏移> <十六进制数据>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %%s\n", args[1])
		return
	}
	if off < 0 || off > state.stream.Len() {
		fmt.Printf("插入位置超出范围 (offset=%%d, total=%%d)\n", off, state.stream.Len())
		return
	}
	state.stream.Insert(off, data)
	state.dirty = true
	saveState(state)
	fmt.Printf("已插入 %%d bytes @ 0x%%X，新大小: %%d bytes\n", len(data), off, state.stream.Len())
}

func cmdDelete(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 2 {
		fmt.Println("用法: hex delete <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		fmt.Printf("无效字节数: %%s\n", args[1])
		return
	}
	if off < 0 || off+n > state.stream.Len() {
		fmt.Printf("删除范围超出 (offset=%%d, size=%%d, total=%%d)\n", off, n, state.stream.Len())
		return
	}
	state.stream.Delete(off, off+n)
	state.dirty = true
	saveState(state)
	fmt.Printf("已删除 %%d bytes @ 0x%%X，新大小: %%d bytes\n", n, off, state.stream.Len())
}

func cmdReplace(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 3 {
		fmt.Println("用法: hex replace <起始> <结束> <十六进制数据>")
		return
	}
	start, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效起始偏移: %%s\n", args[0])
		return
	}
	end, err := parseNum(args[1])
	if err != nil {
		fmt.Printf("无效结束偏移: %%s\n", args[1])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[2], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %%s\n", args[2])
		return
	}
	if start < 0 || end > state.stream.Len() || start > end {
		fmt.Printf("替换范围无效 (%%d-%%d, total=%%d)\n", start, end, state.stream.Len())
		return
	}
	state.stream.Replace(start, end, data)
	if state.stream.Error() != nil {
		fmt.Printf("替换失败: %%v\n", state.stream.Error())
		state.stream.ClearError()
		return
	}
	state.dirty = true
	saveState(state)
	fmt.Printf("已替换 [%%d,%%d) -> %%d bytes，新大小: %%d bytes\n", start, end, len(data), state.stream.Len())
}

func cmdHexDump(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	limit := 0
	if len(args) >= 1 {
		limit, _ = parseNum(args[0])
	}
	data := state.stream.Bytes()
	if limit > 0 && limit < len(data) {
		fmt.Print(formatHexDump(data[:limit], 0))
		fmt.Printf("  (%%d/%%d bytes shown)\n", limit, len(data))
	} else {
		fmt.Print(formatHexDump(data, 0))
		fmt.Printf("  (%%d bytes total)\n", len(data))
	}
}

func cmdFind(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 1 {
		fmt.Println("用法: hex find <十六进制数据>")
		return
	}
	pattern, err := hex.DecodeString(strings.ReplaceAll(args[0], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %%s\n", args[0])
		return
	}
	data := state.stream.Bytes()
	found := 0
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := range pattern {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			fmt.Printf("  匹配 @ 0x%%X (%%d)\n", i, i)
			found++
			if found >= 20 {
				fmt.Println("  (已达到20个匹配上限)")
				break
			}
		}
	}
	if found == 0 {
		fmt.Println("未找到匹配")
	} else {
		fmt.Printf("共找到 %%d 个匹配\n", found)
	}
}

func cmdPos(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 1 {
		fmt.Printf("当前位置: %%d (0x%%X)\n", state.stream.Pos(), state.stream.Pos())
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	state.stream.SetPos(off)
	fmt.Printf("位置已设为: %%d (0x%%X)\n", state.stream.Pos(), state.stream.Pos())
}

func cmdSeek(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 2 {
		fmt.Println("用法: hex seek <偏移> <whence(0=头,1=当前,2=尾)>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	whence, err := parseNum(args[1])
	if err != nil || whence < 0 || whence > 2 {
		fmt.Printf("无效 whence: %%s (0=头,1=当前,2=尾)\n", args[1])
		return
	}
	state.stream.Seek(int64(off), whence)
	fmt.Printf("位置已设为: %%d (0x%%X)\n", state.stream.Pos(), state.stream.Pos())
}

func cmdLen(state *shellState) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	fmt.Printf("总字节数: %%d (0x%%X)\n", state.stream.Len(), state.stream.Len())
}

func cmdInfo(state *shellState) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	fmt.Printf("文件: %%s\n", state.path)
	fmt.Printf("大小: %%d bytes (0x%%X)\n", state.stream.Len(), state.stream.Len())
	fmt.Printf("位置: %%d (0x%%X)\n", state.stream.Pos(), state.stream.Pos())
	fmt.Printf("脏标记: %%v\n", state.dirty)
}

func cmdTruncate(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 1 {
		fmt.Println("用法: hex truncate <长度>")
		return
	}
	length, err := parseNum(args[0])
	if err != nil || length < 0 {
		fmt.Printf("无效长度: %%s\n", args[0])
		return
	}
	oldLen := state.stream.Len()
	state.stream.Truncate(length)
	state.dirty = true
	saveState(state)
	fmt.Printf("已截断: %%d -> %%d bytes\n", oldLen, state.stream.Len())
}

func cmdUndo(state *shellState) {
	if state == nil || state.path == "" {
		fmt.Println("没有可撤销的文件")
		return
	}
	s, err := %s.NewFromFile(state.path)
	if err != nil {
		fmt.Printf("重新加载失败: %%v\n", err)
		return
	}
	state.stream = s
	state.dirty = false
	saveState(state)
	fmt.Printf("已撤销更改，重新加载: %%s (%%d bytes)\n", state.path, state.stream.Len())
}

func cmdString(state *shellState, args []string) {
	if state == nil || state.stream == nil {
		fmt.Println("没有打开的文件")
		return
	}
	if len(args) < 2 {
		fmt.Println("用法: hex str <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %%s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		fmt.Printf("无效字节数: %%s\n", args[1])
		return
	}
	if off < 0 {
		off = 0
	}
	data := state.stream.Slice(off, off+n)
	if len(data) == 0 {
		fmt.Println("(无数据)")
		return
	}
	fmt.Printf("%%q\n", string(data))
}

func cmdList(args []string) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("无法读取目录: %%v\n", err)
		return
	}
	for _, e := range entries {
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		fmt.Printf("%%s (%%d bytes)\n", e.Name(), size)
	}
}

func formatHexDump(data []byte, base int) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		b.WriteString(fmt.Sprintf("%%08X  ", base+i))
		for j := 0; j < 16; j++ {
			if j == 8 {
				b.WriteByte(' ')
			}
			if i+j < len(data) {
				b.WriteString(fmt.Sprintf("%%02X ", data[i+j]))
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			c := data[i+j]
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|")
		if i+16 < len(data) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
`, bsPkg, tmpDir, bsPkg, bsPkg, bsPkg, bsPkg)
}

func findBSPackage() (string, error) {
	modRoot := findBSModuleRoot()
	if modRoot == "" {
		return "", fmt.Errorf("cannot find go.mod")
	}
	modBytes, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	moduleLine := strings.TrimSpace(strings.Split(string(modBytes), "\n")[0])
	moduleName := strings.TrimPrefix(moduleLine, "module ")
	return moduleName + "/binary_stream", nil
}

func findBSModuleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	dir, _ = filepath.Abs(dir)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func ShellCodeScript(filePath string, scriptPath string) error {
	bsPkg, err := findBSPackage()
	if err != nil {
		return fmt.Errorf("binary_stream: shellcode: %w", err)
	}

	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("binary_stream: read script %s: %w", scriptPath, err)
	}

	s, err := NewFromFile(filePath)
	if err != nil {
		return fmt.Errorf("binary_stream: open file %s: %w", filePath, err)
	}

	shell := &shellStateForScript{
		path:   filePath,
		dirty:  false,
		stream: s,
	}

	lines := strings.Split(string(scriptData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Printf("hex>> %s\n", line)
		if !shell.dispatch(line, bsPkg) {
			break
		}
	}

	if shell.dirty {
		if err := shell.stream.SaveToFile(shell.path); err != nil {
			return fmt.Errorf("binary_stream: save file %s: %w", shell.path, err)
		}
		fmt.Printf("已保存: %s (%d bytes)\n", shell.path, shell.stream.Len())
	}
	return nil
}

type shellStateForScript struct {
	path   string
	dirty  bool
	stream *Stream
}

func (s *shellStateForScript) dispatch(line string, bsPkg string) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return true
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "exit", "quit":
		return false
	case "open", "load":
		s.doOpen(args)
	case "save":
		s.doSave()
	case "saveas":
		s.doSaveAs(args)
	case "read", "r":
		s.doRead(args)
	case "write", "w", "patch":
		s.doWrite(args)
	case "insert":
		s.doInsert(args)
	case "delete", "del", "d":
		s.doDelete(args)
	case "replace", "rep":
		s.doReplace(args)
	case "hexdump", "hd":
		s.doHexDump(args)
	case "find":
		s.doFind(args)
	case "pos", "p":
		s.doSetPos(args)
	case "seek":
		s.doSeek(args)
	case "len", "size":
		s.doLen()
	case "info":
		s.doInfo()
	case "truncate", "trunc":
		s.doTruncate(args)
	case "undo":
		s.doUndo()
	case "string", "str":
		s.doReadString(args)
	default:
		fmt.Printf("未知命令: %s\n", cmd)
	}
	return true
}

func (s *shellStateForScript) doOpen(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: open <文件路径>")
		return
	}
	stream, err := NewFromFile(args[0])
	if err != nil {
		fmt.Printf("打开失败: %v\n", err)
		return
	}
	s.stream = stream
	s.path = args[0]
	s.dirty = false
	fmt.Printf("已加载: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellStateForScript) doSave() {
	if err := s.stream.SaveToFile(s.path); err != nil {
		fmt.Printf("保存失败: %v\n", err)
		return
	}
	s.dirty = false
	fmt.Printf("已保存: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellStateForScript) doSaveAs(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: saveas <文件路径>")
		return
	}
	if err := s.stream.SaveToFile(args[0]); err != nil {
		fmt.Printf("保存失败: %v\n", err)
		return
	}
	s.path = args[0]
	s.dirty = false
	fmt.Printf("已保存: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellStateForScript) doRead(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: read <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		fmt.Printf("无效字节数: %s\n", args[1])
		return
	}
	if off < 0 {
		off = 0
	}
	data := s.stream.Slice(off, off+n)
	if len(data) == 0 {
		fmt.Println("(无数据)")
		return
	}
	fmt.Print(formatHexDump(data, off))
	fmt.Printf("  (%d bytes, offset 0x%X-0x%X)\n", len(data), off, off+len(data)-1)
}

func (s *shellStateForScript) doWrite(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: write <偏移> <十六进制数据>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %s\n", args[1])
		return
	}
	if off < 0 || off+len(data) > s.stream.Len() {
		fmt.Printf("写入超出范围 (offset=%d, size=%d, total=%d)\n", off, len(data), s.stream.Len())
		return
	}
	s.stream.Patch(off, data)
	if s.stream.Error() != nil {
		fmt.Printf("写入失败: %v\n", s.stream.Error())
		s.stream.ClearError()
		return
	}
	s.dirty = true
	fmt.Printf("已写入 %d bytes @ 0x%X\n", len(data), off)
}

func (s *shellStateForScript) doInsert(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: insert <偏移> <十六进制数据>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %s\n", args[1])
		return
	}
	if off < 0 || off > s.stream.Len() {
		fmt.Printf("插入位置超出范围 (offset=%d, total=%d)\n", off, s.stream.Len())
		return
	}
	s.stream.Insert(off, data)
	s.dirty = true
	fmt.Printf("已插入 %d bytes @ 0x%X，新大小: %d bytes\n", len(data), off, s.stream.Len())
}

func (s *shellStateForScript) doDelete(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: delete <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		fmt.Printf("无效字节数: %s\n", args[1])
		return
	}
	if off < 0 || off+n > s.stream.Len() {
		fmt.Printf("删除范围超出 (offset=%d, size=%d, total=%d)\n", off, n, s.stream.Len())
		return
	}
	s.stream.Delete(off, off+n)
	s.dirty = true
	fmt.Printf("已删除 %d bytes @ 0x%X，新大小: %d bytes\n", n, off, s.stream.Len())
}

func (s *shellStateForScript) doReplace(args []string) {
	if len(args) < 3 {
		fmt.Println("用法: replace <起始> <结束> <十六进制数据>")
		return
	}
	start, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效起始偏移: %s\n", args[0])
		return
	}
	end, err := parseNum(args[1])
	if err != nil {
		fmt.Printf("无效结束偏移: %s\n", args[1])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[2], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %s\n", args[2])
		return
	}
	if start < 0 || end > s.stream.Len() || start > end {
		fmt.Printf("替换范围无效 (%d-%d, total=%d)\n", start, end, s.stream.Len())
		return
	}
	s.stream.Replace(start, end, data)
	if s.stream.Error() != nil {
		fmt.Printf("替换失败: %v\n", s.stream.Error())
		s.stream.ClearError()
		return
	}
	s.dirty = true
	fmt.Printf("已替换 [%d,%d) -> %d bytes，新大小: %d bytes\n", start, end, len(data), s.stream.Len())
}

func (s *shellStateForScript) doHexDump(args []string) {
	limit := 0
	if len(args) >= 1 {
		limit, _ = parseNum(args[0])
	}
	data := s.stream.Bytes()
	if limit > 0 && limit < len(data) {
		fmt.Print(formatHexDump(data[:limit], 0))
		fmt.Printf("  (%d/%d bytes shown)\n", limit, len(data))
	} else {
		fmt.Print(formatHexDump(data, 0))
		fmt.Printf("  (%d bytes total)\n", len(data))
	}
}

func (s *shellStateForScript) doFind(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: find <十六进制数据>")
		return
	}
	pattern, err := hex.DecodeString(strings.ReplaceAll(args[0], " ", ""))
	if err != nil {
		fmt.Printf("无效十六进制: %s\n", args[0])
		return
	}
	data := s.stream.Bytes()
	found := 0
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := range pattern {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			fmt.Printf("  匹配 @ 0x%X (%d)\n", i, i)
			found++
			if found >= 20 {
				fmt.Println("  (已达到20个匹配上限)")
				break
			}
		}
	}
	if found == 0 {
		fmt.Println("未找到匹配")
	} else {
		fmt.Printf("共找到 %d 个匹配\n", found)
	}
}

func (s *shellStateForScript) doSetPos(args []string) {
	if len(args) < 1 {
		fmt.Printf("当前位置: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	s.stream.SetPos(off)
	fmt.Printf("位置已设为: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
}

func (s *shellStateForScript) doSeek(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: seek <偏移> <whence(0=头,1=当前,2=尾)>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	whence, err := parseNum(args[1])
	if err != nil || whence < 0 || whence > 2 {
		fmt.Printf("无效 whence: %s (0=头,1=当前,2=尾)\n", args[1])
		return
	}
	s.stream.Seek(int64(off), whence)
	fmt.Printf("位置已设为: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
}

func (s *shellStateForScript) doLen() {
	fmt.Printf("总字节数: %d (0x%X)\n", s.stream.Len(), s.stream.Len())
}

func (s *shellStateForScript) doInfo() {
	fmt.Printf("文件: %s\n", s.path)
	fmt.Printf("大小: %d bytes (0x%X)\n", s.stream.Len(), s.stream.Len())
	fmt.Printf("位置: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
	fmt.Printf("脏标记: %v\n", s.dirty)
}

func (s *shellStateForScript) doTruncate(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: truncate <长度>")
		return
	}
	length, err := parseNum(args[0])
	if err != nil || length < 0 {
		fmt.Printf("无效长度: %s\n", args[0])
		return
	}
	oldLen := s.stream.Len()
	s.stream.Truncate(length)
	s.dirty = true
	fmt.Printf("已截断: %d -> %d bytes\n", oldLen, s.stream.Len())
}

func (s *shellStateForScript) doUndo() {
	stream, err := NewFromFile(s.path)
	if err != nil {
		fmt.Printf("重新加载失败: %v\n", err)
		return
	}
	s.stream = stream
	s.dirty = false
	fmt.Printf("已撤销更改，重新加载: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellStateForScript) doReadString(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: str <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		fmt.Printf("无效偏移: %s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		fmt.Printf("无效字节数: %s\n", args[1])
		return
	}
	if off < 0 {
		off = 0
	}
	data := s.stream.Slice(off, off+n)
	if len(data) == 0 {
		fmt.Println("(无数据)")
		return
	}
	fmt.Printf("%q\n", string(data))
}

func parseNum(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return int(v), err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return int(v), err
}

func formatHexDump(data []byte, base int) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		b.WriteString(fmt.Sprintf("%08X  ", base+i))
		for j := 0; j < 16; j++ {
			if j == 8 {
				b.WriteByte(' ')
			}
			if i+j < len(data) {
				b.WriteString(fmt.Sprintf("%02X ", data[i+j]))
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			c := data[i+j]
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|")
		if i+16 < len(data) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func ShellCodeWithHistory() {
	ShellCode()
}
