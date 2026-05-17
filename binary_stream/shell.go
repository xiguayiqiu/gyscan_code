package binary_stream

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Shellcode 启动交互式二进制编辑 shell，提示符为 hex>>
// 支持 open/save/read/write/insert/delete/replace/hexdump 等命令操作文件
func Shellcode(filePath string) {
	if filePath == "" {
		fmt.Println("用法: binary_stream.Shellcode(\"文件路径\")")
		return
	}

	s, err := NewFromFile(filePath)
	if err != nil {
		fmt.Printf("打开文件失败: %v\n", err)
		return
	}

	rl, err := NewReadLine("hex>> ")
	if err != nil {
		fmt.Printf("初始化终端失败: %v\n", err)
		return
	}
	defer rl.Restore()

	rl.Completions = map[string][]string{
		"": {"exit", "quit", "q", "help", "h", "?", "open", "load",
			"save", "saveas", "read", "r", "write", "w", "patch",
			"insert", "i", "delete", "del", "d", "replace", "rep",
			"hexdump", "hd", "len", "size", "info", "pos", "p", "seek",
			"rem", "remaining", "eof", "truncate", "trunc", "string",
			"str", "find", "undo", "ls", "pwd", "cd", "clear",
		},
	}

	shell := &shellState{
		stream: s,
		rl:     rl,
		path:   filePath,
		dirty:  false,
		se:     NewShellExec("hex").SetReader(rl),
	}

	rl.Printf("已加载: %s (%d bytes)\n", filePath, shell.stream.Len())
	rl.Println("输入 help 查看帮助，↑↓ 浏览历史，Tab 补全，输入 exit 退出")

	for {
		line, err := rl.ReadLine()
		if err != nil || line == "" {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !shell.dispatch(line) {
			break
		}
	}
}

type shellState struct {
	stream *Stream
	rl     *ReadLine
	path   string
	dirty  bool
	se     *ShellExec
}

func (s *shellState) dispatch(line string) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return true
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "exit", "quit":
		if s.dirty {
			fmt.Print("数据已修改，是否保存? (y/n): ")
			resp, _ := s.rl.ReadLine()
			if strings.ToLower(strings.TrimSpace(resp)) == "y" {
				s.doSave()
			}
		}
		s.rl.Println("再见!")
		return false
	case "q":
		if s.dirty {
			s.rl.Println("警告: 数据已修改，使用 exit 退出以确认")
			return true
		}
		s.rl.Println("再见!")
		return false
	case "help", "h", "?":
		s.doHelp()
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
	case "insert", "i":
		s.doInsert(args)
	case "delete", "del", "d":
		s.doDelete(args)
	case "replace", "rep":
		s.doReplace(args)
	case "hexdump", "hd":
		s.doHexDump(args)
	case "len", "size":
		s.doLen()
	case "info":
		s.doInfo()
	case "pos", "p":
		s.doSetPos(args)
	case "seek":
		s.doSeek(args)
	case "rem", "remaining":
		s.doRemaining()
	case "eof":
		s.doEOF()
	case "truncate", "trunc":
		s.doTruncate(args)
	case "string", "str":
		s.doReadString(args)
	case "find":
		s.doFind(args)
	case "undo":
		s.doUndo(args)
	default:
		if s.se != nil {
			s.se.ExecCommand(line)
		} else {
			s.rl.Printf("未知命令: %s，输入 help 查看帮助\n", cmd)
		}
	}
	return true
}

func (s *shellState) doHelp() {
	s.rl.Println(`
=== hex shell 命令 ===

文件操作:
  open <path>       打开文件
  save              保存到当前文件
  saveas <path>     另存为
  info              显示文件信息
  len               显示数据长度
  exit              退出

数据查看:
  hexdump [lines]   十六进制转储（默认全部）
  read <off> <n>    读取 n 个字节（十六进制显示）
  str <off> <n>     读取 n 个字节（字符串显示）
  find <hex>        搜索字节

数据编辑:
  write <off> <hex>     覆盖写入（定长）
  insert <off> <hex>    插入数据
  delete <off> <n>      删除 n 个字节
  replace <s> <e> <hex> 替换范围数据
  truncate <len>        截断到指定长度

定位:
  pos <off>          设置读写位置
  seek <off> <whence> 移动位置（0=头,1=当前,2=尾）
  rem                显示剩余字节
  eof                检查是否到末尾

其他:
  undo               撤销修改（重新加载文件）
  help               显示帮助`)
}

func (s *shellState) doOpen(args []string) {
	if len(args) < 1 {
		s.rl.Println("用法: open <文件路径>")
		return
	}
	stream, err := NewFromFile(args[0])
	if err != nil {
		s.rl.Printf("打开失败: %v\n", err)
		return
	}
	s.stream = stream
	s.path = args[0]
	s.dirty = false
	s.rl.Printf("已加载: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellState) doSave() {
	if err := s.stream.SaveToFile(s.path); err != nil {
		s.rl.Printf("保存失败: %v\n", err)
		return
	}
	s.dirty = false
	s.rl.Printf("已保存: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellState) doSaveAs(args []string) {
	if len(args) < 1 {
		s.rl.Println("用法: saveas <文件路径>")
		return
	}
	if err := s.stream.SaveToFile(args[0]); err != nil {
		s.rl.Printf("保存失败: %v\n", err)
		return
	}
	s.path = args[0]
	s.dirty = false
	s.rl.Printf("已保存: %s (%d bytes)\n", s.path, s.stream.Len())
}

func (s *shellState) doRead(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: read <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		s.rl.Printf("无效字节数: %s\n", args[1])
		return
	}
	if off < 0 {
		off = 0
	}

	data := s.stream.Slice(off, off+n)
	if len(data) == 0 {
		s.rl.Println("(无数据)")
		return
	}

	s.rl.Println(formatHexDump(data, off))
	s.rl.Printf("  (%d bytes, offset 0x%X-0x%X)\n", len(data), off, off+len(data)-1)
}

func (s *shellState) doWrite(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: write <偏移> <十六进制数据>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
	if err != nil {
		s.rl.Printf("无效十六进制: %s\n", args[1])
		return
	}
	if off < 0 || off+len(data) > s.stream.Len() {
		s.rl.Printf("写入超出范围 (offset=%d, size=%d, total=%d)\n", off, len(data), s.stream.Len())
		return
	}
	s.stream.Patch(off, data)
	if s.stream.Error() != nil {
		s.rl.Printf("写入失败: %v\n", s.stream.Error())
		s.stream.ClearError()
		return
	}
	s.dirty = true
	s.rl.Printf("已写入 %d bytes @ 0x%X\n", len(data), off)
}

func (s *shellState) doInsert(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: insert <偏移> <十六进制数据>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
	if err != nil {
		s.rl.Printf("无效十六进制: %s\n", args[1])
		return
	}
	if off < 0 || off > s.stream.Len() {
		s.rl.Printf("插入位置超出范围 (offset=%d, total=%d)\n", off, s.stream.Len())
		return
	}
	s.stream.Insert(off, data)
	s.dirty = true
	s.rl.Printf("已插入 %d bytes @ 0x%X，新大小: %d bytes\n", len(data), off, s.stream.Len())
}

func (s *shellState) doDelete(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: delete <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		s.rl.Printf("无效字节数: %s\n", args[1])
		return
	}
	if off < 0 || off+n > s.stream.Len() {
		s.rl.Printf("删除范围超出 (offset=%d, size=%d, total=%d)\n", off, n, s.stream.Len())
		return
	}
	s.stream.Delete(off, off+n)
	s.dirty = true
	s.rl.Printf("已删除 %d bytes @ 0x%X，新大小: %d bytes\n", n, off, s.stream.Len())
}

func (s *shellState) doReplace(args []string) {
	if len(args) < 3 {
		s.rl.Println("用法: replace <起始> <结束> <十六进制数据>")
		return
	}
	start, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效起始偏移: %s\n", args[0])
		return
	}
	end, err := parseNum(args[1])
	if err != nil {
		s.rl.Printf("无效结束偏移: %s\n", args[1])
		return
	}
	data, err := hex.DecodeString(strings.ReplaceAll(args[2], " ", ""))
	if err != nil {
		s.rl.Printf("无效十六进制: %s\n", args[2])
		return
	}
	if start < 0 || end > s.stream.Len() || start > end {
		s.rl.Printf("替换范围无效 (%d-%d, total=%d)\n", start, end, s.stream.Len())
		return
	}
	s.stream.Replace(start, end, data)
	if s.stream.Error() != nil {
		s.rl.Printf("替换失败: %v\n", s.stream.Error())
		s.stream.ClearError()
		return
	}
	s.dirty = true
	s.rl.Printf("已替换 [%d,%d) -> %d bytes，新大小: %d bytes\n", start, end, len(data), s.stream.Len())
}

func (s *shellState) doHexDump(args []string) {
	limit := 0
	if len(args) >= 1 {
		limit, _ = parseNum(args[0])
	}
	data := s.stream.Bytes()
	if !s.dirty {
		if s.stream.Error() != nil {
			s.stream.ClearError()
		}
	}
	if limit > 0 && limit < len(data) {
		s.rl.Println(formatHexDump(data[:limit], 0))
		s.rl.Printf("  (%d/%d bytes shown)\n", limit, len(data))
	} else {
		s.rl.Println(formatHexDump(data, 0))
		s.rl.Printf("  (%d bytes total)\n", len(data))
	}
}

func (s *shellState) doLen() {
	s.rl.Printf("总字节数: %d (0x%X)\n", s.stream.Len(), s.stream.Len())
}

func (s *shellState) doInfo() {
	s.rl.Printf("文件: %s\n", s.path)
	s.rl.Printf("大小: %d bytes (0x%X)\n", s.stream.Len(), s.stream.Len())
	s.rl.Printf("位置: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
	s.rl.Printf("脏标记: %v\n", s.dirty)
}

func (s *shellState) doSetPos(args []string) {
	if len(args) < 1 {
		s.rl.Printf("当前位置: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	s.stream.SetPos(off)
	s.rl.Printf("位置已设为: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
}

func (s *shellState) doSeek(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: seek <偏移> <whence(0=头,1=当前,2=尾)>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	whence, err := parseNum(args[1])
	if err != nil || whence < 0 || whence > 2 {
		s.rl.Printf("无效 whence: %s (0=头,1=当前,2=尾)\n", args[1])
		return
	}
	s.stream.Seek(int64(off), whence)
	s.rl.Printf("位置已设为: %d (0x%X)\n", s.stream.Pos(), s.stream.Pos())
}

func (s *shellState) doRemaining() {
	s.rl.Printf("剩余: %d bytes (0x%X)\n", s.stream.Remaining(), s.stream.Remaining())
}

func (s *shellState) doEOF() {
	if s.stream.EOF() {
		s.rl.Println("已到达末尾")
	} else {
		s.rl.Printf("未到末尾，剩余: %d bytes\n", s.stream.Remaining())
	}
}

func (s *shellState) doReadString(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: str <偏移> <字节数>")
		return
	}
	off, err := parseNum(args[0])
	if err != nil {
		s.rl.Printf("无效偏移: %s\n", args[0])
		return
	}
	n, err := parseNum(args[1])
	if err != nil || n <= 0 {
		s.rl.Printf("无效字节数: %s\n", args[1])
		return
	}
	if off < 0 {
		off = 0
	}
	data := s.stream.Slice(off, off+n)
	if len(data) == 0 {
		s.rl.Println("(无数据)")
		return
	}
	s.rl.Printf("%q\n", string(data))
}

func (s *shellState) doTruncate(args []string) {
	if len(args) < 1 {
		s.rl.Println("用法: truncate <长度>")
		return
	}
	length, err := parseNum(args[0])
	if err != nil || length < 0 {
		s.rl.Printf("无效长度: %s\n", args[0])
		return
	}
	oldLen := s.stream.Len()
	s.stream.Truncate(length)
	s.dirty = true
	s.rl.Printf("已截断: %d -> %d bytes\n", oldLen, s.stream.Len())
}

func (s *shellState) doFind(args []string) {
	if len(args) < 1 {
		s.rl.Println("用法: find <十六进制数据>")
		return
	}
	pattern, err := hex.DecodeString(strings.ReplaceAll(args[0], " ", ""))
	if err != nil {
		s.rl.Printf("无效十六进制: %s\n", args[0])
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
			s.rl.Printf("  匹配 @ 0x%X (%d)\n", i, i)
			found++
			if found >= 20 {
				s.rl.Println("  (已达到20个匹配上限)")
				break
			}
		}
	}
	if found == 0 {
		s.rl.Println("未找到匹配")
	} else {
		s.rl.Printf("共找到 %d 个匹配\n", found)
	}
}

func (s *shellState) doUndo(args []string) {
	stream, err := NewFromFile(s.path)
	if err != nil {
		s.rl.Printf("重新加载失败: %v\n", err)
		return
	}
	s.stream = stream
	s.dirty = false
	s.rl.Printf("已撤销更改，重新加载: %s (%d bytes)\n", s.path, s.stream.Len())
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

// ShellcodeScript 执行脚本文件中的命令操作二进制文件
func ShellcodeScript(filePath string, scriptPath string) error {
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("binary_stream: read script %s: %w", scriptPath, err)
	}

	s, err := NewFromFile(filePath)
	if err != nil {
		return fmt.Errorf("binary_stream: open file %s: %w", filePath, err)
	}

	shell := &shellState{
		stream: s,
		rl:     nil,
		path:   filePath,
		dirty:  false,
		se:     NewShellExec("hex"),
	}

	lines := strings.Split(string(scriptData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Printf("hex>> %s\n", line)
		if !shell.dispatch(line) {
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

// ShellcodeWithHistory 启动交互式二进制编辑 shell，支持命令历史记录
func ShellcodeWithHistory(filePath string) {
	Shellcode(filePath)
}
