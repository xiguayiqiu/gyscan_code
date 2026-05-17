package format_conversion

import (
	"fmt"
	"os"
	"strings"

	"github.com/xiguayiqiu/gyscan_code/binary_stream"
)

func Shellcode() {
	rl, err := binary_stream.NewReadLine("fmt>> ")
	if err != nil {
		fmt.Printf("初始化终端失败: %v\n", err)
		return
	}
	defer rl.Restore()

	rl.Completions = map[string][]string{
		"": {"exit", "quit", "q", "help", "h", "?", "convert", "c",
			"batch", "b", "info", "i", "formats", "detect", "d",
			"ls", "pwd", "cd", "clear",
		},
	}

	shell := &convertShell{
		rl: rl,
		se: binary_stream.NewShellExec("fmt").SetReader(rl),
	}

	rl.Println("=== 格式转换 Shell ===")
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

func ShellcodeScript(scriptPath string) error {
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("format_conversion: read script %s: %w", scriptPath, err)
	}

	shell := &convertShell{
		rl: nil,
		se: binary_stream.NewShellExec("fmt"),
	}

	lines := strings.Split(string(scriptData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Printf("fmt>> %s\n", line)
		if !shell.dispatch(line) {
			break
		}
	}
	return nil
}

func ShellcodeWithHistory() {
	Shellcode()
}

type convertShell struct {
	rl *binary_stream.ReadLine
	se *binary_stream.ShellExec
}

func (s *convertShell) dispatch(line string) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return true
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "exit", "quit", "q":
		s.rl.Println("再见!")
		return false
	case "help", "h", "?":
		s.doHelp()
	case "convert", "c":
		s.doConvert(args)
	case "batch", "b":
		s.doBatch(args)
	case "info", "i":
		s.doInfo(args)
	case "formats":
		s.doFormats()
	case "detect", "d":
		s.doDetect(args)
	default:
		if s.se != nil {
			s.se.ExecCommand(line)
		} else {
			s.rl.Printf("未知命令: %s，输入 help 查看帮助\n", cmd)
		}
	}
	return true
}

func (s *convertShell) doHelp() {
	s.rl.Println(`
=== 格式转换命令 ===

格式转换:
  convert <src> <dst>    单个文件格式转换
  batch <dir> <srcExt> <dstExt>  批量转换目录下文件
  info <path>            查看文件格式信息
  detect <path>          检测文件真实格式（魔数）
  formats                列出所有支持格式

其他:
  help                   显示帮助
  exit / quit / q        退出

快捷键:
  ↑↓               浏览历史命令
  Tab               命令补全
  ←→               移动光标
  Ctrl+A/E         行首/行尾
  Ctrl+U/K         删除到行首/行尾
  Ctrl+W           删除前一个单词

示例:
  convert image.png image.jpg
  convert audio.wav audio.mp3
  convert video.mp4 video.mov
  batch ./images .png .jpg
  info document.pdf
  detect unknown.bin`)
}

func (s *convertShell) doConvert(args []string) {
	if len(args) < 2 {
		s.rl.Println("用法: convert <源文件> <目标文件>")
		return
	}

	s.rl.Printf("正在转换 %s -> %s ...\n", args[0], args[1])
	if err := ConvertFile(args[0], args[1]); err != nil {
		s.rl.Printf("转换失败: %v\n", err)
		return
	}

	srcFmt := GetFormatName(args[0])
	dstFmt := GetFormatName(args[1])
	s.rl.Printf("转换成功: %s (%s) -> %s (%s)\n", args[0], srcFmt, args[1], dstFmt)
}

func (s *convertShell) doBatch(args []string) {
	if len(args) < 3 {
		s.rl.Println("用法: batch <目录> <源扩展名> <目标扩展名>")
		s.rl.Println("示例: batch ./images .png .webp")
		return
	}

	if err := BatchConvert(args[0], args[1], args[2]); err != nil {
		s.rl.Printf("批量转换失败: %v\n", err)
	}
}

func (s *convertShell) doInfo(args []string) {
	if len(args) < 1 {
		s.rl.Println("用法: info <文件路径>")
		return
	}

	format := GetFormatName(args[0])
	s.rl.Printf("文件: %s\n", args[0])

	info, err := os.Stat(args[0])
	if err != nil {
		s.rl.Printf("  状态: 无法读取 (%v)\n", err)
		return
	}
	s.rl.Printf("  大小: %d bytes\n", info.Size())
	s.rl.Printf("  格式: %s\n", format)
}

func (s *convertShell) doFormats() {
	s.rl.Println("支持的格式:")
	for _, f := range SupportedFormats() {
		s.rl.Printf("  - %s\n", f)
	}
	s.rl.Println("")
	s.rl.Println("支持的转换:")
	for _, c := range SupportedConversions() {
		s.rl.Printf("  - %s\n", c)
	}
}

func (s *convertShell) doDetect(args []string) {
	if len(args) < 1 {
		s.rl.Println("用法: detect <文件路径>")
		return
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		s.rl.Printf("读取失败: %v\n", err)
		return
	}

	format := DetectFormat(data)
	s.rl.Printf("文件: %s\n", args[0])
	s.rl.Printf("  魔数检测: %s\n", format.String())

	extFormat := DetectFormatByExt(extractExt(args[0]))
	s.rl.Printf("  扩展名检测: %s\n", extFormat.String())

	if format != extFormat && format != FormatUnknown && extFormat != FormatUnknown {
		s.rl.Printf("  ⚠ 魔数与扩展名不一致!\n")
	}
}
