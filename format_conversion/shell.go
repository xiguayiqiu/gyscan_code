package format_conversion

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func ShellCode() error {
	fmtPkg, err := findFmtPackage()
	if err != nil {
		return fmt.Errorf("format_conversion: shellcode: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "fmtsh_*")
	if err != nil {
		return fmt.Errorf("format_conversion: shellcode: create tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	modPath := filepath.Join(tmpDir, "go.mod")
	modContent := fmt.Sprintf(`module fmtsh

go 1.26

require %s v0.0.0

replace %s => %s
`, fmtPkg, fmtPkg, findModuleRoot())

	if err := os.WriteFile(modPath, []byte(modContent), 0644); err != nil {
		return fmt.Errorf("format_conversion: shellcode: write go.mod: %w", err)
	}

	mainPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(buildMainGo(fmtPkg)), 0644); err != nil {
		return fmt.Errorf("format_conversion: shellcode: write main.go: %w", err)
	}

	rcPath := filepath.Join(tmpDir, "bashrc")
	rcContent := fmt.Sprintf(`if [ -f ~/.bashrc ]; then
	. ~/.bashrc
fi

alias fmt='go run "%s/main.go"'

help() {
	cat <<'EOF'
fmt shell - 文件格式转换工具

命令:
  fmt convert <src> <dst>    单个文件格式转换
  fmt batch <dir> <srcExt> <dstExt>  批量转换目录下文件
  fmt info <path>             查看文件格式信息
  fmt detect <path>           检测文件真实格式（魔数）
  fmt formats                 列出所有支持格式
  fmt help                    显示帮助
  fmt pandoc                  检查 pandoc 安装状态

支持的格式:
  图片: PNG, JPG, BMP, ICO, WEBP, GIF
  音频: WAV, MP3, OGG
  视频: MP4, MOV
  文档: Markdown, DOC, DOCX, ODT, HTML, RTF, PDF, TXT
  （注意: .doc 只能作为输入；PDF 输出需要 wkhtmltopdf 等引擎）

示例:
  fmt convert image.png image.jpg
  fmt convert audio.wav audio.mp3
  fmt convert video.mp4 video.mov
  fmt convert document.md document.docx
  fmt batch ./docs .md .docx
  fmt info photo.jpg
  fmt detect unknown.bin

EOF
}

list() {
	echo "支持的格式:"
	echo "  图片: PNG, JPG, BMP, ICO, WEBP, GIF"
	echo "  音频: WAV, MP3, OGG"
	echo "  视频: MP4, MOV"
	echo "  文档: Markdown, DOC, DOCX, ODT, HTML, RTF, PDF, TXT"
	echo ""
	echo "注意: pandoc 不支持将 .doc 作为输出格式，请使用 .docx"
	echo "注意: PDF 输出需要 wkhtmltopdf/weasyprint 等 PDF 引擎"
}

convert() {
	if command -v magick >/dev/null 2>&1 || command -v convert >/dev/null 2>&1; then
		echo "提示: 检测到 ImageMagick convert 命令，已自动转发到 fmt convert"
	fi
	fmt convert "$@"
}

PS1="fmt>> "
unset PROMPT_COMMAND 2>/dev/null
`, tmpDir)

	if err := os.WriteFile(rcPath, []byte(rcContent), 0644); err != nil {
		return fmt.Errorf("format_conversion: shellcode: write bashrc: %w", err)
	}

	exec.Command("go", "build", "-o", filepath.Join(tmpDir, "fmtsh"), mainPath).Run()

	printDependencyStatus()

	fmt.Println("+----------------------------------------------------------+")
	fmt.Println("|     fmt shell  -  文件格式转换工具                       |")
	fmt.Println("+----------------------------------------------------------+")
	fmt.Println("")
	fmt.Println("  help              查看帮助")
	fmt.Println("  list              列出支持的格式")
	fmt.Println("  fmt convert <src> <dst>  转换文件")
	fmt.Println("  fmt batch <dir> <src> <dst>  批量转换")
	fmt.Println("  fmt info <file>   查看文件信息")
	fmt.Println("  fmt detect <file> 检测文件格式")
	fmt.Println("  fmt pandoc        检查 pandoc 状态")
	fmt.Println("  exit              退出")
	fmt.Println("  （可直接使用系统命令: ls, echo, pwd, cat ...）")
	fmt.Println("")

	cmd := exec.Command("/bin/bash", "--rcfile", rcPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	return nil
}

func buildMainGo(fmtPkg string) string {
	pkgName := filepath.Base(fmtPkg)
	return fmt.Sprintf(`package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"%s"
)

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "convert", "c":
		cmdConvert(args)
	case "batch", "b":
		cmdBatch(args)
	case "info", "i":
		cmdInfo(args)
	case "detect", "d":
		cmdDetect(args)
	case "formats", "list", "l":
		cmdFormats()
	case "pandoc":
		cmdPandoc()
	case "help", "h", "?":
		showHelp()
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("fmt shell - 文件格式转换工具")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  fmt convert <src> <dst>    单个文件格式转换")
	fmt.Println("  fmt batch <dir> <srcExt> <dstExt>  批量转换目录下文件")
	fmt.Println("  fmt info <path>             查看文件格式信息")
	fmt.Println("  fmt detect <path>           检测文件真实格式（魔数）")
	fmt.Println("  fmt formats                 列出所有支持格式")
	fmt.Println("  fmt pandoc                  检查 pandoc 安装状态")
	fmt.Println("  fmt help                    显示帮助")
	fmt.Println()
	fmt.Println("支持的格式:")
	fmt.Println("  图片: PNG, JPG, BMP, ICO, WEBP, GIF")
	fmt.Println("  音频: WAV, MP3, OGG")
	fmt.Println("  视频: MP4, MOV")
	fmt.Println("  文档: Markdown, DOC, DOCX, ODT, HTML, RTF, PDF, TXT")
	fmt.Println()
	fmt.Println("注意: pandoc 不支持输出 .doc 格式，请使用 .docx 代替")
	fmt.Println("注意: PDF 输出需要 wkhtmltopdf/weasyprint 等 PDF 引擎")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  fmt convert image.png image.jpg")
	fmt.Println("  fmt convert audio.wav audio.mp3")
	fmt.Println("  fmt convert video.mp4 video.mov")
	fmt.Println("  fmt convert document.md document.docx")
	fmt.Println("  fmt batch ./docs .md .docx")
	fmt.Println("  fmt info photo.jpg")
	fmt.Println("  fmt detect unknown.bin")
}

func cmdConvert(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: fmt convert <源文件> <目标文件>")
		fmt.Println("示例: fmt convert document.md document.docx")
		return
	}
	fmt.Printf("正在转换 %%s -> %%s ...\n", args[0], args[1])
	if err := %s.ConvertFile(args[0], args[1]); err != nil {
		fmt.Printf("转换失败: %%v\n", err)
		return
	}
	srcFmt := %s.GetFormatName(args[0])
	dstFmt := %s.GetFormatName(args[1])
	fmt.Printf("转换成功: %%s (%%s) -> %%s (%%s)\n", args[0], srcFmt, args[1], dstFmt)
}

func cmdBatch(args []string) {
	if len(args) < 3 {
		fmt.Println("用法: fmt batch <目录> <源扩展名> <目标扩展名>")
		fmt.Println("示例: fmt batch ./docs .md .docx")
		return
	}
	if err := %s.BatchConvert(args[0], args[1], args[2]); err != nil {
		fmt.Printf("批量转换失败: %%v\n", err)
	}
}

func cmdInfo(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: fmt info <文件路径>")
		return
	}
	path := args[0]
	format := %s.GetFormatName(path)
	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("文件: %%s\n", path)
		fmt.Printf("  状态: 无法读取 (%%v)\n", err)
		return
	}
	fmt.Printf("文件: %%s\n", path)
	fmt.Printf("  大小: %%d bytes\n", info.Size())
	fmt.Printf("  格式: %%s\n", format)
}

func cmdDetect(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: fmt detect <文件路径>")
		return
	}
	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("读取失败: %%v\n", err)
		return
	}
	format := %s.DetectFormat(data)
	ext := extractExt(path)
	extFormat := %s.DetectFormatByExt(ext)
	fmt.Printf("文件: %%s\n", path)
	fmt.Printf("  魔数检测: %%s\n", format.String())
	fmt.Printf("  扩展名检测: %%s\n", extFormat.String())
	if format != extFormat && format != %s.FormatUnknown && extFormat != %s.FormatUnknown {
		fmt.Println("  警告: 魔数与扩展名不一致!")
	}
}

func cmdFormats() {
	fmt.Println("支持的格式:")
	for _, f := range %s.SupportedFormats() {
		fmt.Printf("  - %%s\n", f)
	}
	fmt.Println()
	fmt.Println("支持的转换:")
	for _, c := range %s.SupportedConversions() {
		fmt.Printf("  - %%s\n", c)
	}
}

func cmdPandoc() {
	if _, err := exec.LookPath("pandoc"); err != nil {
		fmt.Println("pandoc: 未安装")
		fmt.Println("安装方法: sudo apt install pandoc  (Debian/Ubuntu)")
		fmt.Println("         sudo yum install pandoc  (RHEL/CentOS)")
		fmt.Println("         brew install pandoc      (macOS)")
		fmt.Println()
		fmt.Println("注意: pandoc 不支持输出 .doc 格式，请使用 .docx")
		fmt.Println("注意: PDF 输出需要 wkhtmltopdf/weasyprint 等 PDF 引擎")
		return
	}
	out, err := exec.Command("pandoc", "--version").Output()
	if err != nil {
		fmt.Println("pandoc: 已安装但无法获取版本信息")
		return
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		fmt.Printf("pandoc: 已安装 (%%s)\n", lines[0])
	}
	fmt.Println("注意: pandoc 不支持输出 .doc 格式，请使用 .docx")
	fmt.Println("注意: PDF 输出需要 wkhtmltopdf/weasyprint 等 PDF 引擎")
}

func extractExt(filename string) string {
	i := strings.LastIndex(filename, ".")
	if i < 0 {
		return ""
	}
	return filename[i:]
}
`, fmtPkg,
		pkgName, pkgName, pkgName, pkgName, pkgName, pkgName, pkgName,
		pkgName, pkgName, pkgName, pkgName)
}

func ShellcodeScript(scriptPath string) error {
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("format_conversion: read script %s: %w", scriptPath, err)
	}

	lines := strings.Split(string(scriptData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Printf("fmt>> %s\n", line)
		dispatchScript(line)
	}
	return nil
}

func dispatchScript(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "exit", "quit", "q":
		return
	case "convert", "c":
		if len(args) >= 2 {
			fmt.Printf("正在转换 %s -> %s ...\n", args[0], args[1])
			if err := ConvertFile(args[0], args[1]); err != nil {
				fmt.Printf("转换失败: %v\n", err)
				return
			}
			fmt.Printf("转换成功: %s (%s) -> %s (%s)\n", args[0], GetFormatName(args[0]), args[1], GetFormatName(args[1]))
		}
	case "batch", "b":
		if len(args) >= 3 {
			if err := BatchConvert(args[0], args[1], args[2]); err != nil {
				fmt.Printf("批量转换失败: %v\n", err)
			}
		}
	case "pandoc":
		cmdPandoc()
	case "formats", "l":
		for _, f := range SupportedFormats() {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Println()
		for _, c := range SupportedConversions() {
			fmt.Printf("  - %s\n", c)
		}
	case "info", "i":
		if len(args) >= 1 {
			fmt.Printf("文件: %s\n", args[0])
			fmt.Printf("  格式: %s\n", GetFormatName(args[0]))
		}
	case "detect", "d":
		if len(args) >= 1 {
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Printf("读取失败: %v\n", err)
				return
			}
			fmt.Printf("文件: %s\n", args[0])
			fmt.Printf("  魔数检测: %s\n", DetectFormat(data).String())
		}
	default:
		fmt.Printf("未知命令: %s\n", cmd)
	}
}

func ShellcodeWithHistory() {
	ShellCode()
}

func cmdPandoc() {
	if _, err := exec.LookPath("pandoc"); err != nil {
		fmt.Println("pandoc: 未安装")
		fmt.Println("安装方法: sudo apt install pandoc  (Debian/Ubuntu)")
		fmt.Println("         sudo yum install pandoc  (RHEL/CentOS)")
		fmt.Println("         brew install pandoc      (macOS)")
		fmt.Println()
		fmt.Println("注意: pandoc 不支持输出 .doc 格式，请使用 .docx")
		fmt.Println("注意: PDF 输出需要 wkhtmltopdf/weasyprint 等 PDF 引擎")
		return
	}
	out, err := exec.Command("pandoc", "--version").Output()
	if err != nil {
		fmt.Println("pandoc: 已安装但无法获取版本信息")
		return
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		fmt.Printf("pandoc: 已安装 (%s)\n", lines[0])
	}
	fmt.Println("注意: pandoc 不支持输出 .doc 格式，请使用 .docx")
	fmt.Println("注意: PDF 输出需要 wkhtmltopdf/weasyprint 等 PDF 引擎")
}

func printDependencyStatus() {
	missingPandoc := false
	missingFFmpeg := false

	fmt.Println("依赖检查:")
	if _, err := exec.LookPath("pandoc"); err != nil {
		fmt.Println("  pandoc: 未安装 (文档转换功能将不可用)")
		missingPandoc = true
	} else {
		fmt.Println("  pandoc: 已安装")
	}
	if _, err := exec.LookPath("convert"); err != nil {
		if _, err := exec.LookPath("magick"); err != nil {
			fmt.Println("  ImageMagick: 未安装 (图片转换可能受限)")
		} else {
			fmt.Println("  ImageMagick (magick): 已安装")
		}
	} else {
		fmt.Println("  ImageMagick (convert): 已安装")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		fmt.Println("  ffmpeg: 未安装 (音频/视频/GIF 转换功能将不可用)")
		missingFFmpeg = true
	} else {
		fmt.Println("  ffmpeg: 已安装")
	}

	if (missingPandoc || missingFFmpeg) && runtime.GOOS == "windows" {
		fmt.Println()
		fmt.Println("+----------------------------------------------------------+")
		fmt.Println("|  Windows 用户注意:                                       |")
		fmt.Println("|  部分功能需要额外安装以下组件才能完整体验:               |")
		if missingPandoc {
			fmt.Println("|    pandoc: https://pandoc.org/installing.html            |")
			fmt.Println("|             winget install pandoc                        |")
		}
		if missingFFmpeg {
			fmt.Println("|    ffmpeg: https://ffmpeg.org/download.html              |")
			fmt.Println("|             winget install ffmpeg                        |")
		}
		fmt.Println("+----------------------------------------------------------+")
	}

	fmt.Println()
}

func findFmtPackage() (string, error) {
	modRoot := findModuleRoot()
	if modRoot == "" {
		return "", fmt.Errorf("cannot find go.mod")
	}
	modBytes, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	moduleLine := strings.TrimSpace(strings.Split(string(modBytes), "\n")[0])
	moduleName := strings.TrimPrefix(moduleLine, "module ")
	return moduleName + "/format_conversion", nil
}

func findModuleRoot() string {
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