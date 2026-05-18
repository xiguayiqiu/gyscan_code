# format_conversion - 文件格式转换库

基于 `binary_stream` 二进制流操作库和 `ffmpeg-go` / `pandoc` 等外部工具，实现图片、音频、视频、文档文件格式之间的互转。通过魔数检测自动识别源格式，支持文件级和字节级转换。

## 依赖要求

部分功能依赖外部命令行工具，请在对应平台安装：

| 工具 | 用途 | Linux | macOS | Windows |
|------|------|-------|-------|---------|
| **ffmpeg** | 音频/视频/GIF 转换 | `sudo apt install ffmpeg` | `brew install ffmpeg` | `winget install ffmpeg` |
| **pandoc** | 文档格式转换 | `sudo apt install pandoc` | `brew install pandoc` | `winget install pandoc` |
| **wkhtmltopdf** (可选) | PDF 输出引擎 | `sudo apt install wkhtmltopdf` | `brew install wkhtmltopdf` | `winget install wkhtmltopdf` |

> **Windows 用户注意**：运行 ShellCode 时会自动检测缺失组件并提示安装方式。图片转换（PNG/JPG/BMP/ICO/WEBP）使用 Go 原生实现，无需额外依赖。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/format_conversion"
```

---

## 极简 API

```go
// 通用转换
err := format_conversion.Convert("input.png", "output.jpg")

// 图片转换
err := format_conversion.ImageConvert("photo.png", "photo.bmp")

// 音频转换（需要 ffmpeg）
err := format_conversion.AudioConvert("sound.wav", "sound.mp3")

// 视频转换
err := format_conversion.VideoConvert("clip.mp4", "clip.mov")

// 文档转换（需要 pandoc）
err := format_conversion.DocumentConvert("readme.md", "readme.docx")

// 批量转换
err := format_conversion.BatchConvert("./images", ".png", ".webp")

// 格式检测
format := format_conversion.GetFormat("file.bin")
name := format_conversion.GetFormatName("file.bin")

// 检查依赖
if !format_conversion.IsPandocAvailable() {
    fmt.Println("请先安装 pandoc")
}
```

---

## 格式检测

### 魔数检测

通过文件头部魔数（Magic Number）自动识别格式：

| 格式 | 魔数 | 检测特征 |
|------|------|----------|
| PNG | `89 50 4E 47` | PNG 文件头 |
| JPG | `FF D8 FF` | SOI 标记 |
| BMP | `42 4D` | "BM" 标识 |
| ICO | `00 00 01 00` | ICO 头 |
| WEBP | `RIFF ... WEBP` | RIFF 容器 + WEBP 标识 |
| WAV | `RIFF ... WAVE` | RIFF 容器 + WAVE 标识 |
| MP3 | `FF FB` / `ID3` | 帧同步字或 ID3 标签 |
| OGG | `OggS` | OGG 页头 |
| MP4 | `... ftyp` | ISO BMFF 容器 |
| MOV | `... moov/mdat/ftyp` | QuickTime 容器 |
| GIF | `GIF8` | GIF 标识 |

文档格式（Markdown/DOC/DOCX/ODT/HTML/RTF/PDF/TXT）通过扩展名检测，魔数检测不可靠。

### 函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `DetectFormat(data)` | 通过魔数检测格式 | `FormatType` |
| `DetectFormatByExt(ext)` | 通过扩展名检测格式 | `FormatType` |
| `GetFormat(path)` | 获取文件格式（优先魔数） | `FormatType` |
| `GetFormatName(path)` | 获取文件格式名称 | `string` |

```go
data, _ := os.ReadFile("unknown.bin")
format := format_conversion.DetectFormat(data)
fmt.Println(format.String()) // 输出: PNG, JPG, WAV, ...

extFormat := format_conversion.DetectFormatByExt(".png") // PNG

pathFormat := format_conversion.GetFormat("file.jpg")  // 读取文件头检测
```

---

## 图片格式转换

图片转换使用 Go 标准库 `image/png`、`image/jpeg` 和 `binary_stream` 自定义编码器实现，无需外部依赖。

### 支持的转换路径

| 转换路径 | 转换类型 | 核心变化 | 关键处理 |
|----------|----------|----------|----------|
| **PNG ↔ BMP** | 无损互转 | 无质量损失，BMP 无压缩体积极大 | BMP 54字节文件头 + BGR 像素数据（从下到上） |
| **PNG → JPG** | 有损转换 | 丢失透明通道，体积大幅减小 | 剥离 Alpha 通道，写入 SOI/EOI 标记 |
| **JPG → PNG** | 有损→无损 | 画质无法恢复，支持透明通道 | 解压 JPG 压缩数据，封装 PNG IHDR/IDAT 块 |
| **PNG/JPG → ICO** | 封装转换 | 多尺寸打包（256-16px） | ICO 文件头 + 16字节目录项 + PNG 编码图片数据 |
| **PNG/JPG → WEBP** | 现代转换 | 体积更小（VP8 容器） | RIFF 容器 + VP8X/VP8L Chunk 结构 |

### 函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `Convert(srcPath, dstPath)` | 通用转换（自动检测格式） | `error` |
| `ImageConvert(srcPath, dstPath)` | 图片格式转换 | `error` |
| `ConvertFile(srcPath, dstPath)` | 文件级转换（按扩展名推断） | `error` |
| `ConvertFileByType(srcPath, dstPath, srcFmt, dstFmt)` | 显式指定类型转换 | `error` |
| `ConvertBytes(data, srcFmt, dstFmt)` | 字节级转换 | `([]byte, error)` |
| `BatchConvert(dir, srcExt, dstExt)` | 批量转换目录下文件 | `error` |

```go
// PNG → JPG
err := format_conversion.Convert("screenshot.png", "screenshot.jpg")

// PNG → BMP
err := format_conversion.ImageConvert("logo.png", "logo.bmp")

// JPG → PNG
err := format_conversion.ImageConvert("photo.jpg", "photo.png")

// PNG → ICO（自动生成多尺寸）
err := format_conversion.Convert("icon.png", "favicon.ico")

// PNG → WEBP
err := format_conversion.Convert("banner.png", "banner.webp")

// 批量转换目录下所有 PNG 为 WEBP
err := format_conversion.BatchConvert("./images", ".png", ".webp")
```

### BMP 文件结构说明

BMP 文件头共 54 字节：

```
偏移  大小  字段
0x00   2    "BM" 标识
0x02   4    文件总大小
0x0A   4    像素数据偏移（=54）
0x0E   4    BITMAPINFOHEADER 大小（=40）
0x12   4    宽度
0x16   4    高度
0x1A   2    色彩平面（=1）
0x1C   2    位深度（=24）
0x22   4    像素数据大小
0x36   N    像素数据（BGR，从最后一行开始）
```

---

## 音频格式转换

音频转换使用 [ffmpeg-go](https://github.com/u2takey/ffmpeg-go) 调用系统 ffmpeg 进行真正的音频编解码，生成标准的 MP3/OGG/WAV 文件。

> **需要安装 ffmpeg**：`sudo apt install ffmpeg` (Linux) / `brew install ffmpeg` (macOS) / `winget install ffmpeg` (Windows)

### 支持的转换路径

| 转换路径 | 转换类型 | 核心变化 | 关键处理 |
|----------|----------|----------|----------|
| **WAV → MP3** | 压缩转换 | 体积约 1/10，丢失人耳不敏感细节 | ffmpeg 编码，自动添加 ID3v2 标签 |
| **WAV → OGG** | 压缩转换 | OGG Vorbis 编码 | ffmpeg 编码，生成标准 OGG 页格式 |
| **MP3 → WAV** | 解压转换 | 体积变大，音质不变 | ffmpeg 解码输出 PCM WAV |
| **OGG → WAV** | 解压转换 | 同 MP3→WAV | ffmpeg 解码 OGG Vorbis 输出 PCM |
| **MP3 ↔ OGG** | 有损互转 | 代际损失（音质二次下降） | 通过 ffmpeg 先解码再重新编码 |

```go
// WAV → MP3
err := format_conversion.AudioConvert("recording.wav", "recording.mp3")

// MP3 → WAV
err := format_conversion.AudioConvert("music.mp3", "music.wav")

// OGG → WAV
err := format_conversion.AudioConvert("sound.ogg", "sound.wav")

// MP3 → OGG（代际损失）
err := format_conversion.AudioConvert("music.mp3", "music.ogg")

// 批量音频转换
err := format_conversion.BatchConvert("./audio", ".wav", ".mp3")
```

---

## 视频格式转换

视频容器转换（MP4↔MOV）使用 `binary_stream` 直接修改 Box 头实现无损秒转。视频转 GIF 使用 ffmpeg-go 进行抽帧编码，提取音频同样使用 ffmpeg。

### 支持的转换路径

| 转换路径 | 转换类型 | 核心变化 | 关键处理 |
|----------|----------|----------|----------|
| **MP4 ↔ MOV** | 容器转换 | 内部编码相同可无损秒转（仅改封装） | 两者基于 ISO BMFF，修改 ftyp Box 的 FourCC |
| **视频 → GIF** | 抽帧转换 | 需要 ffmpeg，提取关键帧转为动态图片 | ffmpeg 抽帧: fps=10, 缩放至 320px |
| **视频 → 音频** | 提取流 | 需要 ffmpeg，剥离音频轨道保存为 WAV/MP3/OGG | ffmpeg `-vn` 参数提取纯音频 |

### 函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `VideoConvert(srcPath, dstPath)` | 视频格式转换 | `error` |
| `ExtractAudioFromVideo(videoPath, audioPath)` | 从视频提取音频（需要 ffmpeg） | `error` |
| `VideoToGIF(videoPath, gifPath)` | 视频转 GIF（需要 ffmpeg） | `error` |

```go
// MP4 → MOV（无损容器转换）
err := format_conversion.VideoConvert("clip.mp4", "clip.mov")

// MOV → MP4
err := format_conversion.VideoConvert("quicktime.mov", "standard.mp4")

// 从视频提取音频轨道（需要 ffmpeg）
err := format_conversion.ExtractAudioFromVideo("movie.mp4", "soundtrack.mp3")

// 视频转 GIF（需要 ffmpeg）
err := format_conversion.VideoToGIF("short.mp4", "animated.gif")
```

### ISO BMFF / QuickTime Box 结构

MP4 和 MOV 都基于 ISO Base Media File Format：

```
Box 结构:
  4 bytes: size (含 header)
  4 bytes: type (FourCC)
  N bytes: data
  
关键 Box:
  ftyp  - 文件类型（MP4: "mp42", MOV: "qt  "）
  moov  - 元数据容器
  mdat  - 媒体数据
```

---

## 文档格式转换

文档转换使用 [pandoc](https://pandoc.org/) 进行格式互转，支持 Markdown、DOCX、ODT、HTML、RTF、PDF、TXT 等格式。

> **需要安装 pandoc**：`sudo apt install pandoc` (Linux) / `brew install pandoc` (macOS) / `winget install pandoc` (Windows)

### 支持的转换路径

| 转换路径 | 转换类型 | 核心变化 |
|----------|----------|----------|
| **Markdown ↔ DOCX/ODT/HTML/RTF/TXT** | 文档互转 | pandoc 通用文档转换 |
| **Markdown → PDF** | 导出 PDF | 需要 PDF 引擎 (wkhtmltopdf/weasyprint/pdflatex) |
| **DOC → DOCX/ODT/HTML/RTF/TXT** | 旧格式迁移 | .doc 只能作为输入，不能作为输出目标 |
| **DOCX ↔ ODT/HTML/RTF/TXT** | 文档互转 | 现代 Office 格式互转 |
| **HTML ↔ TXT/RTF** | 文本/富文本互转 | Web 文档与纯文本/富文本转换 |
| **PDF → TXT** | 文本提取 | 从 PDF 提取纯文本内容 |

### 注意事项

- **不支持输出 `.doc`**：pandoc 不支持将 `.doc` 作为输出格式，请使用 `.docx` 代替
- **PDF 输出需要额外引擎**：pandoc 输出 PDF 需要 `wkhtmltopdf`、`weasyprint` 或 `pdflatex` 等 PDF 引擎
- **通过扩展名检测**：文档格式的源/目标类型通过文件扩展名推断

### 函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `DocumentConvert(srcPath, dstPath)` | 文档格式转换 | `error` |
| `IsPandocAvailable()` | 检查 pandoc 是否已安装 | `bool` |

```go
// Markdown → DOCX
err := format_conversion.DocumentConvert("readme.md", "readme.docx")

// Markdown → HTML
err := format_conversion.DocumentConvert("readme.md", "readme.html")

// Markdown → PDF（需要 PDF 引擎）
err := format_conversion.DocumentConvert("report.md", "report.pdf")

// DOCX → Markdown
err := format_conversion.DocumentConvert("document.docx", "document.md")

// HTML → TXT
err := format_conversion.DocumentConvert("page.html", "page.txt")

// PDF → TXT
err := format_conversion.DocumentConvert("paper.pdf", "paper.txt")

// 批量文档转换
err := format_conversion.BatchConvert("./docs", ".md", ".docx")

// 检查 pandoc 是否可用
if format_conversion.IsPandocAvailable() {
    // pandoc 已安装
}
```

---

## 便捷函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `SupportedFormats()` | 所有支持格式列表 | `[]string` |
| `SupportedConversions()` | 支持的转换列表 | `[]string` |
| `IsPandocAvailable()` | 检查 pandoc 是否已安装 | `bool` |

```go
for _, f := range format_conversion.SupportedFormats() {
    fmt.Println(f)
}
// 输出: PNG, JPG/JPEG, BMP, ICO, WEBP, GIF, WAV, MP3, OGG, MP4, MOV,
//       Markdown, DOC, DOCX, ODT, HTML, RTF, PDF, TXT

for _, c := range format_conversion.SupportedConversions() {
    fmt.Println(c)
}
// 输出: PNG ↔ BMP, PNG → JPG, ..., Markdown ↔ DOCX/ODT/HTML/RTF/TXT, ...
```

---

## 典型使用场景

### 场景1：网站图片优化

```go
// 将设计稿 PNG 批量转换为 JPG（减小体积）
format_conversion.BatchConvert("./designs", ".png", ".jpg")

// 生成网站图标
format_conversion.Convert("logo.png", "favicon.ico")

// 生成 WebP 格式（现代浏览器更小体积）
format_conversion.BatchConvert("./photos", ".png", ".webp")
```

### 场景2：音频格式统一

```go
// 将多种音频格式统一为 WAV 进行后续处理
files := []string{"intro.mp3", "voice.ogg", "effect.wav"}
for _, f := range files {
    dst := strings.TrimSuffix(f, filepath.Ext(f)) + ".wav"
    format_conversion.Convert(f, dst)
}
```

### 场景3：视频处理流水线

```go
// 视频格式标准化
format_conversion.Convert("raw.MOV", "standard.mp4")

// 提取音频进行语音识别
format_conversion.ExtractAudioFromVideo("meeting.mp4", "speech.wav")

// 生成预览 GIF
format_conversion.VideoToGIF("demo.mp4", "preview.gif")
```

### 场景4：自动化媒体转换

```go
// 使用 Bytes 转换（不经过文件系统）
srcData, _ := os.ReadFile("input.png")
result, err := format_conversion.ConvertBytes(
    srcData,
    format_conversion.FormatPNG,
    format_conversion.FormatJPG,
)
if err == nil {
    // result 可以直接用于网络传输或存储
    httpWriter.Write(result)
}
```

### 场景5：文档格式批量迁移

```go
// 将所有 Markdown 文档转为 DOCX
format_conversion.BatchConvert("./docs", ".md", ".docx")

// 从 PDF 提取文本内容
format_conversion.Convert("report.pdf", "report.txt")
```

---

## Shellcode - 交互式格式转换 Shell

`ShellCode` 函数启动一个基于 bash 的交互式格式转换 shell，提示符为 `fmt>>`，支持格式检测、文件转换、批量处理等操作，同时可以直接使用系统命令（ls、cat、echo 等）。

启动时自动进行依赖检查，显示 pandoc、ffmpeg、ImageMagick 的安装状态。**Windows 用户**如果缺少组件会收到明确的安装提示。

### 启动方式

```go
// 基础交互式 Shell（自动依赖检查）
format_conversion.ShellCode()

// 脚本执行模式
err := format_conversion.ShellcodeScript("commands.txt")

// 带历史记录（功能与基础版相同）
format_conversion.ShellcodeWithHistory()
```

### 命令一览

| 命令 | 说明 | 示例 |
|------|------|------|
| `fmt convert <src> <dst>` | 单个文件格式转换 | `fmt convert icon.png icon.ico` |
| `fmt batch <dir> <srcExt> <dstExt>` | 批量转换目录下文件 | `fmt batch ./img .png .webp` |
| `fmt info <path>` | 查看文件格式信息 | `fmt info photo.jpg` |
| `fmt detect <path>` | 检测文件真实格式（魔数 + 扩展名） | `fmt detect unknown.bin` |
| `fmt formats` | 列出所有支持格式和转换 | `fmt formats` |
| `fmt pandoc` | 检查 pandoc 安装状态及使用提示 | `fmt pandoc` |
| `fmt help` | 显示帮助 | `fmt help` |
| `exit` / `quit` / `q` | 退出 | `exit` |

### 依赖检查示例

启动 ShellCode 时会自动输出依赖状态：

```
依赖检查:
  pandoc: 已安装
  ImageMagick (magick): 已安装
  ffmpeg: 已安装
```

在 Windows 上缺失组件时会显示：

```
依赖检查:
  pandoc: 未安装 (文档转换功能将不可用)
  ImageMagick (convert): 已安装
  ffmpeg: 未安装 (音频/视频/GIF 转换功能将不可用)

+----------------------------------------------------------+
|  Windows 用户注意:                                       |
|  部分功能需要额外安装以下组件才能完整体验:               |
|    pandoc: https://pandoc.org/installing.html            |
|             winget install pandoc                        |
|    ffmpeg: https://ffmpeg.org/download.html              |
|             winget install ffmpeg                        |
+----------------------------------------------------------+
```

### 使用示例

```bash
$ go run ./examples/main.go
依赖检查:
  pandoc: 已安装
  ffmpeg: 已安装
  ImageMagick: 已安装

+----------------------------------------------------------+
|     fmt shell  -  文件格式转换工具                       |
+----------------------------------------------------------+

  help              查看帮助
  list              列出支持的格式
  fmt convert <src> <dst>  转换文件
  fmt batch <dir> <src> <dst>  批量转换
  fmt info <file>   查看文件信息
  fmt detect <file> 检测文件格式
  fmt pandoc        检查 pandoc 状态
  exit              退出
  （可直接使用系统命令: ls, echo, pwd, cat ...）

fmt>> fmt convert logo.png favicon.ico
正在转换 logo.png -> favicon.ico ...
转换成功: logo.png (PNG) -> favicon.ico (ICO)

fmt>> fmt convert readme.md readme.docx
正在转换 readme.md -> readme.docx ...
转换成功: readme.md (Markdown) -> readme.docx (DOCX)

fmt>> fmt batch ./docs .md .docx
批量转换完成: 15 个文件 .md -> .docx

fmt>> fmt detect unknown.bin
文件: unknown.bin
  魔数检测: PNG
  扩展名检测: UNKNOWN
  警告: 魔数与扩展名不一致!

fmt>> fmt formats
支持的格式:
  - PNG
  - JPG/JPEG
  - BMP
  - ICO
  - WEBP
  - GIF
  - WAV
  - MP3
  - OGG
  - MP4
  - MOV
  - Markdown
  - DOC
  - DOCX
  - ODT
  - HTML
  - RTF
  - PDF
  - TXT

支持的转换:
  - PNG ↔ BMP
  - PNG → JPG
  ...
  - Markdown ↔ DOCX/ODT/HTML/RTF/TXT
  ...

fmt>> ls test/
test.png  test.docx  test.md

fmt>> exit
```

### 脚本执行模式

`ShellCodeScript` 支持从脚本文件读取命令并自动执行：

```bash
# batch_convert.txt
# 批量转换图片为 WebP
batch ./originals .png .webp
batch ./originals .jpg .webp
# 转换图标为 ICO
convert brand/logo.png brand/favicon.ico
# 转换音频
batch ./audio .wav .mp3
# 转换文档
batch ./docs .md .docx
```

```go
err := format_conversion.ShellcodeScript("batch_convert.txt")
if err != nil {
    log.Fatal(err)
}
```

### 代码集成示例

```go
package main

import "github.com/xiguayiqiu/gyscan_code/format_conversion"

func main() {
    // 方式1：交互式 Shell
    format_conversion.ShellCode()

    // 方式2：脚本批量转换
    if err := format_conversion.ShellcodeScript("convert_script.txt"); err != nil {
        log.Fatal(err)
    }

    // 方式3：直接调用 API
    format_conversion.Convert("image.png", "image.webp")
    format_conversion.DocumentConvert("readme.md", "readme.docx")
}
```

---

## 格式检测流程

```
输入文件
    │
    ├─ 尝试魔数检测（读取文件头 12 字节）
    │   ├─ "BM"               → BMP
    │   ├─ 0x89PNG            → PNG
    │   ├─ 0xFFD8FF           → JPG
    │   ├─ 0x00000100         → ICO
    │   ├─ "RIFF...WEBP"      → WEBP
    │   ├─ "RIFF...WAVE"      → WAV
    │   ├─ 0xFFFB / "ID3"     → MP3
    │   ├─ "OggS"             → OGG
    │   ├─ "...ftyp"          → MP4
    │   ├─ "GIF8"             → GIF
    │   └─ 未知               → 扩展名检测
    │
    └─ 扩展名检测
        ├─ .png   → PNG
        ├─ .jpg   → JPG
        ├─ .wav   → WAV
        ├─ .md    → Markdown
        ├─ .doc   → DOC
        ├─ .docx  → DOCX
        ├─ .odt   → ODT
        ├─ .html  → HTML
        ├─ .rtf   → RTF
        ├─ .pdf   → PDF
        ├─ .txt   → TXT
        └─ 未知   → UNKNOWN
```

---

## License

Apache License 2.0