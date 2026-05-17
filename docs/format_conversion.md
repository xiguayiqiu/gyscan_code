# format_conversion - 文件格式转换库

基于 `binary_stream` 二进制流操作库，实现图片、音频、视频文件格式之间的互转。通过魔数检测自动识别源格式，支持文件级和字节级转换。

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

// 音频转换
err := format_conversion.AudioConvert("sound.wav", "sound.mp3")

// 视频转换
err := format_conversion.VideoConvert("clip.mp4", "clip.mov")

// 批量转换
err := format_conversion.BatchConvert("./images", ".png", ".webp")

// 格式检测
format := format_conversion.GetFormat("file.bin")
name := format_conversion.GetFormatName("file.bin")
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

### 支持的转换路径

| 转换路径 | 转换类型 | 核心变化 | 关键处理 |
|----------|----------|----------|----------|
| **WAV → MP3** | 压缩转换 | 体积约 1/10，丢失人耳不敏感细节 | 写入 MP3 帧头 0xFFFB，构建 ID3 标签 |
| **WAV → OGG** | 压缩转换 | OGG 页格式封装 | 构建 OGG Page Header，计算 CRC32 校验 |
| **MP3 → WAV** | 解压转换 | 体积变大，音质不变 | 构建 RIFF/WAVE 文件头，写入 fmt + data 块 |
| **OGG → WAV** | 解压转换 | 同 MP3→WAV | 解析 OGG 页头获取采样率、声道信息 |
| **MP3 ↔ OGG** | 有损互转 | 代际损失（音质二次下降） | 先解压为 WAV 中间格式，再编码为目标格式 |

### WAV 文件结构说明

```
偏移  大小  字段
0x00   4    "RIFF"
0x04   4    文件大小-8
0x08   4    "WAVE"
0x0C   4    "fmt "
0x10   4    fmt 块大小（=16）
0x14   2    音频格式（=1 PCM）
0x16   2    声道数
0x18   4    采样率
0x1C   4    字节率
0x20   2    块对齐
0x22   2    位深度
0x24   4    "data"
0x28   4    数据大小
0x2C   N    PCM 数据
```

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

### MP3 ID3 标签结构

MP3 文件可能包含 ID3v2 标签（文件头部）或 ID3v1 标签（文件尾部 128 字节）：

```go
// ID3v2 头部
// 偏移 0: "ID3" (3 bytes)
// 偏移 3: 版本 (2 bytes)
// 偏移 5: 标志 (1 byte)
// 偏移 6: 大小 (4 bytes, sync-safe integer)
```

---

## 视频格式转换

### 支持的转换路径

| 转换路径 | 转换类型 | 核心变化 | 关键处理 |
|----------|----------|----------|----------|
| **MP4 ↔ MOV** | 容器转换 | 内部编码相同可无损秒转（仅改封装） | 两者基于 ISO BMFF，修改 ftyp Box 的 FourCC |
| **视频 → GIF** | 抽帧转换 | 提取关键帧转为动态图片 | 封装 GIF 图形控制扩展块，设置调色板 |
| **视频 → 音频** | 提取流 | 剥离音频轨道保存为 WAV/MP3/OGG | 解析 moov 原子，定位音频 mdat 数据 |

### 函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `VideoConvert(srcPath, dstPath)` | 视频格式转换 | `error` |
| `ExtractAudioFromVideo(videoPath, audioPath)` | 从视频提取音频 | `error` |
| `VideoToGIF(videoPath, gifPath)` | 视频转 GIF | `error` |

```go
// MP4 → MOV（无损容器转换）
err := format_conversion.VideoConvert("clip.mp4", "clip.mov")

// MOV → MP4
err := format_conversion.VideoConvert("quicktime.mov", "standard.mp4")

// 从视频提取音频轨道
err := format_conversion.ExtractAudioFromVideo("movie.mp4", "soundtrack.mp3")

// 视频转 GIF
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

## 便捷函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `SupportedFormats()` | 所有支持格式列表 | `[]string` |
| `SupportedConversions()` | 支持的转换列表 | `[]string` |

```go
for _, f := range format_conversion.SupportedFormats() {
    fmt.Println(f)
}
// 输出: PNG, JPG/JPEG, BMP, ICO, WEBP, WAV, MP3, OGG, MP4, MOV, GIF

for _, c := range format_conversion.SupportedConversions() {
    fmt.Println(c)
}
// 输出: PNG ↔ BMP, PNG → JPG, ...
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

---

## Shellcode - 交互式格式转换 Shell

`Shellcode` 函数启动一个交互式格式转换 shell，提示符为 `fmt>>`，支持格式检测、文件转换、批量处理等操作。

### 启动方式

```go
// 基础交互式 Shell
format_conversion.Shellcode()

// 脚本执行模式
err := format_conversion.ShellcodeScript("commands.txt")

// 带历史记录（功能与基础版相同）
format_conversion.ShellcodeWithHistory()
```

### 命令一览

| 命令 | 说明 | 示例 |
|------|------|------|
| `convert <src> <dst>` | 单个文件格式转换 | `convert icon.png icon.ico` |
| `batch <dir> <srcExt> <dstExt>` | 批量转换目录下文件 | `batch ./img .png .webp` |
| `info <path>` | 查看文件格式信息 | `info photo.jpg` |
| `detect <path>` | 检测文件真实格式（魔数 + 扩展名） | `detect unknown.bin` |
| `formats` | 列出所有支持格式和转换 | `formats` |
| `help` | 显示帮助 | `help` |
| `exit` / `quit` / `q` | 退出 | `exit` |

### 使用示例

```bash
$ go run -exec "format_conversion.Shellcode"
=== 格式转换 Shell ===
输入 help 查看帮助，输入 exit 退出

fmt>> info logo.png
文件: logo.png
  大小: 24576 bytes
  格式: PNG

fmt>> convert logo.png favicon.ico
正在转换 logo.png -> favicon.ico ...
转换成功: logo.png (PNG) -> favicon.ico (ICO)

fmt>> batch ./photos .png .webp
format_conversion: batch converted 15 files .png -> .webp

fmt>> detect unknown.bin
文件: unknown.bin
  魔数检测: PNG
  扩展名检测: UNKNOWN
  ⚠ 魔数与扩展名不一致!

fmt>> formats
支持的格式:
  - PNG
  - JPG/JPEG
  - BMP
  - ICO
  - WEBP
  - WAV
  - MP3
  - OGG
  - MP4
  - MOV
  - GIF

支持的转换:
  - PNG ↔ BMP
  - PNG → JPG
  ...

fmt>> exit
再见!
```

### 脚本执行模式

`ShellcodeScript` 支持从脚本文件读取命令并自动执行：

```bash
# batch_convert.txt
# 批量转换图片为 WebP
batch ./originals .png .webp
batch ./originals .jpg .webp
# 转换图标为 ICO
convert brand/logo.png brand/favicon.ico
# 转换音频
batch ./audio .wav .mp3
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
    format_conversion.Shellcode()

    // 方式2：脚本批量转换
    if err := format_conversion.ShellcodeScript("convert_script.txt"); err != nil {
        log.Fatal(err)
    }

    // 方式3：直接调用 API
    format_conversion.Convert("image.png", "image.webp")
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
        └─ 未知   → UNKNOWN
```

---

## License

Apache License 2.0