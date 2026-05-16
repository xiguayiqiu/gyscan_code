# scanner - 网络安全扫描模块

网络安全渗透测试的扫描模块，提供子域名枚举、目录扫描和端口扫描功能。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/scanner"
```

---

## 极简 API

```go
// 扫描目录
results := scanner.Scan("https://example.com")

// 扫描子域名
results := scanner.Subs("example.com")

// Ping检测
alive := scanner.Ping("example.com")

// 端口扫描
results := scanner.ScanPorts("example.com", []int{80, 443, 22})

// 链式配置
scanner.New().
    Url("https://example.com").
    Threads(50).
    Scan()
```

---

## 快速函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `scanner.Scan(url)` | 扫描目录 | `[]string` |
| `scanner.Subs(url)` | 扫描子域名 | `[]string` |
| `scanner.Ping(host)` | ICMP Ping检测 | `bool` |
| `scanner.ScanPorts(host, ports)` | 端口扫描 | `[]*PortResult` |
| `scanner.QuickScan(host)` | 快速端口扫描 | `[]*PortResult` |
| `scanner.TopPorts(host, n)` | TOP N端口扫描 | `[]*PortResult` |
| `scanner.Wordlist(filename)` | 读取字典文件 | `[]string` |
| `scanner.New()` | 创建扫描器 | `*Scanner` |

---

## 目录扫描

```go
// 一行代码扫描目录
results := scanner.Scan("https://example.com")

// 链式配置
results := scanner.New().
    Url("https://example.com").
    Threads(50).
    Timeout(10 * time.Second).
    Verbose(true).
    Find()
```

---

## 子域名发现

```go
// 一行代码扫描子域名
results := scanner.Subs("example.com")

// 链式配置
results := scanner.New().
    Url("https://example.com").
    Threads(100).
    Subs()
```

---

## 端口扫描

支持多种扫描协议：TCP Connect、FIN、ACK、UDP

```go
// Ping检测主机存活
alive := scanner.Ping("baidu.com")

// 扫描指定端口
results := scanner.ScanPorts("baidu.com", []int{80, 443, 22, 21, 3306})

// 快速扫描常用端口
results := scanner.QuickScan("baidu.com")

// 扫描TOP N端口
results := scanner.TopPorts("baidu.com", 10)

// 链式配置（支持TCP/FIN/ACK/UDP）
results := scanner.NewPortScanner().
    Host("baidu.com").
    Ports([]int{80, 443, 22, 21}).
    Protocol("tcp").
    Threads(100).
    Timeout(3 * time.Second).
    Scan()
```

### PortResult 结果对象

```go
for _, r := range results {
    r.Host      // 主机IP
    r.Port      // 端口号
    r.Protocol  // 协议 tcp/fin/ack/udp
    r.Status    // 状态 open/closed/filtered
    r.Latency   // 延迟
}
```

---

## 扫描器配置

### Scanner (目录/子域名)

```go
s := scanner.New()
s.Url("https://example.com")     // 设置目标
s.Threads(50)                   // 并发数，默认30
s.Timeout(10 * time.Second)     // 超时
s.Verbose(true)                 // 详细输出
s.Dirs()                       // 扫描目录
s.Subs()                       // 扫描子域名
s.Find()                       // 扫描目录（别名）
```

### PortScanner (端口)

```go
p := scanner.NewPortScanner()
p.Host("example.com")           // 设置目标
p.Ports([]int{80, 443})        // 端口列表
p.Protocol("tcp")              // 协议 tcp/fin/ack/udp
p.Threads(100)                 // 并发数
p.Timeout(3 * time.Second)      // 超时
p.Scan()                        // 执行扫描
p.Ping()                        // Ping检测
```

---

## 字典文件读取

支持读取 `.lst`, `.txt`, `.db`, `.dict`, `.wordlist` 等格式的字典文件

```go
// 读取字典文件
words := scanner.Wordlist("/path/to/wordlist.txt")

// 读取字典（别名）
words := scanner.LoadDict("/path/to/wordlist.txt")
words := scanner.Lines("/path/to/wordlist.txt")

// 读取并处理错误
words, err := scanner.ReadWordlist("/path/to/wordlist.txt")
```

**示例：用于扫描**

```go
// 使用自定义端口列表扫描
results := scanner.ScanPorts("example.com", scanner.Wordlist("ports.txt"))

// 使用自定义子域名字典
results := scanner.SubsWithList("example.com", scanner.Wordlist("subs.txt"))

// 使用自定义目录字典
results := scanner.DirsWithList("https://example.com", scanner.Wordlist("dirs.txt"))
```

---

## License

Apache License 2.0