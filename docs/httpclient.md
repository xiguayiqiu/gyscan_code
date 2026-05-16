# httpclient - 模拟真实浏览器的 HTTP 请求库

对标 Python `requests` 库设计的 Go HTTP 客户端，专为网络安全渗透测试场景打造。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/httpclient"
```

---

## 极简 API（与 Python requests 完全一致）

```go
// 一行代码下载/获取内容
httpclient.Save("https://example.com/video.mp4", "video.mp4")  // 下载文件
data := httpclient.Fetch("https://example.com")  // 获取内容（自动识别二进制）

// 获取响应对象，Python风格
resp := httpclient.FetchResponse("https://example.com")
resp.StatusCode()  // 状态码
resp.Text()        // 响应文本
resp.Ok()          // 是否成功
resp.Headers()     // 响应头
resp.Cookies()     // Cookie
resp.Url()         // 最终URL
resp.Reason()      // 状态原因
resp.Bytes()       // 原始字节
resp.Encoding()    // 检测到的编码

// 指定编码解析
resp.TextWithEncoding("gbk")
resp.TextWithEncoding("gb2312")

// 链式客户端
resp := httpclient.SimpleClient().
    UA("Mozilla/5.0").
    Cookie("session", "abc").
    Encoding("gbk").
    Get("https://example.com")
```

---

## 快速函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `httpclient.Fetch(url)` | GET请求（自动识别二进制） | `[]byte` |
| `httpclient.FetchText(url)` | GET请求（返回文本） | `string` |
| `httpclient.FetchResponse(url)` | GET响应对象 | `*SimpleResponse` |
| `httpclient.Save(url, filename)` | 下载文件并保存 | `error` |
| `httpclient.SaveData(filename, data)` | 保存字节数据 | `error` |
| `httpclient.SaveText(filename, text)` | 保存文本 | `error` |
| `httpclient.Format(text)` | 格式化JSON/HTML | `string` |
| `httpclient.SimpleClient()` | 创建客户端 | `*Simple` |
| `httpclient.Type(url)` | 获取资源并自动分类 | `*TypedResource` |

---

## SimpleResponse 响应对象

```go
resp := httpclient.FetchResponse("https://example.com")

resp.StatusCode()              // int - 状态码 200/404/500
resp.Ok()                     // bool - 是否2xx成功
resp.Text()                   // string - 响应文本（自动编码检测）
resp.Bytes()                   // []byte - 原始字节
resp.ContentType()            // string - Content-Type值
resp.IsBinary()               // bool - 是否二进制内容
resp.TextWithEncoding("gbk")  // string - 指定编码解析
resp.Headers()                // map[string]string - 响应头
resp.Cookies()                // map[string]string - Cookie
resp.Url()                    // string - 最终URL
resp.Reason()                 // string - 状态原因 "OK", "Not Found"
resp.Encoding()               // string - 检测到的编码 "utf-8", "gbk", "gb2312"
resp.Format()                 // string - 格式化JSON/HTML输出
resp.Save("output.html")      // error - 保存响应内容到文件
```

---

## Simple 客户端链式配置

```go
client := httpclient.SimpleClient()

// 配置
client.Timeout(10 * time.Second)
client.Proxy("http://127.0.0.1:8080")
client.UA("Mozilla/5.0 Chrome/125")
client.Header("Authorization", "Bearer token")
client.Cookie("session", "abc123")
client.Cookies(map[string]string{"a": "1", "b": "2"})
client.Encoding("gbk")  // 指定默认编码

// 请求
resp := client.Get(url)
resp := client.Post(url, data)
resp := client.Put(url, data)
resp := client.Delete(url)
resp := client.Head(url)
```

---

## 编码支持

### 自动检测
自动从 `Content-Type` header 或页面 meta 标签检测编码，支持：
- UTF-8, GBK, GB2312, Big5, Shift-JIS, EUC-KR, ISO-8859-1 等

### 指定编码
```go
// 方法1: 请求时指定编码
resp := httpclient.SimpleClient().
    Encoding("gbk").
    Get("https://example.com")
fmt.Println(resp.Text())

// 方法2: 响应对象指定编码解析
resp := httpclient.FetchResponse("https://example.com")
fmt.Println(resp.TextWithEncoding("gbk"))
fmt.Println(resp.TextWithEncoding("gb2312"))
```

---

## 格式化输出

自动识别JSON和HTML进行美化输出。

```go
// 格式化JSON
resp := httpclient.FetchResponse("https://httpbin.org/get")
fmt.Println(resp.Format())

// 格式化HTML
resp := httpclient.FetchResponse("https://httpbin.org/html")
fmt.Println(resp.Format())

// 全局格式化函数
text := httpclient.Format(`{"name":"test"}`)
fmt.Println(text)
```

---

## 保存文件

```go
// 一行代码下载视频/图片/任意文件
httpclient.Save("https://example.com/video.mp4", "video.mp4")
httpclient.Save("https://example.com/image.png", "image.png")

// 获取响应后保存
resp := httpclient.FetchResponse("https://example.com")
resp.Save("output.html")

// 保存字节数据
httpclient.SaveData("data.bin", []byte{1, 2, 3})

// 保存文本
httpclient.SaveText("readme.txt", "Hello World")
```

---

## 资源类型识别

自动识别并分类 Web 资源类型，支持 JSON 自动解析。

```go
res := httpclient.Type("https://api.example.com/user")
fmt.Println(res.Kind)        // json / html / image / pdf / text / binary ...
fmt.Println(res.Kind.String()) // "json"
fmt.Println(res.StatusCode) // 200
fmt.Println(res.ContentType) // "application/json"
fmt.Println(res.Size)        // 响应体大小
fmt.Println(res.Text)        // 原始响应文本
fmt.Println(res.Parsed)      // JSON自动解析为 map/array（仅 KindJSON 时有值）
```

### 资源类型一览

| 类型 | 说明 |
|------|------|
| `KindHTML` | text/html |
| `KindJSON` | application/json |
| `KindXML` | application/xml, text/xml |
| `KindImage` | image/* |
| `KindAudio` | audio/* |
| `KindVideo` | video/* |
| `KindPDF` | application/pdf |
| `KindText` | text/plain 及其他文本类型 |
| `KindBinary` | 二进制流（检测到 null 字节） |
| `KindUnknown` | 无法识别 |

### 链式客户端使用

```go
res := httpclient.SimpleClient().
    UA("Mozilla/5.0").
    Timeout(10 * time.Second).
    Type("https://example.com")

switch res.Kind {
case httpclient.KindJSON:
    fmt.Println("JSON数据:", res.Parsed)
case httpclient.KindHTML:
    fmt.Println("HTML页面:", res.Text[:100])
case httpclient.KindImage:
    fmt.Printf("图片: %d bytes\n", res.Size)
}
```

---

## 与 Python requests 对比

### Python
```python
import requests

r = requests.get("https://example.com")
print(r.text)
print(r.encoding)
r.encoding = 'gbk'
print(r.text)
```

### Go (完全一致的使用体验)
```go
resp := httpclient.FetchResponse("https://example.com")
fmt.Println(resp.Text())
fmt.Println(resp.Encoding())

resp = httpclient.SimpleClient().Encoding("gbk").Get("https://example.com")
fmt.Println(resp.Text())
```

---

## License

Apache License 2.0