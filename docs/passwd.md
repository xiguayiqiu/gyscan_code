# passwd - 密码生成库

网络安全渗透测试的密码生成工具库，提供多种密码生成策略，支持自定义字符集和安全随机数生成。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/passwd"
```

---

## 函数总览

| 函数 | 说明 |
|------|------|
| `passwd.Generate(length)` | 默认密码（大写+小写+数字） |
| `passwd.GenerateStrong(length)` | 强密码（大写+小写+数字+特殊字符） |
| `passwd.GenerateN(length, count)` | 批量生成多个默认密码 |
| `passwd.GenerateWith(length, upper, lower, digit, special)` | 自定义字符集 |
| `passwd.CUPP(profile)` | 社工密码字典生成 |
| `passwd.CUPPInfo(profile)` | 社工密码统计信息 |
| `passwd.LeetSpeak(s)` | 转换为 Leet 语 |
| `passwd.Capitalize(s)` | 首字母大写 |
| `passwd.Reverse(s)` | 字符串反转 |

---

## 字符集说明

内部预定义了以下字符集：

| 类型 | 内容 |
|------|------|
| 小写字母 | `abcdefghijklmnopqrstuvwxyz` |
| 大写字母 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| 数字 | `0123456789` |
| 特殊字符 | `!@#$%^&*()-_=+[]{}|;:,.<>?/~` |

使用 `crypto/rand` 安全随机数生成器，确保密码的不可预测性。

---

## 函数详解

### Generate - 默认密码

生成包含大写字母、小写字母和数字的随机密码。

```go
pwd := passwd.Generate(12)
fmt.Println(pwd)
// 输出示例: "aK8xR3mP7vQ2"
```

```go
pwd := passwd.Generate(16)
fmt.Println(pwd)
// 输出示例: "X9nB4kL1pQ6wE3rT"
```

```go
pwd := passwd.Generate(24)
fmt.Println(pwd)
// 输出示例: "mK7vR2xN9qL4pW8bT5cF1hD"
```

### GenerateStrong - 强密码

在默认密码基础上增加特殊字符，适合需要高安全性的场景。

```go
pwd := passwd.GenerateStrong(16)
fmt.Println(pwd)
// 输出示例: "aX3k@9mQ&vR2pL#n"
```

```go
pwd := passwd.GenerateStrong(20)
fmt.Println(pwd)
// 输出示例: "K8x!R3mP$vQ2wN9bL%p"
```

```go
pwd := passwd.GenerateStrong(32)
fmt.Println(pwd)
// 输出示例: "mK7v@RxN9q!LpW4b$TcF1hD%jY5sG&zX"
```

### GenerateN - 批量生成

一次性生成多个密码，返回字符串切片。适合在用户注册、批量创建账号等场景使用。

```go
pwds := passwd.GenerateN(12, 5)
for i, pwd := range pwds {
    fmt.Printf("%d: %s\n", i+1, pwd)
}
// 输出示例:
// 1: aK3xR8mP2vQ7
// 2: L9nB4kX1pW6
// 3: cF5hD8jY2sG
// 4: R7tZ4mN9qL3
// 5: wE6rT5yU1iO
```

### GenerateWith - 自定义字符集

完全控制密码中包含的字符类型，每个类型以 bool 参数控制。

参数顺序：`upper, lower, digit, special`

#### 纯数字密码

```go
pwd := passwd.GenerateWith(8, false, false, true, false)
fmt.Println(pwd)
// 输出示例: "39472016"
```

#### 纯字母密码

```go
pwd := passwd.GenerateWith(10, true, true, false, false)
fmt.Println(pwd)
// 输出示例: "aKxRmPvQnB"
```

#### 大写字母 + 数字

```go
pwd := passwd.GenerateWith(12, true, false, true, false)
fmt.Println(pwd)
// 输出示例: "A3K9X7R2M5P1"
```

#### 小写字母 + 特殊字符

```go
pwd := passwd.GenerateWith(14, false, true, false, true)
fmt.Println(pwd)
// 输出示例: "a$x@r#m%p&v*q"
```

---

## 使用场景

### 生成用户密码

```go
func generateUserPassword(username string) string {
    pwd := passwd.GenerateStrong(16)
    fmt.Printf("用户 %s 的初始密码: %s\n", username, pwd)
    return pwd
}
```

### 批量生成测试账号

```go
func generateTestAccounts(count int) []struct {
    Username string
    Password string
} {
    accounts := make([]struct {
        Username string
        Password string
    }, count)
    pwds := passwd.GenerateN(12, count)
    for i := 0; i < count; i++ {
        accounts[i] = struct {
            Username string
            Password string
        }{
            Username: fmt.Sprintf("test%d", i+1),
            Password: pwds[i],
        }
    }
    return accounts
}
```

### CUPP - 社工密码字典

基于目标个人信息生成社工密码字典，用于渗透测试中的口令爆破场景。

```go
profile := &passwd.Profile{
    FirstName: "张三",
    LastName:  "zhangsan",
    Nickname:  "zs",
    BirthDate: "1995-06-15",
    Partner:   "lisi",
    Pet:       "wangcai",
    Company:   "acme",
    Keywords:  []string{"admin", "boss"},
}

pwds := passwd.CUPP(profile)
fmt.Println(passwd.CUPPInfo(profile))
// 输出: CUPP: 942 passwords generated from profile

for _, pwd := range pwds[:10] {
    fmt.Println(pwd)
}
// 输出示例:
// zs
// ZHANGSAN
// Zhangsan
// nasgnahz
// acme
// ACME
// wangcai
// lisi
// 06
// 15
```

### LeetSpeak - Leet语转换

```go
fmt.Println(passwd.LeetSpeak("password"))
// 输出: p4ssw0rd

fmt.Println(passwd.LeetSpeak("admin"))
// 输出: 4dm1n
```

### Capitalize - 首字母大写

```go
fmt.Println(passwd.Capitalize("hello"))
// 输出: Hello
```

### Reverse - 字符串反转

```go
fmt.Println(passwd.Reverse("hello"))
// 输出: olleh
```

### 密码强度分级

```go
func generateByLevel(level string) string {
    switch level {
    case "low":
        return passwd.GenerateWith(8, false, false, true, false) // 纯数字
    case "medium":
        return passwd.Generate(12) // 字母+数字
    case "high":
        return passwd.GenerateStrong(20) // 字母+数字+特殊字符
    default:
        return passwd.Generate(16)
    }
}

func main() {
    fmt.Println("低:  ", generateByLevel("low"))
    fmt.Println("中:  ", generateByLevel("medium"))
    fmt.Println("高:  ", generateByLevel("high"))
}
// 输出示例:
// 低:   48375910
// 中:   aK3xR8mP2vQ7
// 高:   X9n@B4k!L1pQ$wE6*rT
```

---

## License

Apache License 2.0
