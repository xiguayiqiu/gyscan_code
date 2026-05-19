# encoding - 编码解码开发库

网络安全渗透测试中的编码解码开发库，提供 Base 家族、URL、Hex、HTML 实体、古典密码以及 JS 混淆编码等功能。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/encoding"
```

---

## 1. Base 家族编码

### 函数列表

| 函数 | 说明 |
|------|------|
| `Base16Encode(data []byte) string` | Base16 编码 |
| `Base16Decode(s string) ([]byte, error)` | Base16 解码 |
| `Base32Encode(data []byte) string` | Base32 编码（标准 RFC 4648） |
| `Base32Decode(s string) ([]byte, error)` | Base32 解码（自动补齐 =） |
| `Base32HexEncode(data []byte) string` | Base32Hex 编码（扩展十六进制字母表） |
| `Base32HexDecode(s string) ([]byte, error)` | Base32Hex 解码（自动补齐 =） |
| `Base64Encode(data []byte) string` | Base64 编码（标准） |
| `Base64Decode(s string) ([]byte, error)` | Base64 解码（标准） |
| `Base64URLEncode(data []byte) string` | Base64 URL 安全编码 |
| `Base64URLDecode(s string) ([]byte, error)` | Base64 URL 安全解码 |
| `Base85Encode(data []byte) string` | Base85（Ascii85）编码 |
| `Base85Decode(s string) ([]byte, error)` | Base85（Ascii85）解码 |

### 使用示例

```go
data := []byte("Hello, World!")

// Base16
enc := encoding.Base16Encode(data)
dec, _ := encoding.Base16Decode(enc)

// Base32
enc = encoding.Base32Encode(data)
dec, _ = encoding.Base32Decode(enc)

// Base64
enc = encoding.Base64Encode(data)
dec, _ = encoding.Base64Decode(enc)

// Base64 URL-Safe
enc = encoding.Base64URLEncode(data)
dec, _ = encoding.Base64URLDecode(enc)

// Base85
enc = encoding.Base85Encode(data)
dec, _ = encoding.Base85Decode(enc)
```

---

## 2. URL 编码

### 函数列表

| 函数 | 说明 |
|------|------|
| `URLEncode(s string) string` | URL 编码（QueryEscape） |
| `URLDecode(s string) (string, error)` | URL 解码（QueryUnescape） |
| `URLComponentEncode(s string) string` | URL 组件编码（PathEscape） |
| `URLComponentDecode(s string) (string, error)` | URL 组件解码（PathUnescape） |

### 使用示例

```go
// URL Query 编码
enc := encoding.URLEncode("hello world&key=value")
dec, _ := encoding.URLDecode(enc)

// URL 路径组件编码
enc = encoding.URLComponentEncode("/path/to/file")
dec, _ = encoding.URLComponentDecode(enc)
```

---

## 3. Hex 编码

### 函数列表

| 函数 | 说明 |
|------|------|
| `HexEncode(data []byte) string` | Hex 编码（小写） |
| `HexDecode(s string) ([]byte, error)` | Hex 解码（支持 0x 前缀、大小写、空格、换行） |
| `HexEncodeWithColon(data []byte) string` | Hex 编码，以冒号分隔 |
| `HexEncodeWithSpace(data []byte) string` | Hex 编码，以空格分隔 |

### 使用示例

```go
data := []byte{0xDE, 0xAD, 0xBE, 0xEF}

// 标准 Hex
enc := encoding.HexEncode(data)            // "deadbeef"
dec, _ := encoding.HexDecode("0xDEADBEEF") // 自动去除 0x 前缀

// 带分隔符
enc = encoding.HexEncodeWithColon(data)     // "de:ad:be:ef"
enc = encoding.HexEncodeWithSpace(data)     // "de ad be ef"
```

---

## 4. HTML 实体编码

### 函数列表

| 函数 | 说明 |
|------|------|
| `HTMLEntityEncode(s string) string` | HTML 实体编码（转义特殊字符） |
| `HTMLEntityDecode(s string) string` | HTML 实体解码 |
| `HTMLEntityEncodeAll(s string) string` | HTML 实体编码（编码所有可编码字符） |
| `HTMLEntityDecodeAll(s string) string` | HTML 实体解码（同 Decode） |

### 使用示例

```go
// 编码特殊字符
enc := encoding.HTMLEntityEncode("<div class=\"test\">&amp;</div>")
// 输出: &lt;div class=&#34;test&#34;&gt;&amp;amp;&lt;/div&gt;

// 解码 XSS payload
dec := encoding.HTMLEntityDecode("&lt;script&gt;alert(1)&lt;/script&gt;")
// 输出: <script>alert(1)</script>
```

---

## 5. 古典密码

### 5.1 凯撒密码 (Caesar Cipher)

将字母按固定偏移量移位。

| 函数 | 说明 |
|------|------|
| `CaesarEncode(s string, shift int) string` | 凯撒密码加密 |
| `CaesarDecode(s string, shift int) string` | 凯撒密码解密 |
| `CaesarBruteForce(s string) []string` | 凯撒密码暴力破解（26个偏移） |

**使用示例**：

```go
enc := encoding.CaesarEncode("Hello World", 3)  // "Khoor Zruog"
dec := encoding.CaesarDecode(enc, 3)             // "Hello World"

// 暴力破解
results := encoding.CaesarBruteForce("Khoor Zruog")
// results[0]: "shift  0: Khoor Zruog"
// results[3]: "shift  3: Hello World"
```

### 5.2 维吉尼亚密码 (Vigenère Cipher)

使用关键词进行多表替换加密。

| 函数 | 说明 |
|------|------|
| `VigenereEncode(s string, key string) string` | 维吉尼亚密码加密 |
| `VigenereDecode(s string, key string) string` | 维吉尼亚密码解密 |

**使用示例**：

```go
enc := encoding.VigenereEncode("HELLO", "KEY")      // "RIJVS"
dec := encoding.VigenereDecode(enc, "KEY")           // "HELLO"

enc = encoding.VigenereEncode("Attack at Dawn", "LEMON")
dec = encoding.VigenereDecode(enc, "LEMON")          // "Attack at Dawn"
```

### 5.3 栅栏密码 - 基础型 (Rail Fence Cipher)

将明文按 Z 字形排列后按行读取。

| 函数 | 说明 |
|------|------|
| `RailFenceEncode(s string, rails int) string` | 栅栏密码加密（基础型） |
| `RailFenceDecode(s string, rails int) string` | 栅栏密码解密（基础型） |

**使用示例**：

```go
enc := encoding.RailFenceEncode("HELLOWORLD", 3)   // "HOLELWRDLO"
dec := encoding.RailFenceDecode(enc, 3)             // "HELLOWORLD"
```

**加密过程**（以 rails=3 为例）：
```
H . . . O . . . L .    → 第1行
. E . L . W . R . D    → 第2行
. . L . . . O . . .    → 第3行

按行读取: HOLELWRDLO
```

### 5.4 栅栏密码 - W 型

W 型与基础型的加密方式相同，均为 Z 字形排列后按行读取。

| 函数 | 说明 |
|------|------|
| `RailFenceWEncode(s string, rails int) string` | 栅栏密码加密（W 型） |
| `RailFenceWDecode(s string, rails int) string` | 栅栏密码解密（W 型） |

---

## 6. Jother 编码

Jother 是一种使用仅 8 个字符 `!` `(` `)` `+` `[` `]` `{` `}` 的 JavaScript 混淆编码技术。编码后的字符串在 JavaScript 环境中执行将还原为原始字符串。

| 函数 | 说明 |
|------|------|
| `JotherEncode(s string) string` | Jother 编码 |
| `JotherDecode(s string) string` | Jother 解码 |

**编码原理**：

- `+[]` → 0
- `+!![]` → 1
- `![]` → false，`(![]+[])` → "false"
- `!![]` → true，`(!![]+[])` → "true"
- `([][[]]+[])` → "undefined"
- `([]+{})` → "[object Object]"
- 通过索引获取字符，拼接成目标字符串

**使用示例**：

```go
enc := encoding.JotherEncode("hi")
// 输出 JavaScript 表达式，可在浏览器控制台执行还原
```

---

## 7. JSFuck 编码

JSFuck 是一种使用仅 6 个字符 `[` `]` `(` `)` `!` `+` 的 JavaScript 混淆编码技术。编码后的字符串在 JavaScript 环境中执行将还原为原始字符串。

| 函数 | 说明 |
|------|------|
| `JSFuckEncode(s string) string` | JSFuck 编码 |
| `JSFuckDecode(s string) string` | JSFuck 解码 |

**编码原理**：

- `+[]` → 0
- `+!![]` → 1
- `(![]+[])` → "false"，获取 f、a、l、s、e
- `(!![]+[])` → "true"，获取 t、r、u、e
- `([][[]]+[])` → "undefined"，获取 u、n、d、e、f、i
- `(+[![]]+[])` → "NaN"，获取 N、a
- `((+!![]/+[])+[])` → "Infinity"，获取 I、n、f、i、t、y
- 通过 `constructor` 获取 `Function` 字符串，获取更多字符

**使用示例**：

```go
enc := encoding.JSFuckEncode("hi")
// 输出 JavaScript 表达式，可在浏览器控制台执行还原
```

---

## 8. 便捷函数 (Easy API)

提供以 `Encode`/`Decode` 为前缀的便捷函数。

| 函数 | 说明 |
|------|------|
| `EncodeBase16 / DecodeBase16` | Base16 编码/解码 |
| `EncodeBase32 / DecodeBase32` | Base32 编码/解码 |
| `EncodeBase64 / DecodeBase64` | Base64 编码/解码 |
| `EncodeBase85 / DecodeBase85` | Base85 编码/解码 |
| `EncodeURL / DecodeURL` | URL 编码/解码 |
| `EncodeHex / DecodeHex` | Hex 编码/解码 |
| `EncodeHTML / DecodeHTML` | HTML 实体编码/解码 |
| `EncodeCaesar / DecodeCaesar` | 凯撒密码加密/解密 |
| `EncodeVigenere / DecodeVigenere` | 维吉尼亚密码加密/解密 |
| `EncodeRailFence / DecodeRailFence` | 栅栏密码加密/解密 |
| `EncodeJother / DecodeJother` | Jother 编码/解码 |
| `EncodeJSFuck / DecodeJSFuck` | JSFuck 编码/解码 |

---

## License

Apache License 2.0