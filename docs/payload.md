# payload - 安全测试Payload库

网络安全渗透测试的Payload库，提供XSS、WAF绕过、浏览器指纹、Web目录扫描防御绕过和弱口令的Payload集合，总计 **3085** 条Payload。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/payload"
```

---

## 极简 API

```go
// 获取所有XSS Payload原始字符串
payloads := payload.XSSStrings()

// 获取所有WAF绕过Payload
payloads := payload.WAFBypassStrings(payload.WAFCloudflare)

// 获取目录扫描UserAgent绕过列表
uaList := payload.DirUserAgentBypassStrings()

// 获取Top1000弱口令
pwList := payload.PwPayloadStrings()

// 获取Payload总数
total := payload.TotalCount()

// 按上下文获取XSS Payload
htmlPayloads := payload.XSSByContext(payload.XSSHTML)
```

---

## Payload 概览

| 分类 | 数量 | 说明 |
|------|------|------|
| XSS Payloads | 529 | 跨站脚本攻击Payload |
| WAF Bypass | 538 | Web应用防火墙绕过Payload |
| 浏览器指纹 | 506 | 浏览器指纹采集Payload |
| 目录扫描防御绕过 | 512 | 目录扫描防御机制绕过 |
| 弱口令 | 1000 | Top1000常见弱口令 |
| **总计** | **3085** | - |

---

## XSS Payloads

### 按上下文分类

```go
// HTML上下文 XSS (188条)
payloads := payload.XSSByContext(payload.XSSHTML)

// 属性上下文 XSS (129条)
payloads := payload.XSSByContext(payload.XSSAttribute)

// Script上下文 XSS (15条)
payloads := payload.XSSByContext(payload.XSSScript)

// SVG上下文 XSS (55条)
payloads := payload.XSSByContext(payload.XSSSVG)

// CSS上下文 XSS (15条)
payloads := payload.XSSByContext(payload.XSSCSS)

// URL上下文 XSS (20条)
payloads := payload.XSSByContext(payload.XSSURL)
```

### 专用Payload

```go
// Polyglot多语境Payload (7条)
payloads := payload.XSSPolyglotPayloads()

// WAF绕过XSS (28条)
payloads := payload.XSSWAFBypassPayloads()

// HTML5新特性XSS (30条)
payloads := payload.XSSHTML5Payloads()

// DOM Clobbering (7条)
payloads := payload.XSSDOMClobberingPayloads()

// Mutation XSS (5条)
payloads := payload.XSSMutationPayloads()

// 获取原始字符串列表
strings := payload.XSSHTMLStrings()
strings := payload.XSSSVGStrings()
strings := payload.XSSPolyglotStrings()
```

### XSS Payload 内容分类

| 子类别 | 数量 | 典型示例 |
|--------|------|----------|
| HTML向量 | 188 | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` |
| Attribute向量 | 129 | `" onmouseover=alert(1) x="`, `" onfocus=alert(1) autofocus x="` |
| Script上下文 | 15 | `');alert(1)//`, `</script><script>alert(1)</script>` |
| SVG向量 | 55 | `<svg onload=alert(1)>`, `<svg><animate onbegin=alert(1)>` |
| CSS向量 | 15 | `body{background-image:url("javascript:alert(1)")}` |
| URL向量 | 20 | `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>` |
| Polyglot | 7 | 多上下文同时注入 |
| WAF绕过XSS | 28 | Unicode编码、fromCharCode、base64编码等 |
| HTML5向量 | 30 | `<details ontoggle>`, `<dialog>`, `<picture onerror>` |
| DOM Clobbering | 7 | 覆盖DOM属性实现XSS |
| Mutation XSS | 5 | noscript/svg mXSS |
| Angular Vector | 30 | `{{constructor.constructor('alert(1)')()}}` |

---

## WAF 绕过 Payloads

```go
// 按WAF类型获取
payloads := payload.WAFBypassPayloads(payload.WAFCloudflare)
payloads := payload.WAFBypassPayloads(payload.WAFAWS)
payloads := payload.WAFBypassPayloads(payload.WAFModSecurity)
payloads := payload.WAFBypassPayloads(payload.WAFIncapsula)
payloads := payload.WAFBypassPayloads(payload.WAFF5)
payloads := payload.WAFBypassPayloads(payload.WAFBarracuda)
payloads := payload.WAFBypassPayloads(payload.WAFSucuri)
payloads := payload.WAFBypassPayloads(payload.WAFAkamai)
payloads := payload.WAFBypassPayloads(payload.WAFGeneric)  // 通用WAF

// 获取所有WAF绕过Payload
payloads := payload.WAFBypassAllPayloads()

// 按技术分类获取
payloads := payload.WAFBypassSQLKeywordsPayloads()
payloads := payload.WAFBypassCommentStylesPayloads()
payloads := payload.WAFBypassSpacesPayloads()
payloads := payload.WAFBypassUnionVariantsPayloads()
payloads := payload.WAFBypassTimeBasedPayloads()
payloads := payload.WAFBypassErrorBasedPayloads()
payloads := payload.WAFBypassBlindSQLPayloads()
payloads := payload.WAFBypassCmdInjectionPayloads()
payloads := payload.WAFBypassSSTIPayloads()
payloads := payload.WAFBypassXXEPayloads()
payloads := payload.WAFBypassFileInclusionPayloads()
payloads := payload.WAFBypassNoSQLInjectionPayloads()
payloads := payload.WAFBypassHTTPDesyncPayloads()

// 获取原始字符串列表
strings := payload.WAFBypassStrings(payload.WAFCloudflare)
strings := payload.WAFBypassAllStrings()
```

### WAF 类型一览

| WAF | 数量 | 绕过技术 |
|-----|------|----------|
| Cloudflare | 25 | 内联注释、URL编码、关键词内嵌、Null字节 |
| AWS WAF | 17 | 大小写混用、Plus空格、Unicode编码 |
| ModSecurity | 18 | 版本注释、全URL编码、关键词拆分 |
| Incapsula | 13 | 十六进制引号、DUAL绕过 |
| F5 ASM | 12 | 注释空白、大小写混用、尾部换行 |
| Barracuda | 10 | 关键词内嵌、注释分隔、大小写+Plus |
| Sucuri | 9 | 注释绕过、ORDER BY |
| Akamai | 9 | 全注释、大小写、假版本注释 |
| 通用 | 28 | 多级URL编码、数学运算、GBK宽字节、Hex编码 |

### 专项绕过技术

| 技术分类 | 说明 |
|----------|------|
| SQLKeywords | SQL关键词变体绕过（UNION/SELECT大小写混用） |
| CommentStyles | 注释风格多样化（`/**/`, `--`, `#`） |
| Spaces | 空白符替代（TAB、换行、回车） |
| UnionVariants | UNION变体（UNION ALL、UNION DISTINCT） |
| TimeBased | 时间盲注（SLEEP、BENCHMARK、WAITFOR） |
| ErrorBased | 报错注入（EXTRACTVALUE、UPDATEXML） |
| BlindSQL | 布尔盲注（逐字符、逐位） |
| CmdInjection | 命令注入绕过（管道、反引号、换行） |
| SSTI | 模板注入（Jinja2、FreeMarker、ERB、Django） |
| XXE | XML外部实体注入（文件读取、OOB带外） |
| FileInclusion | 文件包含（LFI/RFI、PHP Filter、路径遍历） |
| NoSQL | NoSQL注入（MongoDB $gt/$ne/$where） |
| HTTPDesync | HTTP请求走私（CL.TE、TE.CL、TE.TE混淆） |

---

## 浏览器指纹 Payloads

```go
// 按指纹类型获取
payloads := payload.FingerprintByType(payload.FingerprintCanvas)
payloads := payload.FingerprintByType(payload.FingerprintWebGL)
payloads := payload.FingerprintByType(payload.FingerprintWebRTC)
payloads := payload.FingerprintByType(payload.FingerprintFont)
payloads := payload.FingerprintByType(payload.FingerprintAudio)

// 按模块获取
payloads := payload.FingerprintCanvasPayloads()
payloads := payload.FingerprintWebGLPayloads()
payloads := payload.FingerprintPerformancePayloads()
payloads := payload.FingerprintStoragePayloads()
payloads := payload.FingerprintMathPayloads()
payloads := payload.FingerprintIntlPayloads()
payloads := payload.FingerprintWebWorkerPayloads()
payloads := payload.FingerprintWebAssemblyPayloads()
payloads := payload.FingerprintCryptoPayloads()
payloads := payload.FingerprintPermissionsPayloads()
payloads := payload.FingerprintSensorPayloads()
payloads := payload.FingerprintWebGPUPayloads()
payloads := payload.FingerprintBluetoothPayloads()

// 获取原始字符串
strings := payload.FingerprintCanvasStrings()
strings := payload.FingerprintWebGLStrings()
strings := payload.FingerprintAllStrings()
```

### 指纹类型一览

| 类型 | 说明 | Payload内容 |
|------|------|-------------|
| Canvas | Canvas渲染指纹 | 文字渲染、色彩块、渐变、Emoji+哈希 |
| WebGL | GPU信息采集 | 显卡型号、驱动、渲染参数、扩展列表 |
| WebGPU | WebGPU API | 适配器名称、资源限制、着色器/管线检测 |
| Audio | AudioContext指纹 | 振荡器特征、正弦波处理、采样率参数 |
| Font | 字体检测 | 系统已安装字体枚举 |
| WebRTC | 真实IP泄露 | STUN服务IP泄露、SDP信息 |
| Battery | 电量检测 | 电量、充电状态 |
| Plugin | 插件检测 | 浏览器插件列表、MIME类型 |
| Screen | 屏幕信息 | 分辨率、DPR、色深 |
| Timezone | 时区信息 | 时区名称、UTC偏移 |
| Language | 语言偏好 | 首选语言、语言列表 |
| UserAgent | 设备信息 | UA、平台、内存、CPU核心数 |
| Hardware | 硬件性能 | CPU核心数、内存、触摸点数、网络类型 |
| Performance | 性能API | 内存使用、导航类型、资源时间 |
| Storage | 存储API | localStorage、sessionStorage、IndexedDB |
| Media | 媒体编码 | 视频/音频编解码器支持检测 |
| Touch | 触控支持 | 触点数量、事件支持检测 |
| Orientation | 方向传感器 | 陀螺仪、加速度、设备方向 |
| Math | 数学精度 | JS引擎浮点精度、Math函数、排序算法 |
| Intl | 国际化API | DateTimeFormat、NumberFormat、PluralRules |
| WebWorker | Worker API | Worker、SharedWorker、ServiceWorker检测 |
| WebAssembly | WASM支持 | 编译、验证、内存、SIMD检测 |
| Crypto | WebCrypto | SHA算法、密钥生成、随机数 |
| Bluetooth | 蓝牙API | BLE扫描、GATT服务、设备过滤 |
| Sensors | 传感器API | 加速度、陀螺仪、光线、重力传感器 |
| Clipboard | 剪贴板 | 读写API、权限查询 |
| Permissions | 权限状态 | 批量权限查询、各传感器权限 |
| Referrer | 文档信息 | URL、标题、编码、iframe检测 |
| Cookie | Cookie属性 | 启用状态、安全属性、追踪检测 |
| JS Features | JS特性 | ES6/ES2020特性支持、类/箭头函数 |
| CSS Features | CSS特性 | Flex、Grid、clip-path、@supports检测 |
| PWA | 渐进式Web应用 | Manifest、ServiceWorker、安装检测 |
| XR | WebXR | VR/AR会话支持、设备请求、图层类型 |
| Keyboard | 键盘API | 布局映射、锁定、虚拟键盘 |
| Fullscreen | 全屏API | 前缀检测、元素/退出方法 |
| Credentials | 凭据管理 | PasswordCredential、WebAuthn、FedCM |
| Payment | 支付API | PaymentRequest、Apple/Google Pay |
| Speech | 语音API | STT/TTS、语音合成、语音识别 |
| PDF | PDF查看器 | 插件检测、MIME类型、嵌入检测 |

---

## 目录扫描防御绕过 Payloads

```go
// 按绕过类型获取
payloads := payload.DirBypassPayloads(payload.DirBypassUserAgent)
payloads := payload.DirBypassPayloads(payload.DirBypassHeader)
payloads := payload.DirBypassPayloads(payload.DirBypassEncoding)
payloads := payload.DirBypassPayloads(payload.DirBypassCase)
payloads := payload.DirBypassPayloads(payload.DirBypassRateLimit)
payloads := payload.DirBypassPayloads(payload.DirBypassPathObfuscation)
payloads := payload.DirBypassPayloads(payload.DirBypassMethod)
payloads := payload.DirBypassPayloads(payload.DirBypassReferer)
payloads := payload.DirBypassPayloads(payload.DirBypassCookie)
payloads := payload.DirBypassPayloads(payload.DirBypassParam)
payloads := payload.DirBypassPayloads(payload.DirBypassSecurity)

// 获取常用路径
paths := payload.DirCommonPathsPayloads()

// 获取原始字符串
strings := payload.DirUserAgentBypassStrings()
strings := payload.DirHeaderBypassStrings()
strings := payload.DirEncodingBypassStrings()
strings := payload.DirCaseBypassStrings()
strings := payload.DirPathObfuscationBypassStrings()
```

### 绕过类型一览

| 绕过类型 | 数量 | Payload内容 |
|----------|------|-------------|
| UserAgent | 60 | Chrome/Firefox/Safari/移动端/Bot/Curl/Python等各类UA |
| Header | 42 | X-Forwarded-For/Client-IP/JWT/CORS等头部伪造 |
| 编码 | 27 | URL编码/双重编码/Unicode/UTF-8超长编码 |
| 大小写 | 17 | Admin/ADMIN/aDmIn/Web-Inf等变体 |
| 频率限制 | 27 | 随机延迟/递增延迟/并发控制/重试策略 |
| 路径混淆 | 39 | /.// /..;/ .json后缀 URL编码路径 |
| HTTP方法 | 16 | GET/POST/HEAD/PUT/PATCH/DELETE/TRACE/CONNECT |
| Referer | 6 | Google/GitHub/Bing/同源/空Referer |
| Cookie | 6 | 伪造session/token/PHPSESSID/JSESSIONID |
| 参数 | 14 | debug/admin/test/format/callback/json等 |
| 安全绕过 | 163 | 403/401/WAF绕过头部/路径绕过 |
| 常用路径 | 99 | /admin,/api,/jenkins,/swagger,/grafana等 |

---

## 弱口令 Payloads

```go
// 获取Top1000弱口令Payload（含描述）
payloads := payload.PwPayload()

// 获取原始字符串列表
strings := payload.PwPayloadStrings()

// 获取弱口令数量
count := payload.PasswordCount()
```

### 弱口令内容分类

| 类别 | 典型示例 |
|------|----------|
| 纯数字 | `123456`, `123456789`, `111111`, `666666`, `000000` |
| 键盘模式 | `qwerty`, `qazwsx`, `zxcvbnm`, `1q2w3e4r`, `zaq12wsx` |
| 英文单词 | `password`, `sunshine`, `princess`, `dragon`, `monkey` |
| 情感表达 | `iloveyou`, `fuckyou`, `lovely`, `trustno1`, `letmein` |
| 人名 | `michael`, `ashley`, `jennifer`, `thomas`, `daniel` |
| 运动 | `football`, `baseball`, `soccer`, `hockey`, `lakers` |
| 品牌/影视 | `starwars`, `batman`, `cocacola`, `samsung`, `nissan` |
| 混合组合 | `abc123`, `password123`, `qwerty123`, `passw0rd` |
| 反向/倒序 | `drowssap`, `ytrewq`, `nwo` |

---

## 链式配置（高级用法）

```go
// 结合sqlexp和payload创建完整的攻击链
import (
    "github.com/xiguayiqiu/gyscan_code/payload"
    "github.com/xiguayiqiu/gyscan_code/sqlexp"
)

// 获取WAF绕过Payload并用于SQL注入测试
wafPayloads := payload.WAFBypassStrings(payload.WAFCloudflare)
for _, p := range wafPayloads {
    sqlexp.NewExploit().
        DB(sqlexp.MySQL).
        Prefix("'").
        Suffix("--").
        WAFBypass(true)
}
```

---

## 类型参考

```go
type Payload struct {
    Raw         string          // 原始Payload字符串
    Description string          // Payload描述
    Context     XSSContext      // XSS上下文 (XSS专用)
    WAF         WAFType         // WAF类型 (WAF绕过专用)
    FPType      FingerprintType // 指纹类型 (浏览器指纹专用)
    BypassType  DirScanBypassType // 绕过类型 (目录扫描专用)
}
```

### XSSContext 枚举

- `payload.XSSHTML` - HTML上下文
- `payload.XSSAttribute` - 属性上下文
- `payload.XSSScript` - Script上下文
- `payload.XSSCSS` - CSS上下文
- `payload.XSSURL` - URL上下文
- `payload.XSSSVG` - SVG上下文

### WAFType 枚举

- `payload.WAFCloudflare` / `payload.WAFAWS` / `payload.WAFModSecurity`
- `payload.WAFIncapsula` / `payload.WAFF5` / `payload.WAFBarracuda`
- `payload.WAFSucuri` / `payload.WAFAkamai` / `payload.WAFGeneric`

### FingerprintType 枚举

- `payload.FingerprintCanvas` / `payload.FingerprintWebGL` / `payload.FingerprintAudio`
- `payload.FingerprintFont` / `payload.FingerprintWebRTC` / `payload.FingerprintBattery`
- `payload.FingerprintPlugin` / `payload.FingerprintScreen` / `payload.FingerprintTimezone`
- `payload.FingerprintLanguage` / `payload.FingerprintUserAgent` / `payload.FingerprintHardware`
- `payload.FingerprintMedia` / `payload.FingerprintPerformance` / `payload.FingerprintStorage`

### DirScanBypassType 枚举

- `payload.DirBypassUserAgent` / `payload.DirBypassHeader`
- `payload.DirBypassEncoding` / `payload.DirBypassCase`
- `payload.DirBypassRateLimit` / `payload.DirBypassPathObfuscation`
- `payload.DirBypassMethod` / `payload.DirBypassReferer`
- `payload.DirBypassCookie` / `payload.DirBypassParam`
- `payload.DirBypassSecurity`

---

## License

Apache License 2.0