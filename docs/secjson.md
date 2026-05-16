# secJson — 敏感 JSON 分析库

专注于 **JSON 数据内容层的敏感信息识别与风险治理**。其核心目标是识别、评估和管控 JSON 数据中可能泄露的敏感信息，**不涉及 JSON 语法解析本身的安全漏洞**（如原型污染），而是聚焦数据内容层面的敏感信息识别与风险治理。

> **严格能力边界**：仅做敏感数据识别与风险评估，不包含加密解密、数据清洗、自动化脱敏等处理逻辑。

---

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/secJson"
```

---

## 核心分析框架

```
┌─────────────────────────────────────────────────────────────────┐
│                    敏感 JSON 分析引擎                             │
├──────────────────┬──────────────────┬───────────────────────────┤
│  敏感字段识别      │  脱敏与加密验证     │  合规与审计映射              │
│  (正则+字段名+Luhn)│  (4 类脱敏质量评估) │  (GDPR/PCI-DSS/等保2.0)   │
│  置信度分级        │  明文→掩码→加密     │  自动化规则检查             │
│  组合风险评估      │  强度评分 0-90     │  审计证据链                 │
└──────────────────┴──────────────────┴───────────────────────────┘
```

### 四层分析

| 层级 | 分析内容 | 输出 |
|------|---------|------|
| **敏感字段识别与分类** | 15 种敏感值正则 + 18 种字段名规则，含身份证号、银行卡号（Luhn 校验）、JWT Token、API 密钥等 | `[]Match` + 严重等级 |
| **动态敏感性判定** | 上下文路径加权 + 字段组合风险评估（8 种危险组合） | 风险评分 0-100 |
| **脱敏与加密策略验证** | 身份/金融/凭证/隐私四类脱敏质量评估，强度分级（0-90 分） | `[]MaskIssue` |
| **合规与审计要求映射** | PCI-DSS、GDPR、等保2.0、数据安全法自动化规则检查 | `[]ComplianceIssue` |

---

## 核心数据类型

### Match — 单个敏感字段匹配

```go
type Match struct {
    Field    string   `json:"field"`           // 字段名
    Path     string   `json:"path"`            // JSON 路径（如 $.user.id_card）
    Value    string   `json:"value,omitempty"` // 原始值（报告时自动掩码）
    Masked   string   `json:"masked,omitempty"` // 掩码后的值
    Type     string   `json:"type"`            // 敏感类型标识（如 id_card_cn、jwt_token）
    Category Category `json:"category"`        // 敏感类别
    Severity Severity `json:"severity"`        // 严重等级
    Message  string   `json:"message"`         // 描述信息
}
```

### Finding — 分析结果

```go
type Finding struct {
    Matches     []Match  `json:"matches"`               // 敏感字段列表
    TotalFields int      `json:"total_fields"`          // JSON 总字段数
    RiskScore   float64  `json:"risk_score"`            // 风险评分 0-100
    Summary     string   `json:"summary"`               // 分析摘要
    Compliance  []string `json:"compliance_issues,omitempty"` // 合规问题简述
}
```

### MaskIssue — 脱敏问题

```go
type MaskIssue struct {
    Field      string `json:"field"`      // 字段名
    Path       string `json:"path"`       // JSON 路径
    Issue      string `json:"issue"`      // 问题描述
    Level      string `json:"level"`      // 问题等级（CRITICAL/HIGH/MEDIUM）
    Suggestion string `json:"suggestion"` // 修复建议
}
```

### ComplianceIssue — 合规问题

```go
type ComplianceIssue struct {
    Standard string `json:"standard"` // 法规名称（PCI-DSS/GDPR/等保2.0/数据安全法）
    Rule     string `json:"rule"`     // 规则名称
    Field    string `json:"field"`    // 涉及字段
    Path     string `json:"path"`     // JSON 路径
    Status   string `json:"status"`   // 合规状态（违反/需评估/需审查）
    Detail   string `json:"detail"`   // 详细说明
}
```

### 严重等级（Severity）

| 常量 | 说明 | 典型场景 |
|------|------|---------|
| `SeverityCritical` | 严重 | 身份证号明文、API 密钥明文、JWT Token 明文 |
| `SeverityHigh` | 高 | 手机号明文、银行卡号明文、护照号 |
| `SeverityMedium` | 中 | 邮箱地址、地址信息、财务金额字段 |
| `SeverityLow` | 低 | IPv4/IPv6 地址（GDPR 个人数据）、UUID |
| `SeverityInfo` | 信息 | 仅供参考的内部标识符 |

### 敏感类别（Category）

| 常量 | 说明 | 示例字段 |
|------|------|---------|
| `CategoryIdentity` | 身份标识 | 身份证号、护照号、社保号 |
| `CategoryFinance` | 金融信息 | 银行卡号、支付密码、交易金额 |
| `CategoryCredential` | 凭证信息 | API 密钥、JWT Token、密码 |
| `CategoryBiometric` | 生物特征 | 人脸特征值、指纹模板 |
| `CategoryInternal` | 内部标识 | UUID、内部系统 ID |
| `CategoryPrivacy` | 隐私数据 | 手机号、邮箱、地址、IP |
| `CategoryCombined` | 组合风险 | 身份证+手机号、银行卡+手机号 |

### Config — 分析配置

```go
type Config struct {
    StrictMode   bool         // 严格模式（中等级自动提升为高）
    MinSeverity  Severity     // 最低报告等级（默认 SeverityLow）
    MaxDepth     int          // JSON 递归最大深度（默认 50）
    SkipFields   []string     // 跳过的字段名列表（忽略大小写）
    CustomRules  []CustomRule // 自定义检测规则
    ContextPath  string       // API 上下文路径（如 /admin、/api/user）
}

func DefaultConfig() *Config {
    return &Config{
        StrictMode:  false,
        MinSeverity: SeverityLow,
        MaxDepth:    50,
    }
}
```

---

## 使用示例

### 基础扫描（一行调用）

```go
finding, err := secjson.Scan(jsonData)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("风险评分: %.1f/100\n", finding.RiskScore)
fmt.Printf("发现 %d 个敏感字段\n", len(finding.Matches))
for _, m := range finding.Matches {
    fmt.Printf("  [%s] %s: %s → %s\n", m.Severity, m.Field, m.Type, m.Message)
}
```

### 安全判断

```go
if secjson.IsSafe(jsonData) {
    fmt.Println("JSON 数据安全，未发现敏感信息")
} else {
    fmt.Println("⚠ 发现敏感信息，建议立即审查")
}
```

### 完整扫描（含脱敏评估 + 合规检查）

```go
finding, masks, compliance, err := secjson.ScanFull(jsonData)
if err != nil {
    log.Fatal(err)
}

// 脱敏问题
for _, issue := range masks {
    fmt.Printf("  [%s] %s: %s → %s\n", issue.Level, issue.Field, issue.Issue, issue.Suggestion)
}

// 合规问题
for _, c := range compliance {
    fmt.Printf("  [%s] %s: %s\n", c.Standard, c.Rule, c.Detail)
}
```

### 文件扫描

```go
// 基础扫描
finding, err := secjson.ScanFile("/path/to/data.json")

// 完整扫描
finding, masks, compliance, err := secjson.ScanFileFull("/path/to/data.json")

// 扫描并直接保存报告
err := secjson.ScanFileAndSave("/path/to/input.json", "/tmp/report.json")
```

### 严格模式

```go
cfg := secjson.DefaultConfig()
cfg.StrictMode = true
cfg.MinSeverity = secjson.SeverityMedium

a := secjson.NewAnalyzer(cfg)
finding, err := a.Analyze(jsonData)
```

严格模式下所有 `SeverityMedium` 等级的匹配自动提升为 `SeverityHigh`。

### 自定义规则

```go
cfg := secjson.DefaultConfig()

// 跳过特定字段
cfg.SkipFields = []string{"timestamp", "request_id"}

// 添加自定义检测规则
cfg.CustomRules = []secjson.CustomRule{
    {
        Name:     "内部工号",
        Pattern:  `^EMP\d{8}$`,
        Category: secjson.CategoryInternal,
        Severity: secjson.SeverityMedium,
        Message:  "企业内部员工编号",
    },
}

a := secjson.NewAnalyzer(cfg)
finding, _ := a.Analyze(jsonData)
```

---

## easy 封装层（一行式 API）

`easy.go` 将常见操作封装为单一函数调用，覆盖 90% 的常见场景，无需手动创建 `Analyzer`。

### 一行式扫描

```go
// 基础扫描
finding, _ := secjson.Scan(jsonData)

// 严格模式
finding, _ := secjson.ScanStrict(jsonData)

// 完整扫描（含脱敏+合规）
finding, masks, compliance, _ := secjson.ScanFull(jsonData)

// 严格+完整
finding, masks, compliance, _ := secjson.ScanFullStrict(jsonData)

// 字节数组扫描
finding, _ := secjson.ScanBytes([]byte(jsonData))

// 文件扫描
finding, _ := secjson.ScanFile("/path/to/data.json")

// 文件完整扫描
finding, masks, compliance, _ := secjson.ScanFileFull("/path/to/data.json")
```

### 一行式报告

```go
// 安全判断
if secjson.IsSafe(jsonData) { ... }

// 快速报告（纯文本摘要）
report, _ := secjson.QuickReport(jsonData)
fmt.Println(report)

// 保存完整 JSON 报告
secjson.SaveReportTo(jsonData, "/tmp/report.json")

// 扫描文件并保存报告
secjson.ScanFileAndSave("/path/to/input.json", "/tmp/report.json")
```

### 完整函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `Scan(jsonData)` | `(*Finding, error)` | 基础敏感字段扫描 |
| `ScanStrict(jsonData)` | `(*Finding, error)` | 严格模式扫描 |
| `ScanFull(jsonData)` | `(*Finding, []MaskIssue, []ComplianceIssue, error)` | 完整三合一扫描 |
| `ScanFullStrict(jsonData)` | `(*Finding, []MaskIssue, []ComplianceIssue, error)` | 严格+完整扫描 |
| `ScanBytes(data)` | `(*Finding, error)` | 字节数组扫描 |
| `ScanFile(path)` | `(*Finding, error)` | 文件基础扫描 |
| `ScanFileFull(path)` | `(*Finding, []MaskIssue, []ComplianceIssue, error)` | 文件完整扫描 |
| `IsSafe(jsonData)` | `bool` | 安全判断（风险评分 < 20） |
| `QuickReport(jsonData)` | `(string, error)` | 生成文本摘要报告 |
| `SaveReportTo(jsonData, path)` | `error` | 保存完整 JSON 报告 |
| `ScanFileAndSave(input, output)` | `error` | 扫描文件并保存报告 |

---

## 敏感字段识别规则

### 敏感值正则（15 种）

| 类型 | 正则 | 类别 | 严重等级 |
|------|------|------|---------|
| `id_card_cn` | 18 位身份证（地区+年份+校验位） | IDENTITY | CRITICAL |
| `id_card_cn_18` | 18 位身份证（放宽格式） | IDENTITY | CRITICAL |
| `id_card_cn_15` | 15 位旧版身份证 | IDENTITY | HIGH |
| `phone_cn` | `1[3-9]XXXXXXXXX` | PRIVACY | HIGH |
| `email` | 标准邮箱格式 | PRIVACY | MEDIUM |
| `api_key` | `sk_`/`pk_`/`api_key` 前缀 | CREDENTIAL | CRITICAL |
| `base64_sensitive` | 长 Base64 编码串（≥40 字符） | CREDENTIAL | MEDIUM |
| `auth_header` | Bearer/Basic 认证头 | CREDENTIAL | CRITICAL |
| `jwt_or_token` | 疑似 JWT/令牌（≥32 字符 Base64） | CREDENTIAL | HIGH |
| `jwt_token` | 标准 JWT 三段式 `eyJ...` | CREDENTIAL | CRITICAL |
| `bank_card_potential` | 13-19 位数字（Luhn 校验可验证） | FINANCE | HIGH |
| `credit_card` | 信用卡号格式（16 位分隔） | FINANCE | CRITICAL |
| `uuid` | 标准 UUID 格式 | INTERNAL | LOW |
| `ip_address` | IPv4 地址 | PRIVACY | LOW |
| `ipv6_address` | IPv6 地址 | PRIVACY | LOW |

### 敏感字段名（18 种）

| 字段名正则 | 类型 | 类别 | 严重等级 |
|-----------|------|------|---------|
| `id_card`, `card_id`, `idcard`, `identity_card` | `id_card_field` | IDENTITY | CRITICAL |
| `phone`, `mobile`, `tel`, `telephone`, `cell` | `phone_field` | PRIVACY | HIGH |
| `email`, `mail`, `e_mail` | `email_field` | PRIVACY | MEDIUM |
| `password`, `passwd`, `pwd`, `secret`, `pass` | `password_field` | CREDENTIAL | CRITICAL |
| `token`, `jwt`, `access_token`, `refresh_token`, `api_key`, `apikey`, `auth` | `token_field` | CREDENTIAL | CRITICAL |
| `ssn`, `social_security`, `sin` | `ssn_field` | IDENTITY | CRITICAL |
| `passport`, `visa` | `passport_field` | IDENTITY | HIGH |
| `credit_card`, `card_number`, `bank_card`, `bankcard`, `debit_card` | `bank_card_field` | FINANCE | CRITICAL |
| `cvv`, `cvc`, `cvv2`, `cid` | `cvv_field` | FINANCE | CRITICAL |
| `iban`, `swift`, `routing`, `account_number` | `account_field` | FINANCE | HIGH |
| `pin`, `pay_password`, `transaction_password`, `payment_code` | `pin_field` | FINANCE | CRITICAL |
| `face`, `fingerprint`, `biometric`, `face_id`, `touch_id` | `bio_field` | BIOMETRIC | CRITICAL |
| `api_key`, `secret_key`, `private_key`, `encryption_key`, `master_key` | `key_field` | CREDENTIAL | CRITICAL |
| `salary`, `income`, `balance`, `amount` | `finance_field` | FINANCE | MEDIUM |
| `address`, `location`, `gps`, `latitude`, `longitude` | `address_field` | PRIVACY | MEDIUM |
| `birthday`, `birth_date`, `age`, `gender` | `privacy_field` | PRIVACY | MEDIUM |
| `ip_address`, `client_ip`, `remote_addr`, `user_ip` | `ip_field` | PRIVACY | LOW |
| `mother`, `father`, `spouse`, `child`, `family` | `family_field` | PRIVACY | MEDIUM |

### 银行卡 Luhn 校验

```go
// 验证银行卡号格式
if secjson.IsValidBankCard("6222021234567890123") {
    fmt.Println("有效的银行卡号格式")
}

// 仅 Luhn 算法校验
if secjson.LuhnCheck("6222021234567890123") {
    fmt.Println("Luhn 校验通过")
}
```

---

## 动态敏感性判定

### 上下文权重（ContextWeight）

根据 JSON 内部路径和 API 端点路径动态加权风险评分：

```go
// URL 路径权重
ContextWeight("/admin/users")    // 1.5 (管理后台)
ContextWeight("/api/user")       // 1.3 (用户接口)
ContextWeight("/login")          // 1.4 (登录接口)
ContextWeight("/payment/order")  // 1.5 (支付接口)
ContextWeight("/internal/api")   // 1.6 (内部接口)

// JSON 内部路径权重（JSONPathWeight）
ContextWeight("$.user.password")       // 1.5 (凭证字段)
ContextWeight("$.payment.bank_card")   // 1.4 (金融字段)
ContextWeight("$.auth.token")          // 1.4 (认证字段)
ContextWeight("$.admin.secret")        // 1.5 (管理字段)
```

路径权重已自动集成到 `Analyzer.Analyze()` 的风险评分计算中，无需手动调用。

### 组合风险（CombineRisk）

自动检测 8 种危险字段组合，每种组合触发后提升风险评分 +15 分：

| 组合 | 风险描述 |
|------|---------|
| 身份证 + 手机号 | 可精准定位个人身份 |
| 身份证 + 邮箱 | 可关联多个账号 |
| 身份证 + IP 地址 | 可追溯用户地理位置 |
| 银行卡 + 手机号 | 可用于金融诈骗 |
| 手机 + 地址 | 可用于线下骚扰 |
| API 密钥 + Token | 可获取完整权限 |
| JWT + 密码字段 | 认证信息完整泄露 |
| 手机号 + JWT | 可劫持用户会话 |

---

## 脱敏与加密策略验证

### 脱敏质量评估

`AnalyzeMasking` 按敏感类别分发不同的检查逻辑：

| 类别 | 检查逻辑 | 明文惩罚 |
|------|---------|---------|
| 身份标识 | 检查掩码质量（* 覆盖率），< 50 分报告"强度不足" | CRITICAL：必须加密 |
| 金融信息 | 银行卡号明文 → 违反 PCI-DSS | CRITICAL |
| 凭证信息 | 长度 > 8 且非掩码 → CRITICAL | CRITICAL：严禁明文 |
| 隐私数据 | 非掩码 → MEDIUM | MEDIUM：建议脱敏 |

### 掩码质量评分

```
掩码覆盖率 ≥ 80%  →  90 分
掩码覆盖率 ≥ 60%  →  70 分
掩码覆盖率 ≥ 40%  →  50 分
掩码覆盖率 ≥ 20%  →  30 分
掩码覆盖率  < 20%  →  15 分
明文（无掩码）     →  0 分
```

### 识别场景

```go
// 弱脱敏示例
{"id_card": "110***1234"}  // 30% 可还原 → 报告"脱敏强度不足"

// 强脱敏示例
{"id_card": "****"}        // 80% 以上覆盖 → 通过

// 明文示例
{"bank_card": "6222021234567890123"}  // 明文 → 违反 PCI-DSS
```

---

## 合规与审计要求映射

### 自动化合规规则（6 条）

| 法规 | 规则 | 触发条件 |
|------|------|---------|
| **PCI-DSS** | 禁止明文存储 PAN | JSON 中存在明文银行卡号 |
| **PCI-DSS** | 禁止存储 CVV/CVC | JSON 中存在 `cvv` 等字段（任何情况下） |
| **GDPR** | 个人数据的合法处理 | JSON 中存在身份或隐私类字段 |
| **GDPR** | 数据最小化原则 | 个人数据字段 > 5 个 |
| **GDPR** | 生物特征特殊保护 | JSON 中存在生物特征字段且不含加密标记 |
| **等保2.0** | 敏感字段加密存储 | CRITICAL/HIGH 等级字段为明文 |
| **数据安全法** | 重要数据分类分级 | JSON 中存在 CRITICAL 等级字段 |

### 使用方式

```go
finding, masks, compliance, _ := secjson.ScanFull(jsonData)

for _, c := range compliance {
    switch c.Status {
    case "违反":
        fmt.Printf("严重违规 [%s] %s: %s\n", c.Standard, c.Rule, c.Detail)
    case "需评估":
        fmt.Printf("需评估 [%s] %s: %s\n", c.Standard, c.Rule, c.Detail)
    case "不符合":
        fmt.Printf("不符合 [%s] %s: %s\n", c.Standard, c.Rule, c.Detail)
    }
}
```

---

## 报告生成

### 生成与导出

```go
finding, masks, compliance, _ := secjson.ScanFull(jsonData)

// 生成报告
report := secjson.GenerateReport(finding, masks, compliance)

// 保存为 JSON 文件
report.SaveJSON("/tmp/secjson_report.json")

// 获取 JSON 字符串
jsonStr, _ := report.ToJSON()

// 打印可读摘要
fmt.Println(report.Summary())
```

### 报告 JSON 结构

```json
{
  "metadata": {
    "generated_at": "2026-05-15T10:30:00Z",
    "version": "1.0.0",
    "analyzer": "secJson",
    "mode": "full"
  },
  "finding": {
    "matches": [
      {
        "field": "id_card",
        "path": "$.user.id_card",
        "value": "110101199001011234",
        "masked": "110****234",
        "type": "id_card_cn",
        "category": "IDENTITY",
        "severity": "CRITICAL",
        "message": "中国大陆身份证号，属于强监管个人身份标识"
      }
    ],
    "total_fields": 10,
    "risk_score": 85.5,
    "summary": "严重风险：发现 5 个敏感字段，风险评分 85.5/100, 已检查 10 个字段",
    "compliance_issues": [
      "[GDPR] 个人数据的合法处理: JSON中包含个人身份信息(PII)，需确认...",
      "[数据安全法] 重要数据分类分级: JSON中包含重要级别数据，需按..."
    ]
  },
  "mask_issues": [
    {
      "field": "id_card",
      "path": "$.user.id_card",
      "issue": "身份信息以明文存储，严重违规",
      "level": "CRITICAL",
      "suggestion": "必须对身份证号等强监管字段进行加密存储，禁止明文"
    }
  ],
  "compliance_issues": [
    {
      "standard": "GDPR",
      "rule": "个人数据的合法处理",
      "status": "需评估",
      "detail": "JSON中包含个人身份信息(PII)，需确认处理目的合法且有适当保护措施"
    },
    {
      "standard": "PCI-DSS",
      "rule": "禁止明文存储PAN",
      "field": "bank_card",
      "path": "$.payment.bank_card",
      "status": "违反",
      "detail": "PAN（主账号）以明文存储在JSON中，PCI-DSS要求#3.4必须加密"
    }
  ]
}
```

### 可读摘要示例

```
敏感JSON分析报告
=========================
风险评分: 85.5/100
发现 5 个敏感字段
脱敏问题: 3 个
合规问题: 2 个

敏感字段明细:
  1. [CRITICAL] id_card: 中国大陆身份证号，属于强监管个人身份标识
  2. [HIGH] phone: 中国大陆手机号码
  3. [CRITICAL] token: JWT（JSON Web Token），包含用户身份和权限信息
  4. [CRITICAL] api_key: API密钥或访问令牌，泄露可导致未授权访问
  5. [CRITICAL] : 身份证+手机号组合可精准定位个人身份

脱敏建议:
  1. [CRITICAL] id_card: 必须对身份证号等强监管字段进行加密存储，禁止明文
  2. [MEDIUM] phone: 建议对个人隐私字段进行脱敏处理，符合GDPR最小化原则
  3. [CRITICAL] token: 凭证类字段严禁明文存储，应使用哈希或密封存储方案

合规问题:
  1. [GDPR] 个人数据的合法处理: JSON中包含个人身份信息(PII)...
  2. [PCI-DSS] 禁止明文存储PAN: PAN（主账号）以明文存储...
```

---

## 典型工作流

```
JSON 输入
    │
    ▼
┌─────────────────┐
│ 1. JSON 递归遍历 │  按 $.字段.子字段 逐层展开
│    walkJSON()   │  最大深度 50 层
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. 值模式匹配     │  15 种正则 + Luhn 校验
│    analyzeString()│  字段名匹配 18 种规则
│    analyzeField() │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. 后处理         │  严重等级过滤
│    filter + dedup │  去重（Path+Type）
│    CombineRisk    │  8 种组合风险检测
│    ContextWeight  │  路径权重计算
└────────┬────────┘
         │
         ▼
┌─────────────────┬─────────────────┐
│ 4. 脱敏验证       │ 5. 合规检查       │
│    AnalyzeMasking │    CheckCompli  │
│    四类分发检查    │    ance()       │
│    质量评分 0-90   │    6 条自动化规则 │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 6. 报告生成       │  → RiskScore 0-100
│    GenerateReport│  → Summary
│                  │  → JSON 导出
└─────────────────┘
```

---

## 架构一览

| 文件 | 职责 |
|------|------|
| `secjson.go` | 核心类型定义（Match/Finding/MaskIssue/ComplianceIssue/Config）+ `Analyzer` 主分析器：JSON 递归遍历、风险评分、字段分析、去重 |
| `patterns.go` | 15 种敏感值正则模式 + 18 种敏感字段名正则 + 银行卡 Luhn 算法校验 |
| `context.go` | 组合风险评估（8 种危险组合）+ 双层上下文权重（URL 路径 + JSON 内部路径） |
| `mask.go` | 脱敏质量验证：身份/金融/凭证/隐私四类分发检查，掩码强度评分（0-90 分），类别解析（防止分类误判） |
| `compliance.go` | 自动化合规规则检查：PCI-DSS（PAN/CVV）+ GDPR（合法处理/最小化/生物特征）+ 等保2.0（加密率）+ 数据安全法（分类分级） |
| `report.go` | JSON 报告生成与导出：元数据 + 发现结果 + 脱敏问题 + 合规问题，支持 SaveJSON / ToJSON / Summary |
| `easy.go` | 简化封装层：12 个一行式 API（Scan/ScanFull/ScanFile/IsSafe/QuickReport/SaveReportTo 等） |

---

## License

Apache License 2.0