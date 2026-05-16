# api — API 资产发现库

专注于 **API 端点挖掘与资产测绘** 的 Go 开发库。通过被动流量分析、前端代码解析、上下文感知探测三条路径，自动化识别目标系统中所有显式与隐式 API 端点。

> **严格能力边界**：仅做 API 资产发现，不包含漏洞检测、攻击载荷、风险评估逻辑。

---

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/api"
```

---

## 三大发现路径

```
┌─────────────────────────────────────────────────────┐
│                  API 资产发现引擎                      │
├───────────────┬───────────────┬─────────────────────┤
│  被动流量分析  │  前端代码解析  │  上下文感知主动探测    │
│  (PCAP/日志)  │  (JS/HTML/TS) │  (按需启用)          │
│  置信度 1.0   │  置信度 0.8   │  置信度 0.6          │
│  零误报零干扰  │  发现隐藏接口  │  补全遗漏端点         │
└───────────────┴───────────────┴─────────────────────┘
```

### 路径一：被动流量分析（无侵入式发现）

从 PCAP 文件、JSON 日志、URL 列表中提取真实调用的 API 端点：

- **PCAP 解析**：通过 `ano.LoadPcap` 读取网络流量，提取 HTTP 请求行（Method + Path）
- **JSON 日志**：支持 `method`/`url`/`path`/`host`/`port` 字段的结构化日志
- **URL 列表**：纯文本列表，每行一个端点（`GET /api/users`）
- **自动过滤**：排除静态资源（`.js`/`.css`/`.png`/`.html` 等 22 种扩展名）
- **优势**：零误报（仅记录真实调用）、零干扰（无需主动发包）

### 路径二：前端代码深度解析（对抗混淆）

从 JS/TS/HTML 源码中提取硬编码的 API 路径：

- **12 种正则模式**：覆盖 `fetch()`、`axios`、`$.ajax`、`XMLHttpRequest`、`baseURL` 变量
- **语义级还原**：识别动态拼接 URL（`baseURL + "/api"`），提取完整路径
- **可信度分级**：含 `/api/`、`/v[0-9]+/` → 自动提升置信度；含 `test`/`demo` → 自动降低置信度
- **大文件保护**：JS 文件 >10MB 自动截断至 2MB 分析
- **支持格式**：`.js` `.ts` `.tsx` `.jsx` `.mjs` `.html` `.htm`
- **优势**：发现流量中未触发的隐藏接口（管理后台、调试端点）

### 路径三：上下文感知主动探测（精准补全）

基于已发现接口动态生成探测策略，避免盲目扫描：

- **26 个内置探测后缀**：`/api` `/graphql` `/swagger.json` `/health` `/admin` `/metrics` `/actuator` 等
- **动态候选生成**：从已有前缀派生候选路径（如 `/api/v1` → `/api/v1/admin`）
- **存在性验证**：`403`（需权限）≠ `404`（不存在）；返回 JSON/XML 判定为 API
- **并发控制**：默认 5 并发，可配置速率限制
- **默认关闭**：需显式启用 `ActiveProbe: true`，配额上限 1000 次
- **优势**：补全被动分析遗漏的接口（如未被调用的测试端点）

---

## 核心数据类型

### APIEndpoint — 单个 API 端点

```go
type APIEndpoint struct {
    Path        string       `json:"path"`          // 归一化路径（如 /api/users/{id}）
    Methods     []HTTPMethod `json:"methods"`       // HTTP 方法列表
    Host        string       `json:"host"`          // 目标主机
    Port        int          `json:"port"`          // 端口
    Confidence  Confidence   `json:"confidence"`    // 置信度 0.0~1.0
    Source      SourceType   `json:"source"`        // 来源类型
    Parameters  []Parameter  `json:"parameters,omitempty"` // 参数列表
    ContentType string       `json:"content_type,omitempty"` // 响应类型
    StatusCode  int          `json:"status_code,omitempty"`  // HTTP 状态码
    SeenCount   int          `json:"seen_count"`    // 出现次数
}
```

### APIAssetList — 标准化资产清单

```go
type APIAssetList struct {
    Target     string        `json:"target"`       // 目标域名
    TotalCount int           `json:"total_count"`  // 去重后端点数
    Endpoints  []APIEndpoint `json:"endpoints"`    // 端点列表（按置信度降序）
    Sources    []SourceType  `json:"sources"`      // 数据来源列表
}
```

### 置信度常量

| 常量 | 值 | 来源 | 说明 |
|------|-----|------|------|
| `ConfidenceTraffic` | `1.0` | 被动流量 | 从真实网络流量提取，零误报 |
| `ConfidenceJSParse` | `0.8` | 前端代码 | 从 JS/HTML 源码解析 |
| `ConfidenceProbe` | `0.6` | 主动探测 | 通过 HTTP 请求验证 |
| `ConfidenceUnknown` | `0.3` | 未知来源 | 兜底值 |

### 来源类型

```go
const (
    SourceTraffic     SourceType = "traffic"       // 被动流量分析
    SourceJSParse     SourceType = "js_parse"      // 前端代码解析
    SourceActiveProbe SourceType = "active_probe"  // 主动探测
)
```

### 发现模式

```go
type DiscoveryMode int

const (
    ModePassiveOnly  DiscoveryMode = iota  // 仅被动流量分析
    ModePassiveAndJS                       // 被动流量 + 前端解析（默认）
    ModeFull                               // 全部三条路径
)
```

### DiscoveryConfig — 发现配置

```go
type DiscoveryConfig struct {
    Target       string          // 目标域名（必填）
    Mode         DiscoveryMode   // 发现模式
    PcapPaths    []string        // PCAP/日志/URL 列表文件路径
    JSPaths      []string        // 前端代码文件或目录路径
    ActiveProbe  bool            // 是否启用主动探测（默认 false）
    ProbeLimit   int             // 主动探测上限（默认 1000）
    AllowHTTP    bool            // 是否允许 HTTP（默认仅 HTTPS）
    RateLimit    int             // 并发探测速率（默认 10）
    IncludeHost  string          // 强制指定主机名（PCAP 解析用）
    TLSKeyLog    string          // TLS 会话密钥文件路径（预留）
}
```

---

## 使用示例

### 一键发现（推荐）

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
result, err := engine.Run()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("发现 %d 个 API 端点\n", result.TotalCount)
for _, ep := range result.Endpoints {
    fmt.Printf("  [%.1f] %s %s\n", ep.Confidence, ep.Methods, ep.Path)
}

// 导出 JSON 报告
api.ExportJSON(result.Target, result.Endpoints, cfg.Mode, "api_assets.json")
```

### 仅被动流量分析

```go
cfg := &api.DiscoveryConfig{
    Target:    "example.com",
    Mode:      api.ModePassiveOnly,
    PcapPaths: []string{"traffic.pcap", "urls.txt"},
}

engine := api.NewDiscoveryEngine(cfg)
result, _ := engine.Run()

// 按置信度过滤
highConf := api.FilterByConfidence(result.Endpoints, 0.8)
fmt.Printf("高置信度端点: %d 个\n", len(highConf))
```

### 仅前端代码解析

```go
cfg := &api.DiscoveryConfig{
    Target:  "example.com",
    Mode:    api.ModePassiveAndJS,
    JSPaths: []string{"./frontend/", "./public/app.js"},
}

engine := api.NewDiscoveryEngine(cfg)
result, _ := engine.Run()
```

### 主动探测（基于已有端点）

```go
existing := []api.APIEndpoint{
    {Path: "/api/v1/users", Methods: []api.HTTPMethod{api.MethodGET}},
    {Path: "/api/v1/products", Methods: []api.HTTPMethod{api.MethodGET}},
}

cfg := &api.DiscoveryConfig{
    Target:      "example.com",
    Mode:        api.ModeFull,
    ActiveProbe: true,
    ProbeLimit:  200,
}

engine := api.NewDiscoveryEngine(cfg)
engine.AddEndpoints(existing)
result, _ := engine.Run()
```

### 单独使用去重和归一化

```go
// 去重
endpoints := []api.APIEndpoint{...}
deduped := api.Deduplicate(endpoints)

// 路径归一化
for _, ep := range deduped {
    ep.Path = api.NormalizePath(ep.Path)
}

// 合并两个来源的端点
merged := api.MergeEndpoints(trafficEndpoints, jsEndpoints)
```

### 置信度评调整与过滤

```go
// 调整置信度（根据路径特征自动加减）
api.AdjustConfidence(&endpoint)

// 批量调整
classified := api.ClassifyConfidence(endpoints)

// 按最低置信度过滤
highConf := api.FilterByConfidence(endpoints, api.ConfidenceJSParse)
```

### JSON 报告导出

```go
// 完整报告（含元数据和统计）
report := api.GenerateReport("example.com", endpoints, api.ModeFull)
report.SaveJSON("report.json")

// JSON 字符串
jsonStr, _ := report.ToJSON()

// 仅导出端点列表
api.ExportEndpointsJSON(endpoints, "endpoints.json")
```

---

## easy 封装层（一行式 API）

`easy.go` 将常用操作封装为单一函数调用，覆盖 80% 的常见场景，无需手动配置 `DiscoveryConfig`。

### 一行式发现

```go
// 仅被动流量分析
eps, _ := api.DiscoverPcap("example.com", "traffic.pcap")

// 从 JSON 日志发现
eps, _ := api.DiscoverLogs("example.com", "api_log.jsonl")

// 从 URL 列表发现
eps, _ := api.DiscoverURLs("example.com", "urls.txt")

// 仅前端代码解析
eps, _ := api.DiscoverJS("example.com", "./frontend/src/")

// PCAP + JS 双路径
eps, _ := api.DiscoverBoth("example.com", "traffic.pcap", "./frontend/")

// 全三条路径（含主动探测，限制 500 次）
eps, _ := api.DiscoverWithProbe("example.com", "traffic.pcap", "./frontend/", 500)

// 默认配置快速扫描
eps, _ := api.QuickScan("example.com")
```

| 函数 | 模式 | 参数 |
|------|------|------|
| `DiscoverPcap(target, pcapPath)` | 仅被动 | 目标域名 + PCAP/日志/URL文件路径 |
| `DiscoverLogs(target, logPath)` | 仅被动 | 同上（JSON 日志） |
| `DiscoverURLs(target, urlListPath)` | 仅被动 | 同上（URL 列表） |
| `DiscoverJS(target, jsPath)` | 仅 JS | 目标域名 + JS 文件或目录路径 |
| `DiscoverBoth(target, pcapPath, jsPath)` | PCAP + JS | 目标域名 + 两个路径 |
| `DiscoverWithProbe(target, pcap, js, limit)` | 全三条路径 | 目标域名 + 两个路径 + 探测次数上限 |
| `QuickScan(target)` | 默认模式 | 仅目标域名 |

### 一行式后处理

```go
// 三合一：去重 + 归一化 + 置信度调整
eps = api.CleanEndpoints(eps)

// 一键导出 JSON 报告
api.SaveReport("example.com", eps, "report.json")

// 提取不重复的路径列表
paths := api.UniquePaths(eps)
```

### 分组与统计

```go
// 按来源分组
bySource := api.GroupBySource(eps)
fmt.Println("流量发现:", len(bySource[api.SourceTraffic]))

// 按 HTTP 方法分组
byMethod := api.GroupByMethod(eps)

// 按置信度三档分组
high, medium, low := api.GroupByConfidence(eps)

// 计数
api.CountBySource(eps)  // map[SourceType]int
api.CountByMethod(eps)  // map[HTTPMethod]int

// 格式化摘要
fmt.Println(api.Summary(eps))  // "47 endpoints (high:23 medium:18 low:6)"
```

### 集合运算

```go
traffic, _ := api.DiscoverPcap("x.com", "t.pcap")
js, _ := api.DiscoverJS("x.com", "./src/")

// 交集：两边都发现的端点
both := api.Intersect(traffic, js)

// 差集：JS 中有但流量中从未调用的隐藏接口
hidden := api.Diff(js, traffic)

// 并集：合并去重
all := api.Union(traffic, js)
```

### 排序

```go
eps = api.SortByConfidence(eps)  // 按置信度降序
eps = api.SortByCount(eps)       // 按出现次数降序
```

### 完整函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `DiscoverPcap(target, path)` | `([]APIEndpoint, error)` | 被动分析单个文件 |
| `DiscoverLogs(target, path)` | `([]APIEndpoint, error)` | 等同 DiscoverPcap |
| `DiscoverURLs(target, path)` | `([]APIEndpoint, error)` | 等同 DiscoverPcap |
| `DiscoverJS(target, path)` | `([]APIEndpoint, error)` | 前端解析单个路径 |
| `DiscoverBoth(target, pcap, js)` | `([]APIEndpoint, error)` | PCAP + JS 双路径 |
| `DiscoverWithProbe(target, pcap, js, limit)` | `([]APIEndpoint, error)` | 全三条路径 |
| `QuickScan(target)` | `([]APIEndpoint, error)` | 默认配置快速扫描 |
| `CleanEndpoints(eps)` | `[]APIEndpoint` | 去重+归一化+置信度调整 |
| `SaveReport(target, eps, path)` | `error` | 一键导出 JSON |
| `UniquePaths(eps)` | `[]string` | 提取唯一路径 |
| `GroupBySource(eps)` | `map[SourceType][]APIEndpoint` | 按来源分组 |
| `GroupByMethod(eps)` | `map[HTTPMethod][]APIEndpoint` | 按方法分组 |
| `GroupByConfidence(eps)` | `(high, medium, low)` | 按置信度三档分组 |
| `CountBySource(eps)` | `map[SourceType]int` | 来源计数 |
| `CountByMethod(eps)` | `map[HTTPMethod]int` | 方法计数 |
| `Summary(eps)` | `string` | 格式化摘要 |
| `Intersect(a, b)` | `[]APIEndpoint` | 交集 |
| `Diff(a, b)` | `[]APIEndpoint` | 差集 |
| `Union(a, b)` | `[]APIEndpoint` | 并集 |
| `SortByConfidence(eps)` | `[]APIEndpoint` | 按置信度降序 |
| `SortByCount(eps)` | `[]APIEndpoint` | 按出现次数降序 |

### easy 安全分析（新增）

在 API 资产发现基础上，提供敏感 API 分类、JSON 安全检测、攻击面分析、HTTP 探测的一行式接口：

```go
// --- 敏感 API 分类 ---
sensitiveAPIs := api.ClassifyAPIs(endpoints)                     // 批量敏感 AP I 分类
fmt.Println(api.CountSensitiveAPI(endpoints))                   // 敏感 API 统计摘要
if api.HasSensitiveAPI(endpoints) { ... }                       // 是否有敏感 API
critical := api.FilterSensitiveAPIs(endpoints, api.SensCritical) // 按等级过滤

// --- JSON 安全分析 ---
if !api.IsJSONSafe(jsonData) {                                  // JSON 是否含敏感数据
    fmt.Printf("风险评分: %.0f\n", api.JSONRiskScore(jsonData)) // JSON 风险评分
}
finding, _ := api.ScanEndpointJSON(endpoint, jsonData)          // 端点 JSON 安全分析
findings, _ := api.ScanEndpointsJSON(endpoints, dataMap)        // 批量端点 JSON 分析

// --- Swagger 文档分析 ---
doc, swaggerEps, _ := api.LoadSwagger("https://api.example.com/v3/api-docs") // 远程加载
swaggerEps, _ := api.ParseSwagger([]byte(data))                             // 本地解析
auth, noauth, _ := api.CheckSwaggerAuth("https://api.example.com/v3/api-docs") // 认证覆盖

// --- 参数分析 ---
fmt.Println(api.AnalyzeParams(endpoint))                        // 单端点参数分析
names, summary := api.CollectSensitiveParams(endpoints)         // 收集敏感参数
added, removed := api.DiffAPIs(v1Endpoints, v2Endpoints)        // API 版本差异

// --- 攻击面分析 ---
fmt.Println(api.ScanAttackSurface(endpoints))                   // 攻击面分析摘要
top3 := api.TopRiskAPIs(endpoints, 3)                           // Top N 风险 API
if api.HasRiskyAPI(endpoints, 70) { ... }                       // 是否有高风险 API

// --- HTTP 探测 ---
result := api.ProbeAPI(endpoint, "https://example.com")         // 单端点探测
fmt.Println(api.ProbeAPIs(endpoints, "https://example.com"))    // 批量探测摘要
fmt.Println(api.QuickProbe("https://example.com", "/health", "/admin")) // 最简探测
isVuln := api.TestAuth(endpoint, "https://example.com")         // 认证绕过
fmt.Println(api.QuickAuthTest("https://example.com", "/health", "/admin")) // 批量认证测试

// --- 综合报告 ---
fmt.Println(api.QuickSecurityReport("example.com", endpoints))  // 一键安全报告
if api.HasRiskyEndpoints(endpoints) { ... }                      // 是否有风险端点
```

### easy 安全分析速查表

| 函数 | 返回 | 说明 |
|------|------|------|
| **敏感 API 分类** | | |
| `ClassifyAPIs(eps)` | `[]*SensitiveAPI` | 批量敏感 API 分类 |
| `CountSensitiveAPI(eps)` | `string` | 敏感 API 统计摘要 |
| `HasSensitiveAPI(eps)` | `bool` | 是否有敏感 API |
| `FilterSensitiveAPIs(eps, minLevel)` | `[]*SensitiveAPI` | 按等级过滤 |
| **JSON 安全分析** | | |
| `IsJSONSafe(jsonData)` | `bool` | JSON 是否含敏感数据 |
| `JSONRiskScore(jsonData)` | `float64` | JSON 风险评分 (0-100) |
| `ScanEndpointJSON(ep, json)` | `(*SecJsonFinding, error)` | 端点 JSON 安全分析 |
| `ScanEndpointsJSON(eps, data)` | `([]*SecJsonFinding, error)` | 批量端点 JSON 分析 |
| **Swagger 分析** | | |
| `LoadSwagger(url)` | `(*SwaggerDoc, []APIEndpoint, error)` | 远程加载 Swagger |
| `ParseSwagger(data)` | `([]APIEndpoint, error)` | 本地解析 Swagger |
| `CheckSwaggerAuth(url)` | `(auth, noauth int, err)` | 快速检查认证覆盖 |
| **参数分析** | | |
| `AnalyzeParams(ep)` | `string` | 单端点参数分析摘要 |
| `CollectSensitiveParams(eps)` | `([]string, string)` | 收集所有敏感参数 |
| `DiffAPIs(old, new)` | `(added, removed int)` | API 版本新增/删除计数 |
| **攻击面分析** | | |
| `ScanAttackSurface(eps)` | `string` | 攻击面分析摘要 |
| `TopRiskAPIs(eps, n)` | `[]*AttackSurface` | Top N 最高风险 |
| `HasRiskyAPI(eps, minScore)` | `bool` | 是否有高风险 API |
| **HTTP 探测** | | |
| `ProbeAPI(ep, baseURL)` | `*APIProbeResult` | 单端点探测 |
| `ProbeAPIs(eps, baseURL)` | `string` | 批量探测摘要 |
| `QuickProbe(baseURL, paths...)` | `string` | 最简探测（只传路径名） |
| `TestAuth(ep, baseURL)` | `bool` | 认证绕过检测 |
| `QuickAuthTest(baseURL, paths...)` | `string` | 批量认证绕过摘要 |
| **综合报告** | | |
| `QuickSecurityReport(target, eps)` | `string` | 一键安全报告 |
| `HasRiskyEndpoints(eps)` | `bool` | 是否有任何风险端点 |

---

## 路径归一化

自动识别路径中的动态段，将其替换为命名占位符，避免因参数值差异导致重复记录：

```go
path := "/user/550e8400-e29b-41d4-a716-446655440000"
norm := api.NormalizePath(path)  // "/user/{uuid}"
```

### 归一化规则（按优先级）

| 原始段 | 替换为 | 示例 |
|--------|--------|------|
| 64 位十六进制 | `{hash_sha256}` | `/file/e3b0c44...` |
| 40 位十六进制 | `{hash_sha1}` | `/file/da39a3e...` |
| 32 位十六进制 | `{hash_md5}` | `/file/d41d8cd9...` |
| UUID 格式 | `{uuid}` | `/user/550e8400-e29b-...` |
| ISO 日期 | `{date}` | `/report/2024-01-15` |
| 10-13 位数字 | `{timestamp}` | `/event/1704067200` |
| 24 位十六进制 | `{object_id}` | `/obj/507f1f77bcf8...` |
| 6 位以上数字 | `{id}` | `/user/12345` |
| 任意长度数字 | `{id}` | `/item/42` |

### 辅助判断函数

| 函数 | 说明 |
|------|------|
| `NormalizePath(path)` | 归一化单个路径 |
| `NormalizePaths(endpoints)` | 批量归一化端点列表 |
| `IsStaticResource(path)` | 判断是否为静态资源（22 种扩展名） |
| `IsAPIPath(path)` | 判断是否为 API 路径（前缀 `/api/`、`/graphql`、后缀 `.json` 等） |
| `IsLowConfidence(path)` | 判断是否含低可信词（test/demo/staging 等） |
| `ExtractSegments(path)` | 提取路径段列表 |
| `ExtractPrefix(path, depth)` | 提取指定深度的路径前缀 |
| `ExtractCommonPrefixes(endpoints)` | 提取出现 ≥2 次的前缀列表 |

---

## 置信度调整逻辑

`AdjustConfidence` 根据端点特征自动修正置信度：

| 条件 | 调整 | 说明 |
|------|------|------|
| 路径含低置信词（test/demo/dev 等） | `-0.2` | 可能是测试/调试端点 |
| 路径匹配 API 特征（/api/、/graphql 等） | `+0.05` | 增强 API 路径可信度 |
| 路径为静态资源 | `-0.5` | 静态文件不应被标记为 API |
| 出现次数 >10 | `+0.05` | 高频调用增强可信度 |
| 结果范围限制 | `[0.0, 1.0]` | 置信度始终在合法范围内 |

---

## 报告格式

`ExportJSON` 生成的 JSON 报告结构：

```json
{
  "metadata": {
    "generated_at": "2026-05-15T10:30:00Z",
    "version": "1.0.0",
    "target": "example.com",
    "total_apis": 47,
    "sources": ["traffic", "js_parse"],
    "mode": "full"
  },
  "endpoints": [
    {
      "path": "/api/v1/users/{id}",
      "methods": ["GET", "POST"],
      "host": "example.com",
      "port": 443,
      "confidence": 1.0,
      "source": "traffic",
      "seen_count": 152
    }
  ],
  "stats": {
    "by_confidence": {"high": 23, "medium": 18, "low": 6},
    "by_method": {"GET": 38, "POST": 15, "DELETE": 4},
    "by_source": {"traffic": 30, "js_parse": 17},
    "static_filtered": 0,
    "low_confidence": 4
  }
}
```

| 报告函数 | 说明 |
|----------|------|
| `GenerateReport(target, endpoints, mode)` | 生成完整 Report 结构体 |
| `report.SaveJSON(path)` | 保存报告为 JSON 文件 |
| `report.ToJSON()` | 返回 JSON 字符串 |
| `ExportEndpointsJSON(endpoints, path)` | 仅导出端点列表 |
| `ExportJSON(target, endpoints, mode, path)` | 便捷导出完整报告 |

---

## 输入文件格式一览

### PCAP 文件

标准 libpcap 格式，通过 `ano.LoadPcap` 读取，自动提取 HTTP 请求行：

```
支持扩展名: .pcap, .pcapng, .cap
```

### JSON 日志

每行一个 JSON 对象，支持的字段：

```jsonl
{"method": "GET", "url": "https://example.com/api/users", "count": 10}
{"method": "POST", "path": "/api/orders", "host": "example.com", "port": 443}
```

### URL 列表

纯文本格式，每行一个端点：

```
GET /api/users
POST /api/users
GET /api/v1/products/123
DELETE /api/products/456
```

---

## 核心指标要求

| 指标 | 达标要求 | 实现方式 |
|------|----------|---------|
| **覆盖率** | ≥95% | 依赖被动流量质量 + JS 解析 + 主动探测补全 |
| **误报率** | ≤5% | 静态资源过滤 + 置信度分级 + 低置信词降权 |
| **置信度分级** | 必须包含 | 流量=1.0 / JS=0.8 / 探测=0.6 |
| **动态参数识别率** | ≥90% | 9 级正则归一化（UUID/ID/Hash/Date/Timestamp） |

---

## 资源控制与安全约束

| 约束 | 实现 |
|------|------|
| 主动探测默认关闭 | `ActiveProbe` 需显式设为 `true` |
| 探测配额上限 | `ProbeLimit` 默认 1000，可配置 |
| 大文件自动截断 | JS >10MB 仅分析前 2MB |
| 并发速率限制 | `RateLimit` 默认 10 并发 |
| 无漏洞检测逻辑 | 库内不包含任何测试载荷 |
| 仅 HTTPS 探测 | `AllowHTTP` 默认 `false` |
| 严格资产测绘定位 | 仅识别端点，不做风险评估 |

---

## 敏感 API 识别与分类 (`sensitive.go`)

在 API 发现的基础上，自动识别**高风险 API 端点**并进行分类分级。三套规则体系交叉匹配：

- **49 种路径模式**：匹配 `/admin` `/login` `/auth` `/payment` `/debug` `/webhook` 等敏感路径
- **18 种参数模式**：检测 `api_key` `token` `password` `credit_card` `ssn` 等敏感参数名
- **方法+路径组合规则**：POST 到 `/login`/`/auth` 判定为 Critical，DELETE 到 `/user`/`/order` 判定为 Critical

### 敏感等级

| 等级 | 常量 | 风险分 | 说明 |
|------|------|--------|------|
| critical | `SensCritical` | 90 | 支付、认证、密钥操作 |
| high | `SensHigh` | 70 | 用户数据、管理接口、文件上传 |
| medium | `SensMedium` | 50 | 配置、导出、批量操作 |
| low | `SensLow` | 25 | 健康检查、仪表盘 |
| info | `SensInfo` | 10 | 信息性接口 |
| none | `SensNone` | 0 | 无敏感特征 |

### 敏感类别（13 类）

`auth` `admin` `user` `payment` `security` `internal` `config` `data_export` `health_check` `debug` `file_upload` `webhook` `third_party`

### 使用示例

```go
// 批量分类
sas := api.ClassifySensitiveAPIs(endpoints)

// 仅保留 critical + high
highRisk := api.FilterBySensitivity(sas, api.SensHigh)

// 按类别分组
byCat := api.GroupBySensitivityCategory(sas)
adminAPIs := byCat[api.CatAdmin]
paymentAPIs := byCat[api.CatPayment]

// 格式化摘要
fmt.Println(api.SensitiveSummary(sas))
// 敏感API总数: 15
//   按级别: critical:5个, high:7个, medium:3个
//   按类别: admin:8个, payment:3个, auth:2个

// 含参数分析的单端点分类
for _, ep := range endpoints {
    sa := api.ClassifySensitiveAPI(ep)
    if sa.Sensitivity != api.SensNone {
        fmt.Printf("  [%s] %s → %s\n", sa.Sensitivity, ep.Path, sa.Reason)
    }
}
```

### 参数敏感度检测

```go
params := url.Values{"api_key": {"xxx"}, "token": {"yyy"}}
results := api.AnalyzeSensitiveParameters(params)
for _, r := range results {
    fmt.Printf("  [%s] %s\n", r.Sensitivity, r.Reason)
    // [critical] 密钥参数 (api_key)
    // [critical] Token参数 (token)
}
```

### 函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `ClassifySensitiveAPI(ep)` | `*SensitiveAPI` | 单端点分类 |
| `ClassifySensitiveAPIs(eps)` | `[]*SensitiveAPI` | 批量分类（自动过滤非敏感） |
| `AnalyzeSensitiveParameters(params)` | `[]SensitiveAPI` | 参数敏感度分析 |
| `AnalyzeEndpointParams(ep)` | `*SensitiveAPI` | 端点 + 参数联合分析 |
| `FilterBySensitivity(sas, minLevel)` | `[]*SensitiveAPI` | 按最低等级过滤 |
| `GroupBySensitivityCategory(sas)` | `map[Category][]*SensitiveAPI` | 按类别分组 |
| `SensitiveSummary(sas)` | `string` | 格式化摘要 |

---

## JSON 响应敏感数据分析 (`secjson_integration.go`)

与 [secJson](../secJson) 库深度集成，对 API 端点返回的 JSON 响应体进行敏感数据识别，自动检测身份证号、银行卡号、手机号、JWT Token、API 密钥等敏感字段，并将结果反向增强敏感 API 分类。

### 使用示例

```go
// 准备 JSON 响应数据（key 为端点路径）
dataMap := map[string]string{
    "/api/user":  `{"id_card":"110101199001011234","phone":"13800138000"}`,
    "/api/order": `{"bank_card":"6222021234567890123"}`,
}

// 批量分析端点的 JSON 响应
findings, _ := api.AnalyzeMultipleEndpoints(endpoints, dataMap, nil)

// 按风险评分过滤
risky := api.SecJsonFindSensitiveEndpoints(findings, 50)
fmt.Printf("高风险 JSON 端点: %d 个\n", len(risky))

// JSON 评分反向增强敏感 API 分类
sas := api.ClassifySensitiveAPIs(endpoints)
enhanced := api.SecJsonUpdateEndpointSensitivity(sas, findings)

// 快速生成 JSON 安全报告
report, _ := api.SecJsonQuickReport(endpoints, dataMap)
fmt.Println(report)

// 汇总统计
fmt.Println(api.SecJsonSummary(findings))
// secJson分析摘要:
//   分析端点: 12 个
//   总字段数: 86
//   敏感匹配: 23 个
//   脱敏问题: 5 个
//   合规问题: 3 个
//   高风险端点: 4 个
```

### 函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `AnalyzeEndpointWithSecJson(ep, json, cfg)` | `(*SecJsonFinding, error)` | 单端点 JSON 分析 |
| `AnalyzeMultipleEndpoints(eps, dataMap, cfg)` | `([]*SecJsonFinding, error)` | 批量端点 JSON 分析 |
| `SecJsonQuickReport(eps, dataMap)` | `(string, error)` | 快速文本报告 |
| `SecJsonFindSensitiveEndpoints(fs, minScore)` | `[]*SecJsonFinding` | 按评分过滤 |
| `SecJsonUpdateEndpointSensitivity(sas, fs)` | `[]*SensitiveAPI` | JSON 评分增强敏感分类 |
| `SecJsonSummary(findings)` | `string` | 格式化摘要 |
| `SecJsonExtractEndpoints(findings)` | `[]*APIEndpoint` | 提取原始端点 |
| `DefaultSecJsonConfig()` | `*SecJsonAnalysisConfig` | 默认配置 |

---

## Swagger/OpenAPI 文档分析 (`swagger.go`)

从 OpenAPI (3.0) / Swagger 文档中自动解析并提取 API 端点清单，同时进行认证检查和敏感操作识别。

### 使用示例

```go
// 从远程 URL 获取 Swagger 文档
doc, endpoints, err := api.DiscoverSwagger("https://api.example.com/v3/api-docs")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Swagger 文档: %s v%s, %d 个端点\n",
    doc.Info.Title, doc.Info.Version, len(endpoints))

// 按认证分类
auth, noauth := api.SwaggerEndpointsByAuth(endpoints)
fmt.Printf("需要认证: %d, 无需认证: %d\n", len(auth), len(noauth))

// 检测未受保护的敏感 API
unprotected := api.SwaggerCheckUnprotectedSensitiveAPIs(endpoints)
for _, ep := range unprotected {
    fmt.Printf("  ⚠ %s %s (%s)\n", ep.Method, ep.Path, ep.Summary)
}

// 按 Tag 分组
byTag := api.SwaggerEndpointsByTag(endpoints)
for tag, eps := range byTag {
    fmt.Printf("  [%s] %d 个端点\n", tag, len(eps))
}
```

### 本地 JSON 解析

```go
data, _ := os.ReadFile("swagger.json")
doc, endpoints, err := api.ParseSwaggerJSON(data)
```

### 函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `DiscoverSwagger(url)` | `(*SwaggerDoc, []*APIEndpoint, error)` | HTTP 获取并解析 |
| `ParseSwaggerJSON(data)` | `(*SwaggerDoc, []*APIEndpoint, error)` | 本地 JSON 解析 |
| `ExtractSwaggerEndpoints(doc)` | `[]*SwaggerEndpoint` | 提取结构化端点 |
| `SwaggerEndpointsByAuth(eps)` | `(auth, noauth []*SwaggerEndpoint)` | 按认证分类 |
| `SwaggerEndpointsByTag(eps)` | `map[string][]*SwaggerEndpoint` | 按 Tag 分组 |
| `SwaggerCheckUnprotectedSensitiveAPIs(eps)` | `[]*SwaggerEndpoint` | 检测未保护敏感 API |
| `SwaggerSummary(eps)` | `string` | 格式化摘要 |

---

## API 参数深度分析 (`parameter_analysis.go`)

对 API 端点的参数进行语义分类、类型推断和注入风险评估，支持多版本 API 对比分析。

### 参数类型推断（10 种规则）

| 规则 | 类型 | 示例 |
|------|------|------|
| `^id$` | identifier | `id` |
| `_id$` | foreign_key | `user_id` |
| `^is_\|^has_` | boolean | `is_active`, `has_permission` |
| `_at$\|^created` | datetime | `created_at`, `updated_at` |
| `^email` | email | `email`, `email_address` |
| `^phone\|^mobile` | phone | `phone`, `mobile` |
| `_url$\|_link$` | url | `avatar_url`, `href` |
| `^status$\|^type$` | enum | `status`, `type` |
| `_count$\|_total$` | number | `total_count`, `amount` |
| `^file$\|^image$` | file | `file`, `avatar` |

### 参数分类

| 类别 | 判定条件 | 风险权重 |
|------|---------|----------|
| credential | 含 password/secret/token/key | +25 |
| pii | 含 email/phone/address/name | +15 |
| financial | 含 amount/price/card/account | +20 |
| file | 含 file/image/photo | +18 |
| url | 含 url/link/redirect | +15 |

### 注入风险检测（8 种规则）

| 参数模式 | 风险等级 | 风险描述 |
|---------|---------|---------|
| search/query/filter | high | 搜索/查询参数（SQL 注入） |
| id/user_id/order_id | high | ID 参数（越权风险） |
| sort/order_by | medium | 排序参数 |
| limit/offset/page | low | 分页参数（DoS 风险） |
| callback/redirect/return_url | high | 重定向参数（SSRF 风险） |
| file/path/filename | critical | 文件路径参数（路径遍历） |
| url/link/href | high | URL 参数（SSRF 风险） |
| format/output | medium | 格式参数 |

### 使用示例

```go
// 单端点参数分析
pa := api.AnalyzeParamDetails(endpoint)
fmt.Println(api.ParamAnalysisSummary(pa))
// 参数分析摘要:
//   参数总数: 5
//   风险等级: high
//   必填参数: 2
//   注入风险参数: 3

// 批量敏感参数检测
params := api.DetectSensitiveParams(endpoints)
for _, p := range params {
    fmt.Printf("  [%s] %s → %s\n", p.Risk, p.Param, p.Category)
    // [critical] api_key → credential
    // [high] email → pii
}

// API 版本对比
v1, _ := api.DiscoverJS("example.com", "./v1/")
v2, _ := api.DiscoverJS("example.com", "./v2/")
diff := api.CompareAPIVersions(v1, v2)
fmt.Printf("新增: %d, 删除: %d, 修改: %d\n",
    len(diff.Added), len(diff.Removed), len(diff.Modified))
```

### 函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `AnalyzeParamDetails(ep)` | `*ParamAnalysis` | 单端点参数深度分析 |
| `DetectSensitiveParams(eps)` | `[]SensitiveParam` | 批量敏感参数检测 |
| `CompareAPIVersions(old, new)` | `*APICompareResult` | 两版本端点对比 |
| `AnalyzeMultiVersionAPIs(base, compare)` | `*APICompareResult` | 多版本 API 对比 |
| `ParamAnalysisSummary(pa)` | `string` | 格式化摘要 |

---

## API 攻击面分析 (`attack_surface.go`)

基于**路径模式 + 方法特征**的自动化攻击面测绘，识别 9 类风险面，支持分级过滤和 Top N 排序。

### 9 类攻击面

| 类别 | 风险分 | 检测内容 |
|------|--------|---------|
| `admin_api` | 85 | 管理后台、控制台、仪表盘暴露 |
| `auth_api` | 60~90 | 登录、注册、密码重置、Token 接口 |
| `data_leak_api` | 70~95 | 支付/交易/用户数据/GraphQL 接口暴露 |
| `debug_api` | 95 | 调试接口（debug/trace/pprof/actuator/metrics） |
| `internal_api` | 80 | 配置接口（config/env/setting） |
| `file_api` | 80 | 文件上传接口暴露 |
| `injection_api` | 90 | 原始查询/执行接口（sql/raw/execute） |
| `unauth_api` | 85~95 | 支付/用户数据接口可能未认证 |
| `high_risk_api` | 75 | Webhook 回调接口暴露 |

### 使用示例

```go
// 全量攻击面分析
surfaces := api.AnalyzeAttackSurfaces(endpoints)

// 按类别定向查找
adminAPIs := api.FindAdminAPIs(endpoints)
authAPIs  := api.FindAuthAPIs(endpoints)
leakAPIs  := api.FindDataLeakAPIs(endpoints)
debugAPIs := api.FindDebugAPIs(endpoints)

// 按风险分过滤
critical := api.FilterByRiskScore(surfaces, 80)

// Top N 最高风险
top10 := api.TopRiskyAPIs(surfaces, 10)
for _, as := range top10 {
    fmt.Printf("  [%s] %.0f %s\n", as.Severity, as.RiskScore, as.Endpoint.Path)
}

// 格式化摘要
fmt.Println(api.AttackSurfaceSummary(surfaces))
// 攻击面分析摘要:
//   总风险API: 23 个
//   critical: 5 个
//   high: 12 个
//   medium: 6 个
//   各类别: admin_api:8, auth_api:5, data_leak_api:3, debug_api:2
```

### 函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `AnalyzeAttackSurface(ep)` | `*AttackSurface` | 单端点攻击面分析 |
| `AnalyzeAttackSurfaces(eps)` | `[]*AttackSurface` | 全量攻击面分析 |
| `FindAdminAPIs(eps)` | `[]*AttackSurface` | 管理后台接口 |
| `FindAuthAPIs(eps)` | `[]*AttackSurface` | 认证接口 |
| `FindDataLeakAPIs(eps)` | `[]*AttackSurface` | 数据泄露类接口 |
| `FindDebugAPIs(eps)` | `[]*AttackSurface` | 调试接口 |
| `FilterByRiskScore(ss, minScore)` | `[]*AttackSurface` | 按风险分过滤 |
| `TopRiskyAPIs(ss, n)` | `[]*AttackSurface` | Top N 排序 |
| `AttackSurfaceSummary(ss)` | `string` | 格式化摘要 |

---

## HTTP 实时探测 (`httpclient_integration.go`)

与项目自带的 [httpclient](../httpclient) 库深度集成，对发现的 API 端点进行实时 HTTP 验证探测，支持认证绕过测试。

### 使用示例

```go
// 单端点探测
result := api.ProbeEndpointWithHTTP(endpoint, "https://example.com")
fmt.Printf("  [%d] %s (%d bytes, type=%s)\n",
    result.StatusCode, result.URL, result.ResponseSize, result.ContentType)

// 批量探测
results := api.ProbeEndpointsWithHTTP(endpoints, "https://example.com")
fmt.Println(api.ProbeSummary(results))
// HTTP探测摘要:
//   总探测端点: 47 个
//   可访问: 42 个
//   JSON响应: 23 个
//   HTTP 200: 35 个
//   HTTP 401: 5 个
//   HTTP 404: 7 个

// 认证绕过测试（批量测试所有 high 级别敏感 API）
sas := api.ClassifySensitiveAPIs(endpoints)
vulns := api.TestAllAuthBypass(sas, "https://example.com")
for _, v := range vulns {
    if v.IsVulnerable {
        fmt.Printf("  ⚠ %s → %s\n", v.Endpoint.Path, v.Description)
    }
}

// 多方法探测（GET/POST/PUT/DELETE/OPTIONS）
methods := api.ProbeEndpointMethods(endpoint, "https://example.com")
for _, r := range methods {
    fmt.Printf("  %s → [%d] %s\n", r.Method, r.StatusCode, r.ContentType)
}
```

### 函数速查

| 函数 | 返回 | 说明 |
|------|------|------|
| `ProbeEndpointWithHTTP(ep, baseURL)` | `*APIProbeResult` | 单端点探测 |
| `ProbeEndpointsWithHTTP(eps, baseURL)` | `[]*APIProbeResult` | 批量探测 |
| `ProbeEndpointMethods(ep, baseURL)` | `[]*APIProbeResult` | 多方法探测 |
| `TestAuthenticationBypass(ep, baseURL)` | `[]*APISecurityTest` | 单端点认证绕过测试 |
| `TestAllAuthBypass(sas, baseURL)` | `[]*APISecurityTest` | 批量认证绕过测试 |
| `ProbeStatusCounts(results)` | `map[int]int` | 状态码计数 |
| `ProbeSummary(results)` | `string` | 格式化摘要 |

---

## 架构一览

| 文件 | 职责 |
|------|------|
| `api.go` | 核心类型定义（APIEndpoint/APIAssetList/DiscoveryConfig）+ DiscoveryEngine 编排器 |
| `normalizer.go` | 路径归一化（9 级正则替换）、静态资源判断、API 路径判断、低置信度判断 |
| `passive.go` | 被动流量分析：PCAP 解析、JSON 日志解析、URL 列表解析 |
| `js_parser.go` | 前端代码深度解析：12 种正则模式、baseURL 还原、目录递归扫描 |
| `prober.go` | 主动探测：动态候选生成、并发验证、响应特征判断 |
| `dedup.go` | 去重聚合：按 Path+Host+Port+Method 去重、置信度排序、静态资源过滤 |
| `confidence.go` | 置信度调整：路径特征加减分、按阈值过滤 |
| `report.go` | JSON 报告生成：元数据 + 端点列表 + 统计信息 |
| `sensitive.go` | 敏感 API 识别：49 种路径模式 + 18 种参数模式 + 13 类敏感分组 |
| `secjson_integration.go` | JSON 响应敏感分析：集成 secJson 库，敏感字段检测 + 反向增强分类 |
| `swagger.go` | Swagger/OpenAPI 解析：HTTP 获取 + JSON 解析 + 认证检查 |
| `parameter_analysis.go` | 参数深度分析：10 类类型推断 + 8 种注入风险 + 版本对比 |
| `attack_surface.go` | 攻击面测绘：9 类风险面检测 + Top N 排序 |
| `httpclient_integration.go` | HTTP 实时探测：端点验证 + 认证绕过测试 |

---

## 典型工作流

```
数据采集                   分析处理                    资产输出
┌──────────┐           ┌──────────────┐           ┌──────────┐
│ PCAP 文件 │──被动分析──→│ 提取 HTTP 请求│──标记 1.0──→│          │
│ JSON 日志 │           │ 过滤静态资源  │           │ JSON 报告 │
│ URL 列表  │           └──────────────┘           │          │
└──────────┘                                       │ 端点列表  │
                                                    │          │
┌──────────┐           ┌──────────────┐           │ 置信度    │
│ JS 源码   │──JS 解析──→│ 12 种正则匹配 │──标记 0.8──→│ 统计信息  │
│ HTML 页面 │           │ 语义还原路径  │           │          │
│ TSX 组件  │           └──────────────┘           └──────────┘
└──────────┘
                               ↓
┌──────────┐           ┌──────────────┐
│ 已发现前缀 │──主动探测──→│ 生成候选 URL │──标记 0.6──→
│ 26 种后缀 │           │ 并发 HTTP 验证│
└──────────┘           └──────────────┘
                    ↓
              ┌──────────┐
              │ 去重聚合  │
              │ 归一化    │
              │ 置信度调整 │
              └──────────┘
```

---

## License

Apache License 2.0