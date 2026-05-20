# bluez - 蓝牙安全渗透测试库

用于操作CSR蓝牙设备的安全渗透测试模块，覆盖物理层、链路层、主机层和社会工程层四个层次的蓝牙安全攻防功能。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/bluez"
```

---

## 安全合规与运行模式

### 双模式设计

库默认运行在 **SAFE 模式**下，所有主动攻击功能被锁定。

| 模式 | 说明 | 允许的操作 |
|------|------|-----------|
| `MODE_SAFE` (默认) | 安全模式 | Scan, Audit, DiscoverableScan, RFSniff, TrackDevice, ClassToString, RSSIToDistance |
| `MODE_RED_TEAM` | 红队模式 | 所有攻击功能 (KNOB, BIAS, MITM, DoS, BlueBorne, Bluesnarfing, Bluebugging, FirmwareTamper, Bluejacking, WeakPINBrute, BLEPairingAttack) |

### 启用红队模式

**方式一：环境变量**

```bash
export BLUEZ_BYPASS_LEGAL=IAcceptFullLegalResponsibility
```

**方式二：代码调用**

```go
bluez.EnableRedTeam("IAcceptFullLegalResponsibility")
```

### 审计日志

所有攻击性操作执行时，自动生成不可篡改的审计日志，记录时间、目标MAC（已脱敏）、操作者IP和操作结果，每条日志附带SHA256签名。

```go
entries := bluez.GetAuditLog()
for _, e := range entries {
    fmt.Printf("[%s] op=%s target=%s success=%v sig=%s\n",
        e.Time.Format(time.RFC3339), e.Operation, e.TargetMAC, e.Success, e.Signature[:16])
}

integrity := bluez.VerifyAuditIntegrity()
fmt.Printf("日志完整性: %v\n", integrity)

bluez.ClearAuditLog()
```

### AuditEntry 结构

```go
type AuditEntry struct {
    Time       time.Time  // 操作时间
    Operation  string     // 操作名称
    TargetMAC  string     // 目标MAC (脱敏)
    CallerIP   string     // 调用者IP
    Success    bool       // 是否成功
    Details    string     // 操作详情
    Signature  string     // SHA256签名 (防篡改)
}
```

---

## 极简 API

```go
// 推荐方式：通过 bluez.New() 实例化
bz := bluez.New().
    Target("AA:BB:CC:DD:EE:FF").
    Timeout(10 * time.Second).
    Verbose(true).
    KeySize(1)

// 安全操作 (SAFE模式可用)
result := bz.Scan()
report := bz.SecurityAudit()
packets := bz.Sniff(30 * time.Second)
records := bz.Track(5 * time.Second)
discoverable := bz.Discoverable()

// 攻击操作 (需 RED_TEAM 模式)
knob := bz.KNOB()
bias := bz.BIAS()
mitm := bz.MITM()
replay := bz.Replay([]byte{0x00, 0x01})
bb := bz.BlueBorne()
snarf := bz.Bluesnarfing()
bug := bz.Bluebugging()
fw := bz.Firmware()

// BLE操作
bleDevices, _ := bz.BLEScan()
gattSvcs, _ := bz.BLEDiscoverGATT("AA:BB:CC:DD:EE:FF")
pairRes, _ := bz.BLEPairingAttack("AA:BB:CC:DD:EE:FF", "justworks")

// Context支持
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
bz.Context(ctx).Sniff(30 * time.Second)
```

---

## 快捷函数

> 以下函数提供向后兼容，推荐使用 `bluez.New()` 实例化方式以获得安全模式保护。

| 函数 | 说明 | 返回值 | 需要RED_TEAM |
|------|------|--------|-------------|
| `bluez.Scan()` | 扫描附近蓝牙设备 (含BLE) | `*ScanResult` | 否 |
| `bluez.Audit()` | 蓝牙安全审计 | `*AuditReport` | 否 |
| `bluez.RFSniff(timeout)` | RF嗅探捕获数据包 | `[]PacketRecord` | 否 |
| `bluez.TrackDevice(duration)` | 设备位置追踪 | `[]TrackRecord` | 否 |
| `bluez.DoSFlood(type, timeout)` | DoS洪水攻击 | `error` | 是 |
| `bluez.KNOBAttack(target)` | KNOB密钥协商攻击 | `*KNOBResult` | 是 |
| `bluez.BIASAttack(target)` | BIAS身份欺骗攻击 | `*BIASResult` | 是 |
| `bluez.MITMAttack(target)` | 中间人攻击 | `*MITMResult` | 是 |
| `bluez.ReplayAttack(target, data)` | 重放攻击 | `*ReplayResult` | 是 |
| `bluez.BlueBorne(target)` | BlueBorne漏洞检测 | `*BlueBorneResult` | 是 |
| `bluez.Bluesnarfing(target)` | Bluesnarfing数据窃取 | `*BluesnarfingResult` | 是 |
| `bluez.Bluebugging(target)` | Bluebugging设备劫持 | `*BluebuggingResult` | 是 |
| `bluez.FirmwareTamper(target)` | 固件篡改探测 | `*FirmwareResult` | 是 |
| `bluez.Bluejacking(msg)` | Bluejacking消息发送 | `*BluejackingResult` | 是 |
| `bluez.WeakPINBrute()` | 弱PIN暴力破解 | `[]WPScanResult` | 是 |
| `bluez.DiscoverableScan()` | 可发现设备扫描 | `[]DiscoverableDevice` | 否 |
| `bluez.AnalyzeDiscoverableRisk(devices)` | 可发现设备风险分析 | `[]string` | 否 |
| `bluez.RSSIToDistance(rssi, txPower)` | RSSI距离计算 | `float64` | 否 |
| `bluez.New()` | 创建BlueZ实例 | `*BlueZ` | - |
| `bluez.EnableRedTeam(token)` | 启用红队模式 | `error` | - |
| `bluez.DisableRedTeam()` | 禁用红队模式 | - | - |
| `bluez.GetAuditLog()` | 获取审计日志 | `[]AuditEntry` | - |
| `bluez.VerifyAuditIntegrity()` | 验证日志完整性 | `bool` | - |
| `bluez.BLEScan(ctx, timeout)` | BLE设备扫描 | `[]BLEDevice` | 否 |
| `bluez.BLEPairingAttack(ctx, target, method)` | BLE配对攻击 | `*BLEPairingResult` | 是 |
| `bluez.BLEDiscoverGATT(ctx, target)` | BLE GATT服务发现 | `[]GATTService` | 是 |

---

## BDAddr 隐私保护

默认情况下，设备MAC地址在日志和审计报告中会被脱敏处理。

```go
addr, _ := bluez.ParseBDAddr("AA:BB:CC:DD:EE:FF")

// 完整格式
addr.String()           // "AA:BB:CC:DD:EE:FF"

// 脱敏格式
addr.Anonymize()        // "AA:BB:CC...:EE:FF"
addr.SafeString(false)  // "AA:BB:CC...:EE:FF"

// Verbose模式下显示完整地址
addr.SafeString(true)   // "AA:BB:CC:DD:EE:FF"
```

---

## 统一 BlueZ API

推荐使用链式配置的统一入口，自动集成安全模式和审计日志。

```go
bz := bluez.New()

bz.Context(context.Background()).
    Target("AA:BB:CC:DD:EE:FF").
    Timeout(10 * time.Second).
    Verbose(true).
    PinCode("0000").
    KeySize(1).
    IOCap(bluez.IO_CAP_NO_INPUT_NO_OUTPUT).
    EncryptSize(7).
    BLEScanTimeout(5 * time.Second).
    BLEScanActive(true)

// 物理层操作
packets := bz.Sniff(30 * time.Second)
records := bz.Track(5 * time.Second)
bz.DoS("connection")

// 链路层操作
knob := bz.KNOB()
bias := bz.BIAS()
mitm := bz.MITM()
replay := bz.Replay([]byte{0x00, 0x01})

// 主机层操作
bb := bz.BlueBorne()
snarf := bz.Bluesnarfing()
bug := bz.Bluebugging()
fw := bz.Firmware()

// 社会工程
bj := bz.Bluejack("Hello from BlueZ!")
wp := bz.WeakPIN()
disc := bz.Discoverable()

// BLE操作
bleDevices, _ := bz.BLEScan()
gattServices, _ := bz.BLEDiscoverGATT("AA:BB:CC:DD:EE:FF")
pairingResult, _ := bz.BLEPairingAttack("AA:BB:CC:DD:EE:FF", "justworks")

// 综合扫描 (含BLE)
result := bz.Scan()
fmt.Printf("Br/EDR: %d, Discoverable: %d, BLE: %d\n",
    len(result.Devices), len(result.Discoverable), len(result.BLEDevices))

// 安全审计 (含BLE)
report := bz.SecurityAudit()
```

### Context 支持

所有长时间运行的操作支持 `context.Context` 取消：

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

bz.Context(ctx).Sniff(30 * time.Second)
```

---

## BLE 5.3/5.4 支持

### BLE 设备扫描

支持主动/被动BLE扫描，解析广播包中的设备名称、服务UUID、厂商ID和TX功率。

```go
ble := bluez.NewBLELayer()

cfg := bluez.DefaultBLEConfig()
cfg.ScanTimeout = 10 * time.Second
cfg.ActiveScan = true

ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()

devices, err := ble.Config(cfg).Scan(ctx)
for _, d := range devices {
    fmt.Printf("%s Name=%s RSSI=%d Services=%d\n",
        d.Address.SafeString(false), d.Name, d.RSSI, len(d.Services))
}
```

### BLEDevice 结构

```go
type BLEDevice struct {
    Address    BDAddr     // 设备地址
    AddrType   uint8      // 地址类型 (PUBLIC/RANDOM)
    Name       string     // 设备名称 (来自广播包)
    RSSI       int8       // 信号强度 dBm
    TxPower    int8       // 发射功率
    AdvType    uint8      // 广播类型
    Flags      uint8      // 广播标志
    Services   []UUID     // 广播的16位服务UUID列表
    CompanyID  uint16     // 厂商ID
    RawData    []byte     // 原始广播数据
    LastSeen   time.Time  // 最后发现时间
}
```

### BLE 配对攻击

支持三种BLE配对攻击模式：

```go
// Just Works 绕过攻击
result, _ := bz.BLEPairingAttack("AA:BB:CC:DD:EE:FF", "justworks")

// Passkey Entry 暴力破解
result, _ := bz.BLEPairingAttack("AA:BB:CC:DD:EE:FF", "passkey")

// 密钥重装攻击 (Key Reinstallation)
result, _ := bz.BLEPairingAttack("AA:BB:CC:DD:EE:FF", "keyreinstall")
```

### BLEPairingResult 结构

```go
type BLEPairingResult struct {
    Success       bool    // 是否成功
    PairingMethod uint8   // 配对方法
    TargetAddr    BDAddr  // 目标地址
    LTK           []byte  // 长期密钥
    EDIV          uint16  // 加密分集值
    RAND          []byte  // 随机数
    Details       string  // 详细信息
}
```

### BLE GATT 服务发现

```go
services, err := bz.BLEDiscoverGATT("AA:BB:CC:DD:EE:FF")
for _, svc := range services {
    fmt.Printf("Service: %s [0x%04X-0x%04X]\n",
        svc.UUID.String(), svc.StartHandle, svc.EndHandle)
}
```

### GATTService 结构

```go
type GATTService struct {
    UUID            UUID
    StartHandle     uint16
    EndHandle       uint16
    Primary         bool
    Characteristics []GATTCharacteristic
}
```

---

## 物理层与射频层

### RF嗅探

通过HCI原始套接字捕获空中的蓝牙射频信号，还原底层数据包。

```go
packets := bz.Sniff(30 * time.Second)

// 带Context
ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
phy := bluez.NewPhysicalLayer()
phy.Sniffer(&bluez.SnifferConfig{Timeout: 30 * time.Second, MaxPackets: 5000})
records, _ := phy.RFSniffWithContext(ctx)
```

### 位置追踪

利用RSSI信号强度估测设备距离。

```go
records := bz.Track(10 * time.Second)
for _, r := range records {
    fmt.Printf("%s RSSI:%d dBm Location:%s\n",
        r.Address.SafeString(false), r.RSSI, r.Location)
}

distance := bluez.RSSIToDistance(-65, 0)
```

### 拒绝服务攻击

```go
bz.DoS("inquiry")     // inquiry洪水
bz.DoS("connection")  // 连接洪水
bz.DoS("l2cap")       // L2CAP洪水
bz.DoS("pairing")     // 配对洪水
```

---

## 链路层与协议层

### KNOB 密钥协商攻击

强制降级加密密钥长度至1字节。

```go
result := bz.KeySize(1).KNOB()
fmt.Printf("Success: %v, Negotiated: %d bytes\n",
    result.Success, result.NegotiatedSize)
```

### BIAS 身份欺骗攻击

```go
result := bz.BIAS()
fmt.Printf("Auth Bypassed: %v\n", result.AuthBypassed)
```

### MITM 中间人攻击

```go
result := bz.MITM()
if result.SessionKey != nil {
    fmt.Printf("Session key captured: %x\n", result.SessionKey)
}
```

### 重放攻击与数据加解密

```go
// 捕获并提取ACL数据
link := bluez.NewLinkLayer()
packets, _ := link.CapturePackets(10 * time.Second)
aclData := link.ExtractACLData(packets)

// 重放
result := bz.Replay(aclData)

// 加解密
key := []byte{0x01, 0x02, 0x03, ...} // 16字节
encrypted, _ := link.EncryptACL(plaintext, key)
decrypted, _ := link.DecryptACL(encrypted, key)
```

---

## 主机层与应用层

### BlueBorne 漏洞检测

检测 CVE-2017-1000251、CVE-2017-1000250、CVE-2017-8628、CVE-2017-14315。

```go
result := bz.BlueBorne()
fmt.Printf("Vulnerable: %v, Exploit: %s\n", result.Vulnerable, result.ExploitType)
```

### Bluesnarfing 数据窃取

通过OBEX协议提取通讯录、短信等敏感文件。

```go
result := bz.Bluesnarfing()
for file, data := range result.Extracted {
    fmt.Printf("File: %s, Size: %d\n", file, len(data))
}
```

### Bluebugging 设备劫持

通过AT指令接管设备控制权。

```go
result := bz.Bluebugging()
for i, resp := range result.Responses {
    fmt.Printf("CMD: %s -> %s\n", result.CommandsSent[i], resp)
}
```

### 固件篡改探测

```go
result := bz.Firmware()
fmt.Printf("Version: %s, Patchable: %v\n", result.FirmwareVer, result.Patchable)
```

---

## 社会工程与配置层

### Bluejacking

```go
result := bz.Bluejack("您中奖了！点击链接领取奖品！")
fmt.Printf("Sent to %d devices\n", result.DevicesSent)
```

### 弱PIN暴力破解

尝试 `0000`, `1234`, `1111`, `5555` 等15个常用弱PIN。

```go
results := bz.WeakPIN()
for _, r := range results {
    if r.Success {
        fmt.Printf("Device %s vulnerable to PIN: %s\n",
            r.Address.SafeString(false), r.PinTried)
    }
}
```

### 可发现设备风险分析

```go
devices := bz.Discoverable()
risks := bluez.AnalyzeDiscoverableRisk(devices)
```

---

## 安全审计

自动执行综合安全审计，覆盖传统蓝牙和BLE设备。

```go
report := bluez.Audit()
fmt.Println(report.String())
```

### AuditReport 结构

```go
type AuditReport struct {
    Time          time.Time       // 审计时间
    TotalDevices  int             // 发现的设备总数 (含BLE)
    TotalFindings int             // 发现的问题总数
    RiskLevel     string          // NONE/LOW/MEDIUM/HIGH/CRITICAL
    Findings      []AuditFinding  // 详细发现列表
}
```

### AuditFinding 结构

```go
type AuditFinding struct {
    Severity string  // INFO/LOW/MEDIUM/HIGH/CRITICAL
    Category string  // Physical Layer/Link Layer/Host Layer/Social Layer/BLE/Configuration
    Title    string  // 问题标题
    Device   string  // 设备地址 (已脱敏，Verbose模式除外)
    Detail   string  // 详细描述
}
```

---

## BLEConfig 配置

```go
type BLEConfig struct {
    ScanTimeout     time.Duration  // 扫描超时，默认10s
    ScanWindow      time.Duration  // 扫描窗口，默认30ms
    ScanInterval    time.Duration  // 扫描间隔，默认60ms
    ScanType        uint8          // 扫描类型: ACTIVE/PASSIVE
    FilterDuplicates bool          // 是否过滤重复 (默认false)
    ActiveScan      bool           // 是否主动扫描 (默认true)
    Verbose         bool           // 详细输出
}
```

---

## 文件结构

```
bluez/
├── type.go         # 核心类型、常量、HCI结构、BDAddr隐私方法
├── socket.go       # 平台HCI套接字实现
├── platform.go     # 平台适配层 (L2CAP/网络)
├── enforcement.go  # 安全模式、审计日志、BDAddr隐私
├── physical.go     # 物理层与射频层功能 (含Context)
├── link.go         # 链路层与协议层功能
├── host.go         # 主机层与应用层功能
├── social.go       # 社会工程与配置层功能
├── ble.go          # BLE 5.3/5.4 支持 (扫描/GATT/配对攻击)
└── easy.go         # 统一API入口和快捷函数
```

---
## 法律警告与合规使用

### 重要声明

本库为**安全研究工具**，所有功能仅授权用于以下场景：

| 授权场景 | 说明 |
|---------|------|
| **自有设备测试** | 对您合法拥有或获得明确书面授权的设备进行安全测试 |
| **授权渗透测试** | 持有客户书面授权合同的红队/渗透测试项目 |
| **经授权的漏洞研究** | 在协调漏洞披露(CVD)计划下与厂商合作的研究 |
| **安全审计与教育** | 经授权的企业内部安全培训与合规审计 |

**禁止用途：**

- 未经授权对他人设备进行任何形式的扫描、攻击或数据窃取
- 用于商业间谍、隐私侵犯或任何非法监控
- 作为骚扰、跟踪或伤害他人的工具
- 在任何管辖区内违法的情况下使用

### 中国大陆地区特别提示

根据《中华人民共和国网络安全法》、《中华人民共和国刑法》相关条款：

- 非法侵入他人网络、干扰他人网络正常功能、窃取网络数据，构成犯罪的，依法追究刑事责任
- 购买、持有专门用于侵入、非法控制计算机信息系统的程序、工具，或明知他人从事侵入等违法犯罪活动而提供帮助的，均属违法
- 建议仅在持有设备授权或获得相关监管机构明确许可的情况下使用本库

### 欧盟地区特别提示

根据 GDPR 和欧盟网络安全法案，使用蓝牙安全工具时需注意：

- 处理设备标识符（如 MAC 地址）属于个人数据处理，需合法依据
- 未经同意收集设备信息可能违反数据最小化原则
- 渗透测试需符合 ePrivacy 指令要求

### 美国地区特别提示

根据《计算机欺诈与滥用法案》(CFAA)：

- 未经授权访问或超出授权范围访问计算机系统可能构成联邦犯罪
- 蓝牙 DoS 攻击可能触犯《打击非法监听法》和《电信法》
- 建议获取书面授权后再进行任何形式的远程测试

---

## 蓝牙安全防御指南

以下指南帮助开发者和安全运维人员防御本库所列攻击手段。

### 物理层防御

#### 防止射频嗅探与位置追踪

| 防御措施 | 实现方法 |
|---------|---------|
| **使用随机私有地址(RPA)** | BLE 4.2+ 设备应使用定期轮换的随机地址，而非固定 MAC |
| **降低广播功率** | 将设备 TX 功率设为最低有效值，减少信号覆盖范围 |
| **禁用不必要的广播** | 仅在需要连接时才发送广播包，避免长时间可发现 |
| **使用蓝牙 5.0+ 的定位防跟踪机制** | 支持 Extended Advertising 的设备可使用更难追踪的广播方式 |
| **RSSI 随机化** | 在广播包中加入随机 RSSI 值，防止通过信号强度精确追踪 |

```go
// BLE设备应配置随机地址
// Linux: btmgmt addr <random>
```

#### 防止 DoS 攻击

| 防御措施 | 说明 |
|---------|------|
| **限速连接请求** | 在 HCI 层配置连接请求速率限制 |
| **使用连接间隔随机化** | 避免可预测的连接参数，便于检测异常流量 |
| **固件级 DoS 防护** | 选择已修复相关漏洞的最新固件版本 |
| **网络隔离** | 对关键设备启用蓝牙与 WiFi/有线网络的物理隔离 |

### 链路层防御

#### 防止 KNOB 攻击

| 防御措施 | 实现方法 |
|---------|---------|
| **强制最小密钥长度** | 拒绝协商小于 7 字节的加密密钥 |
| **固件更新** | 确保设备使用修复了 CVE-2019-1866 等 KNOB 相关漏洞的固件 |
| **启用安全连接(Secure Connections)** | BLE 4.2+ 的安全连接模式强制 16 字节最小密钥 |
| **配对前验证** | 要求用户确认配对请求，避免静默协商 |

```go
// 检查设备是否支持安全连接
// Linux: hciconfig hci0 features | grep LE Secure Connections
```

#### 防止 BIAS 攻击

| 防御措施 | 实现方法 |
|---------|---------|
| **启用 Secure Connections** | 安全连接模式强制双向认证，防止扮演攻击 |
| **拒绝单方认证连接** | 仅接受已完成完整配对流程的连接 |
| **定期清除配对密钥** | 定期清除设备已存储的 link key，要求重新配对 |
| **使用 OOB 配对** | 优先使用带外(OOB)方式交换配对信息，避免被动窃听 |

```go
// 清除设备配对记录 (Linux)
 // hciconfig hci0 reset
 // blueman-device-manager 移除已配对设备
```

#### 防止重放攻击

| 防御措施 | 实现方法 |
|---------|---------|
| **使用会话随机数** | 每次会话使用唯一的随机数或计数器，防止重放历史数据 |
| **启用加密** | 所有敏感通信必须使用有效加密，防止数据被捕获重放 |
| **消息认证** | 使用 HMAC 或 CMAC 对消息进行认证，防止篡改 |

### 主机层防御

#### 防止 BlueBorne (CVE-2017-1000251/07851/07852/07853)

| 防御措施 | 实现方法 |
|---------|---------|
| **Linux 内核更新** | 升级到 4.14+ 或各发行版提供的最新蓝牙栈补丁 |
| **禁用不必要的 SDP 服务** | 编辑 /etc/bluetooth/main.conf，设置 `DisablePlugins = sap` |
| **关闭蓝牙自动处理** | 设置 `AutoEnable=false`，防止冷启动自动开启蓝牙 |
| **AppArmor/Selinux 限制** | 对 bluetoothd 服务施加最小权限 |
| **BlueZ 6.50+** | 使用修复了相关漏洞的 BlueZ 版本 |

```bash
# 检查 BlueZ 版本 (Linux)
bluetoothctl version

# 检查内核蓝牙安全特性
cat /sys/kernel/debug/bluetooth/hci0/clock
```

#### 防止 Bluesnarfing / Bluebugging

| 防御措施 | 实现方法 |
|---------|---------|
| **禁用 OBEX 文件传输** | 在设备设置中关闭 "接受文件" 或 "FTP" 配置文件的选项 |
| **不使用时关闭蓝牙** | 养成不使用时关闭蓝牙的习惯 |
| **更新手机固件** | iOS 10.3+ 和 Android 8.0+ 已修复大部分相关漏洞 |
| **限制 AT 命令接口** | 厂商固件应限制 RFCOMM 通道上的 AT 命令权限 |
| **启用蓝牙 PIN 保护** | 使用复杂随机 PIN（至少 8 位数字字母混合） |

```bash
# 检查设备暴露的 RFCOMM 通道
sdptool browse <MAC>
```

#### 防止固件篡改

| 防御措施 | 实现方法 |
|---------|---------|
| **启用固件签名验证** | 使用支持安全启动(Secure Boot)的蓝牙芯片 |
| **固件加密** | 选择支持固件加密和完整性校验的芯片方案 |
| **定期检查固件版本** | 关注厂商安全公告，及时更新固件 |
| **禁用固件下载模式** | 在不需要更新的设备上禁用 DFU 模式 |

### 社会工程防御

#### 防止 Bluejacking

| 防御措施 | 实现方法 |
|---------|---------|
| **设备设置为不可发现** | 非配对需求时关闭 "可被发现" 模式 |
| **不响应未知 vCard** | 拒绝接收和打开来源不明的联系人信息 |
| **用户安全意识培训** | 不点击钓鱼链接，不下载未知来源文件 |
| **移动设备管理(MDM)** | 企业环境使用 MDM 策略限制蓝牙使用 |

#### 防止弱 PIN 攻击

| 防御措施 | 实现方法 |
|---------|---------|
| **使用随机 8 位 PIN** | 避免使用默认 PIN 或简单数字组合 |
| **启用 Secure Connections** | 安全连接模式不支持传统 PIN 配对 |
| **使用 OOB 或 LE Secure Connections 配对** | 避免使用 Just Works 或 PIN 配对方式 |
| **定期更换配对密钥** | 定期清除并重新配对，消除已泄露的 link key |

```bash
# Linux 下查看和清除 link key
cat /var/lib/bluetooth/*/linkkeys
# 删除对应设备的 link key 文件可强制重新配对
```

### BLE 专项防御 (针对 BLE 配对攻击)

#### 防止 Just Works 绕过

| 防御措施 | 实现方法 |
|---------|---------|
| **强制 Passkey Entry** | 在固件中配置 `IO_CAP_KEYBOARD_ONLY`，要求输入对方显示的随机数 |
| **使用 OOB 配对** | 通过 NFC 或其他带外通道交换配对数据 |
| **升级到 BLE 5.3** | BLE 5.3 引入的增强型 Passkey Entry 提供更好保护 |

#### 防止密钥重装攻击 (Key Reinstallation)

| 防御措施 | 实现方法 |
|---------|---------|
| **启用加密连接后拒绝重协商** | 实现上应禁止在已加密连接上重新发起密钥协商 |
| **使用第 7 次握手规则** | 按照 BLE 规范，在收到第 7 次握手消息后拒绝重连 |
| **固件更新** | 确保蓝牙控制器和主机栈支持防重装攻击的修复 |
| **使用带外认证** | 在配对过程中引入额外的带外认证步骤 |

### 企业级蓝牙安全策略建议

| 策略 | 具体措施 |
|------|---------|
| **设备清单管理** | 登记所有蓝牙设备，建立资产清单，记录 MAC、固件版本 |
| **定期安全评估** | 使用本库 Audit 功能定期扫描企业蓝牙设备风险 |
| **蓝牙使用策略** | 制定并执行 "在非信任区域关闭蓝牙" 等策略 |
| **固件更新流程** | 建立固件更新机制，确保设备及时修复已知漏洞 |
| **网络隔离** | 蓝牙设备不应作为渗透进入企业网络的跳板 |
| **安全意识培训** | 培训员工识别蓝牙钓鱼和 Bluejacking 社会工程攻击 |
| **日志留存** | 启用蓝牙管理员日志，满足合规审计要求 |

### 安全配置检查清单

```bash
# Linux - 验证蓝牙安全配置
# 1. 检查 BlueZ 版本
bluetoothctl version

# 2. 检查不可发现模式
hciconfig hci0
# 确认 PSCAN 和 ISCAN 标志为 0

# 3. 检查已配对设备数量
bluetoothctl paired-devices

# 4. 检查服务记录
sdptool browse local

# 5. 检查固件信息
hciconfig -a hci0 | grep Version

# 6. 检查内核蓝牙安全特性
cat /sys/kernel/debug/bluetooth/hci0/features
```

---

## 漏洞修复参考

| 漏洞编号 | 影响协议层 | 攻击名称 | 修复版本 |
|---------|----------|---------|---------|
| CVE-2019-1866 | Link Layer | KNOB Attack | BlueZ 5.52+, Linux 5.3+ |
| CVE-2020-10135 | Link Layer | BIAS Attack | BlueZ 5.53+ |
| CVE-2017-1000251 | Host Layer | BlueBorne (Linux RCE) | Linux 4.14.1+ |
| CVE-2017-8628 | Host Layer | BlueBorne (Windows) | MS17-040 |
| CVE-2017-14315 | Host Layer | BlueBorne (iOS/macOS) | iOS 10.3+, macOS 10.12.4+ |
| CVE-2018-5383 | Link Layer | Key Reinstallation | BlueZ 5.50+ |
| CVE-2022-2561 | Host Layer | BlueBorne (Android) | Android Security Bulletin 2022-02+ |
| CVE-2023-45866 | Host Layer | BlueBorne (Android) | Android Security Bulletin 2023-12+ |

---

## License

Apache License 2.0

---