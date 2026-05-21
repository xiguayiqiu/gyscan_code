# Wifie 库文档

Wifie 是一个完整的 WiFi 安全工具库，用于 WiFi 扫描、抓包、握手捕获和安全测试，支持 macOS 和 Linux。支持 CPU 多协程、CUDA GPU 和 OpenCL GPU 三种模式进行 WPA/WPA2 握手穷举破解。

---

## 目录

- [结构体定义](#结构体定义)
  - [WiFi 接口相关](#wifi-接口相关)
  - [WiFi 网络相关](#wifi-网络相关)
  - [帧处理相关](#帧处理相关)
  - [握手相关](#握手相关)
  - [PCAP 文件相关](#pcap-文件相关)
  - [抓包会话相关](#抓包会话相关)
- [公开函数](#公开函数)
  - [接口管理](#接口管理)
  - [信道管理](#信道管理)
  - [帧解析](#帧解析)
  - [握手捕获](#握手捕获)
  - [PCAP 文件操作](#pcap-文件操作)
  - [安全相关](#安全相关)
- [穷举破解相关](#穷举破解相关)
  - [破解配置与目标](#破解配置与目标)
  - [破解会话与结果](#破解会话与结果)
  - [GPU 设备](#gpu-设备)
- [示例程序](#示例程序)
  - [WPA 握手捕获示例](#wpa-握手捕获示例)
  - [WPA 握手穷举破解示例](#wpa-握手穷举破解示例)
  - [完整工作流：捕获 → 破解](#完整工作流捕获--破解)

---

## 结构体定义

### WiFi 接口相关

#### `WiFiInterface`

```go
type WiFiInterface struct {
    Name       string // 接口名称，例如 "wlp0s20f0u1"
    Index      int    // 系统索引
    MAC        string // MAC 地址
    Type       string // 类型："WiFi" 或其他
    Mode       string // 工作模式："Monitor" 或 "Managed"
    Channel    int    // 当前信道
    Freq       int    // 当前频率（MHz）
    TXPower    int    // 发射功率
    IsUp       bool   // 是否启用
    IsMonitor  bool   // 是否在监听模式
    Driver     string // 驱动名称
    Chipset    string // 芯片信息
}
```

#### `ChannelHopConfig`

```go
type ChannelHopConfig struct {
    Channels []int // 信道列表
    HopDelay int   // 信道切换延迟（毫秒）
}
```

---

### WiFi 网络相关

#### `WiFiNetwork`

表示扫描到的 WiFi 网络

```go
type WiFiNetwork struct {
    BSSID       string            // BSSID（AP 的 MAC 地址）
    ESSID       string            // ESSID（网络名称）
    Channel     int               // 工作信道
    Freq        int               // 频率（MHz）
    Signal      int               // 信号强度（dBm）
    Noise       int               // 噪声强度（dBm）
    Privacy     bool              // 是否加密
    Cipher      string            // 加密算法（CCMP、TKIP 等）
    Auth        string            // 认证方式（PSK、MGT 等）
    Standard    string            // 标准（WPA、WPA2、WPA3、WEP、Open）
    Rates       []float64         // 支持的速率列表
    MaxRate     float64           // 最大速率
    BeaconCount int               // 信标帧数
    DataCount   int               // 数据帧数
    FirstSeen   int64             // 首次发现时间戳
    LastSeen    int64             // 最后发现时间戳
    WPS         bool              // 是否启用 WPS
    Country     string            // 国家码
    Vendor      string            // 厂商信息
    HTCap       bool              // 是否支持 HT（802.11n）
    VHTCap      bool              // 是否支持 VHT（802.11ac）
    InfoElements map[int][]byte   // 信息元素原始数据
}
```

#### `WiFiStation`

表示关联到 AP 的客户端

```go
type WiFiStation struct {
    MAC         string   // 客户端 MAC 地址
    BSSID       string   // 关联的 AP 的 BSSID
    Signal      int      // 信号强度
    Noise       int      // 噪声
    Rate        float64  // 当前数据速率
    FirstSeen   int64    // 首次发现
    LastSeen    int64    // 最后发现
    Packets     int      // 发送/接收的包数量
    ProbedSSIDs []string // 探测的 SSID 列表
}
```

#### `ScanResult`

一次完整扫描的结果

```go
type ScanResult struct {
    Networks []*WiFiNetwork // 发现的网络列表
    Stations []*WiFiStation // 发现的客户端列表
    Duration float64        // 扫描耗时（秒）
    Channel  int            // 扫描信道
}
```

---

### 帧处理相关

#### `FrameType`

帧类型枚举

```go
type FrameType uint8

const (
    IEEE80211_FC0_TYPE_MGT  FrameType = 0x00 // 管理帧
    IEEE80211_FC0_TYPE_CTL  FrameType = 0x04 // 控制帧
    IEEE80211_FC0_TYPE_DATA FrameType = 0x08 // 数据帧
)
```

#### `FrameSubtype`

帧子类型枚举

```go
type FrameSubtype uint8

// 常见子类型：
// - IEEE80211_FC0_SUBTYPE_BEACON: 信标帧
// - IEEE80211_FC0_SUBTYPE_PROBE_REQ: 探测请求
// - IEEE80211_FC0_SUBTYPE_PROBE_RESP: 探测响应
// - IEEE80211_FC0_SUBTYPE_DEAUTH: 解除认证
// - IEEE80211_FC0_SUBTYPE_DISASSOC: 解除关联
// - IEEE80211_FC0_SUBTYPE_DATA: 数据帧
// - IEEE80211_FC0_SUBTYPE_QOS_DATA: QoS 数据帧
```

#### `RadiotapInfo`

Radiotap 头信息，包含物理层元数据

```go
type RadiotapInfo struct {
    Version       uint8  // 版本
    Pad           uint8  // 填充
    Length        uint16 // Radiotap 头长度
    Present       uint32 // 存在的字段标识
    TSFT          uint64 // TSF 时间戳
    Flags         uint8  // 标志
    Rate          uint8  // 速率
    Channel       int    // 信道
    ChannelFlags  uint16 // 信道标志
    Freq          int    // 频率（MHz）
    AntSignal     int8   // 天线信号强度（dBm）
    AntNoise      int8   // 天线噪声强度（dBm）
    Antenna       uint8  // 天线索引
    DataRate      float64// 数据速率（Mbps）
    HasFCS        bool   // 是否有 FCS
    BadFCS        bool   // FCS 是否错误
    WEP           bool   // 是否有 WEP
    Frag          bool   // 是否分片
}
```

#### `Frame80211`

802.11 帧结构体

```go
type Frame80211 struct {
    Raw       []byte        // 原始数据包
    FC0       uint8         // Frame Control 0
    FC1       uint8         // Frame Control 1
    Type      FrameType     // 帧类型
    Subtype   FrameSubtype  // 帧子类型
    Duration  uint16        // Duration 字段
    Addr1     string        // MAC 地址 1
    Addr2     string        // MAC 地址 2
    Addr3     string        // MAC 地址 3
    Addr4     string        // MAC 地址 4（仅在 DS to DS 模式）
    Seq       uint16        // 序列号
    Fragment  uint8         // 分片号
    QoSCtl    uint16        // QoS 控制（QoS 帧）
    ToDS      bool          // 是否发往 DS
    FromDS    bool          // 是否来自 DS
    Protected bool          // 是否加密
    Retry     bool          // 是否重传
    PwrMgmt   bool          // 电源管理
    MoreData  bool          // 更多数据
    MoreFrag  bool          // 更多分片
    Order     bool          // 顺序标识
    Body      []byte        // 帧体（Payload）
    FCS       uint32        // FCS
    Radiotap  *RadiotapInfo // Radiotap 信息（如存在）
}
```

---

### 握手相关

#### `EAPOLFrame`

EAPOL（可扩展认证协议）帧

```go
type EAPOLFrame struct {
    Version     uint8      // EAPOL 版本
    Type        uint8      // 帧类型
    Length      uint16     // 长度
    KeyDescType uint8      // 密钥描述类型
    KeyInfo     uint16     // 密钥信息字段
    KeyLength   uint16     // 密钥长度
    ReplayCtr   uint64     // 重放计数器
    KeyNonce    [32]byte   // Key Nonce
    KeyIV       [16]byte   // Key IV
    KeyRSC      [8]byte    // Key RSC
    KeyID       [8]byte    // Key ID
    KeyMIC      [16]byte   // Key MIC
    KeyDataLen  uint16     // Key Data 长度
    KeyData     []byte     // Key Data
    Raw         []byte     // 原始帧数据
}
```

#### `WPAHandshake`

WPA/WPA2 握手信息

```go
type WPAHandshake struct {
    BSSID     string         // AP 的 BSSID
    STAMAC    string         // 客户端的 MAC
    ANonce    [32]byte       // AP 的 Nonce
    SNonce    [32]byte       // 客户端的 Nonce
    EAPOLData [256]byte      // EAPOL 数据（用于 MIC 计算）
    EAPOLSize int            // EAPOL 数据大小
    MIC       [20]byte       // MIC 值
    Frame1    *EAPOLFrame    // 消息 1（来自 AP）
    Frame2    *EAPOLFrame    // 消息 2（来自 STA）
    Frame3    *EAPOLFrame    // 消息 3（来自 AP）
    Frame4    *EAPOLFrame    // 消息 4（来自 STA）
    Complete  bool           // 握手是否完整（已捕获 Msg1 + Msg2 或全部4个消息）
    State     int            // 状态标志
    Version   uint8          // 密钥描述类型版本
    PMKID     []byte         // PMKID（如果有）
}
```

#### WPA 握手状态常量

```go
const (
    WPA_STATE_ANONCE    = 1 << 0 // 已捕获 ANonce（Msg1）
    WPA_STATE_SNONCE    = 1 << 1 // 已捕获 SNonce（Msg2）
    WPA_STATE_EAPOLMIC  = 1 << 2 // 已捕获 EAPOL MIC
    WPA_STATE_COMPLETE  = 7      // 完整（ANonce | SNonce | EAPOLMIC）
)
```

---

### PCAP 文件相关

#### `PcapHeader`

PCAP 文件头

```go
type PcapHeader struct {
    MagicNumber  uint32 // 魔数 (0xa1b2c3d4)
    VersionMajor uint16 // 主版本
    VersionMinor uint16 // 次版本
    ThisZone     int32  // 时区
    SigFigs      uint32 // 时间戳精度
    SnapLen      uint32 // 最大捕获长度
    Network      uint32 // 链路层类型
}
```

#### `PcapRecord`

PCAP 单条记录

```go
type PcapRecord struct {
    Seconds      int64  // 秒
    Microseconds int64  // 微秒
    CapturedLen  int32  // 捕获长度
    OriginalLen  int32  // 原始长度
}
```

---

### 抓包会话相关

#### `CaptureConfig`

抓包配置

```go
type CaptureConfig struct {
    Iface    string        // 网卡接口名称
    BSSID    string        // 可选：目标 BSSID 过滤
    Channel  int           // 信道
    PcapFile string        // 可选：保存的 PCAP 文件路径
    Timeout  time.Duration // 超时时间，0 表示无超时
    BufSize  int           // 缓冲区大小，默认 65535
}
```

#### `CaptureSession`

抓包会话

```go
type CaptureSession struct {
    // 私有字段
    config     CaptureConfig
    stopCh     chan struct{}
    doneCh     chan struct{}
    pcapFile   *os.File
    handshakes map[string]*WPAHandshake
    mu         sync.Mutex
    packetsIn  int64
    startTime  time.Time
}
```

---

## 公开函数

### 接口管理

#### `ListInterfaces() ([]WiFiInterface, error)`

列出所有网络接口

```go
func ListInterfaces() ([]WiFiInterface, error)
```

示例：
```go
ifaces, err := wifie.ListInterfaces()
if err != nil {
    log.Fatal(err)
}
for _, iface := range ifaces {
    fmt.Printf("Name: %s, MAC: %s, IsMonitor: %v\n", iface.Name, iface.MAC, iface.IsMonitor)
}
```

---

#### `GetInterface(name string) (*WiFiInterface, error)`

获取指定名称的接口

```go
func GetInterface(name string) (*WiFiInterface, error)
```

---

#### `DefaultWiFiInterface() (*WiFiInterface, error)`

获取默认的 WiFi 接口

```go
func DefaultWiFiInterface() (*WiFiInterface, error)
```

---

#### `IsMonitorMode(name string) bool`

检查指定接口是否在监听模式

```go
func IsMonitorMode(name string) bool
```

---

#### `EnableMonitorMode(name string) (string, error)`

启用监听模式。如果需要会创建新的监控接口（例如 `wlan0mon`）。

```go
func EnableMonitorMode(name string) (string, error)
```

返回：监听模式接口的名称

---

#### `DisableMonitorMode(name string) error`

禁用监听模式

```go
func DisableMonitorMode(name string) error
```

---

### 信道管理

#### `SetChannel(iface string, channel int) error`

设置网卡工作信道

```go
func SetChannel(iface string, channel int) error
```

---

#### `SetFrequency(iface string, freq int) error`

设置网卡工作频率

```go
func SetFrequency(iface string, freq int) error
```

---

#### `GetCurrentChannel(iface string) int`

获取当前信道

```go
func GetCurrentChannel(iface string) int
```

---

#### `GetCurrentFrequency(iface string) int`

获取当前频率

```go
func GetCurrentFrequency(iface string) int
```

---

#### `SupportedChannels24GHz() []int`

获取标准的 2.4 GHz 信道列表

```go
func SupportedChannels24GHz() []int
```

返回：信道 1-14 的列表

---

#### `SupportedChannels5GHz() []int`

获取标准的 5 GHz 信道列表

```go
func SupportedChannels5GHz() []int
```

---

#### `AllSupportedChannels() []int`

获取所有支持的信道（2.4GHz + 5GHz）

```go
func AllSupportedChannels() []int
```

---

#### `ChannelHop(iface string, config ChannelHopConfig, stopCh <-chan struct{}) error`

信道跳频扫描

```go
func ChannelHop(iface string, config ChannelHopConfig, stopCh <-chan struct{}) error
```

参数：
- `iface`: 网卡接口名
- `config`: 配置，包含信道列表和跳频延迟
- `stopCh`: 停止信号 channel

---

#### `GetSupportedChannels(iface string) ([]int, error)`

获取特定网卡支持的信道列表

```go
func GetSupportedChannels(iface string) ([]int, error)
```

---

#### `ChannelFrequency(channel int) int`

获取信道对应的频率（MHz）

```go
func ChannelFrequency(channel int) int
```

---

#### `FreqToChannel(freq int) int`

从频率（MHz）转换为信道号

```go
func FreqToChannel(freq int) int
```

---

#### `FreqFromChannel(ch int) int`

从信道转换为频率（MHz）

```go
func FreqFromChannel(ch int) int
```

---

#### `Is2GHz(freq int) bool`

检查是否 2.4 GHz 频率

```go
func Is2GHz(freq int) bool
```

---

#### `Is5GHz(freq int) bool`

检查是否 5 GHz 频率

```go
func Is5GHz(freq int) bool
```

---

### 帧解析

#### `ParseFrame80211(data []byte) (*Frame80211, error)`

解析原始 802.11 帧数据

```go
func ParseFrame80211(data []byte) (*Frame80211, error)
```

---

#### `ParseFrameWithRadiotap(packet []byte) (*Frame80211, error)`

解析带有 Radiotap 头的完整帧

```go
func ParseFrameWithRadiotap(packet []byte) (*Frame80211, error)
```

---

#### `GetFrameType(data []byte) FrameType`

获取原始数据包的帧类型

```go
func GetFrameType(data []byte) FrameType
```

---

#### `GetFrameSubtype(data []byte) FrameSubtype`

获取原始数据包的帧子类型

```go
func GetFrameSubtype(data []byte) FrameSubtype
```

---

#### `IsBeacon(data []byte) bool`

检查是否信标帧

```go
func IsBeacon(data []byte) bool
```

---

#### `IsProbeRequest(data []byte) bool`

检查是否探测请求

```go
func IsProbeRequest(data []byte) bool
```

---

#### `IsProbeResponse(data []byte) bool`

检查是否探测响应

```go
func IsProbeResponse(data []byte) bool
```

---

#### `IsDeauth(data []byte) bool`

检查是否解除认证帧

```go
func IsDeauth(data []byte) bool
```

---

#### `IsDisassoc(data []byte) bool`

检查是否解除关联帧

```go
func IsDisassoc(data []byte) bool
```

---

#### `IsAuth(data []byte) bool`

检查是否认证帧

```go
func IsAuth(data []byte) bool
```

---

#### `IsData(data []byte) bool`

检查是否数据帧

```go
func IsData(data []byte) bool
```

---

#### `IsProtected(data []byte) bool`

检查帧是否加密

```go
func IsProtected(data []byte) bool
```

---

#### `IsManagementFrame(f *Frame80211) bool`

检查是否管理帧

```go
func IsManagementFrame(f *Frame80211) bool
```

---

#### `IsControlFrame(f *Frame80211) bool`

检查是否控制帧

```go
func IsControlFrame(f *Frame80211) bool
```

---

#### `IsDataFrame(f *Frame80211) bool`

检查是否数据帧

```go
func IsDataFrame(f *Frame80211) bool
```

---

#### `IsQoSFrame(f *Frame80211) bool`

检查是否 QoS 数据帧

```go
func IsQoSFrame(f *Frame80211) bool
```

---

#### `ParseBeacon(f *Frame80211) *WiFiNetwork`

从信标帧或探测响应帧中解析网络信息

```go
func ParseBeacon(f *Frame80211) *WiFiNetwork
```

---

#### `ParseAuthFrame(f *Frame80211) (alg uint16, seq uint16, status uint16)`

解析认证帧

```go
func ParseAuthFrame(f *Frame80211) (alg uint16, seq uint16, status uint16)
```

---

#### `GetBSSID(f *Frame80211) string`

从帧中获取 BSSID

```go
func GetBSSID(f *Frame80211) string
```

---

#### `GetSourceMAC(f *Frame80211) string`

从帧中获取源 MAC 地址

```go
func GetSourceMAC(f *Frame80211) string
```

---

#### `GetDestMAC(f *Frame80211) string`

从帧中获取目的 MAC 地址

```go
func GetDestMAC(f *Frame80211) string
```

---

#### `GetTransmitterMAC(f *Frame80211) string`

获取发射机 MAC 地址

```go
func GetTransmitterMAC(f *Frame80211) string
```

---

#### `SignalStrength(f *Frame80211) int`

获取帧的信号强度

```go
func SignalStrength(f *Frame80211) int
```

---

### 握手捕获

#### `IsEAPOL(data []byte) bool`

检查是否为 EAPOL Key 帧（不检查版本）

```go
func IsEAPOL(data []byte) bool
```

---

#### `IsEAPOLFrame(f *Frame80211) bool`

检查帧是否 EAPOL 帧

```go
func IsEAPOLFrame(f *Frame80211) bool
```

---

#### `ParseEAPOL(data []byte) (*EAPOLFrame, error)`

解析 EAPOL 帧

```go
func ParseEAPOL(data []byte) (*EAPOLFrame, error)
```

---

#### `ExtractEAPOL(f *Frame80211) ([]byte, error)`

从数据帧中提取 EAPOL 数据

```go
func ExtractEAPOL(f *Frame80211) ([]byte, error)
```

---

#### `GetEAPOLMessageNumber(eapol *EAPOLFrame) int`

获取 EAPOL 消息编号（1-4）

```go
func GetEAPOLMessageNumber(eapol *EAPOLFrame) int
```

返回：
- 1: 消息 1（AP → STA）
- 2: 消息 2（STA → AP）
- 3: 消息 3（AP → STA）
- 4: 消息 4（STA → AP）
- 0: 未知

---

#### `ProcessHandshakeFrame(eapol *EAPOLFrame, frame *Frame80211, handshake *WPAHandshake) bool`

处理单个 EAPOL 帧，更新握手状态

```go
func ProcessHandshakeFrame(eapol *EAPOLFrame, frame *Frame80211, handshake *WPAHandshake) bool
```

返回：是否已更新握手

---

#### `DetectWPAHandshake(f *Frame80211, handshake *WPAHandshake) bool`

检测并处理一个帧中的 WPA 握手

```go
func DetectWPAHandshake(f *Frame80211, handshake *WPAHandshake) bool
```

---

#### `StartNativeCapture(config CaptureConfig, frameCallback func(*Frame80211, time.Time), handshakeCallback func(*WPAHandshake)) (*CaptureSession, error)`

开始原生抓包，支持回调处理

```go
func StartNativeCapture(
    config CaptureConfig,
    frameCallback func(*Frame80211, time.Time),
    handshakeCallback func(*WPAHandshake),
) (*CaptureSession, error)
```

参数：
- `config`: 抓包配置
- `frameCallback`: 帧回调（可选）
- `handshakeCallback`: 握手回调（可选）

返回：抓包会话对象

---

#### `ListenForHandshake(config CaptureConfig) (*WPAHandshake, error)`

监听并等待直到捕获到完整的 WPA 握手

```go
func ListenForHandshake(config CaptureConfig) (*WPAHandshake, error)
```

---

### CaptureSession 方法

#### `(*CaptureSession).Stop()`

停止抓包会话

```go
func (s *CaptureSession) Stop()
```

---

#### `(*CaptureSession).Wait() error`

等待抓包会话结束

```go
func (s *CaptureSession) Wait() error
```

---

#### `(*CaptureSession).Handshakes() map[string]*WPAHandshake`

获取所有捕获的握手（按 BSSID 索引）

```go
func (s *CaptureSession) Handshakes() map[string]*WPAHandshake
```

---

#### `(*CaptureSession).GetHandshake(bssid string) *WPAHandshake`

获取指定 BSSID 的握手

```go
func (s *CaptureSession) GetHandshake(bssid string) *WPAHandshake
```

---

#### `(*CaptureSession).HandshakeCount() int`

获取已捕获握手的数量

```go
func (s *CaptureSession) HandshakeCount() int
```

---

#### `(*CaptureSession).PacketsIn() int64`

获取已捕获的数据包总数

```go
func (s *CaptureSession) PacketsIn() int64
```

---

#### `(*CaptureSession).SavePcap(filename string) error`

设置/修改保存到的 PCAP 文件

```go
func (s *CaptureSession) SavePcap(filename string) error
```

---

### PCAP 文件操作

#### `OpenPcapFile(filename string) ([]byte, error)`

打开 PCAP 文件并读取全部内容

```go
func OpenPcapFile(filename string) ([]byte, error)
```

---

#### `ParsePcapHeader(data []byte) (*PcapHeader, int, error)`

解析 PCAP 文件头

```go
func ParsePcapHeader(data []byte) (*PcapHeader, int, error)
```

---

#### `ReadPcapRecord(data []byte, offset int) (*PcapRecord, []byte, int, error)`

从 PCAP 数据中读取一条记录

```go
func ReadPcapRecord(data []byte, offset int) (*PcapRecord, []byte, int, error)
```

---

#### `ParsePcapFile(data []byte, linktype int, callback func(*Frame80211, time.Time) error) error`

解析整个 PCAP 文件，回调处理每个帧

```go
func ParsePcapFile(data []byte, linktype int, callback func(*Frame80211, time.Time) error) error
```

---

#### `WritePcapHeader(f *os.File, network uint32) error`

写入 PCAP 文件头

```go
func WritePcapHeader(f *os.File, network uint32) error
```

---

#### `WritePcapRecord(f *os.File, packet []byte, ts time.Time) error`

写入一个 PCAP 记录

```go
func WritePcapRecord(f *os.File, packet []byte, ts time.Time) error
```

---

#### `WritePcapFrame(f *os.File, frame *Frame80211, ts time.Time, linktype uint32) error`

将一个帧写入 PCAP 文件

```go
func WritePcapFrame(f *os.File, frame *Frame80211, ts time.Time, linktype uint32) error
```

---

### 穷举破解相关

> 穷举破解功能深度参考 [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) 架构设计，支持 CPU 多协程并发、CUDA GPU 加速和 OpenCL GPU 加速。GPU 后端通过构建标签 (`-tags cuda` 或 `-tags opencl`) 切换，无标签时默认使用 CPU 存根。

#### 破解配置与目标

##### `CrackDevice`

破解设备类型枚举

```go
type CrackDevice int

const (
    CrackDeviceAuto   CrackDevice = iota // 自动选择
    CrackDeviceCPU                       // CPU 模式
    CrackDeviceGPU                       // GPU 模式
    CrackDeviceOpenCL                    // OpenCL 模式
)
```

##### `CrackTarget`

破解目标（从 CAP 文件中提取的握手信息）

```go
type CrackTarget struct {
    BSSID    string  // AP 的 BSSID
    ESSID    string  // 网络 ESSID
    STAMAC   string  // 客户端 MAC
    ANonce   []byte  // AP Nonce（从 Msg1）
    SNonce   []byte  // STA Nonce（从 Msg2）
    EAPOL    []byte  // EAPOL 帧数据（MIC 字段已清零）
    EAPOLSize int    // EAPOL 帧大小
    MIC      []byte  // 捕获的 MIC 值
    KeyVer   uint8   // 密钥描述类型（1=WPA, 2=WPA2）
    PMKID    []byte  // PMKID（如果有）
}
```

##### `CrackConfig`

破解配置

```go
type CrackConfig struct {
    Wordlist      string        // 密码字典文件路径（必需）
    Targets       []CrackTarget // 破解目标列表（必需）
    Workers       int           // 工作协程数，默认 CPU 核数
    Device        CrackDevice   // 设备类型：CPU 或 GPU
    ESSID         string        // 全局 ESSID（当 Target 中未设置时使用）
    Timeout       time.Duration // 超时时间
    Quiet         bool          // 静音模式
    SessionFile   string        // 会话保存文件
    BSSIDFilter   string        // BSSID 过滤
    StatusInterval time.Duration // 状态报告间隔，默认 3 秒
}
```

---

#### 破解会话与结果

##### `CrackResult`

破解结果

```go
type CrackResult struct {
    BSSID      string        // AP 的 BSSID
    ESSID      string        // 网络 ESSID
    STAMAC     string        // 客户端 MAC
    Passphrase string        // 密码！！🎉
    PMK        [32]byte      // PMK（Pairwise Master Key）
    PTK        []byte        // PTK（Pairwise Transient Key）
    MIC        []byte        // MIC 值
    Method     string        // 破解方式："handshake" 或 "pmkid"
    Elapsed    time.Duration // 破解耗时
    Tried      uint64        // 已尝试密码数
    Speed      float64       // 速度（keys/s）
    FoundAt    time.Time     // 发现时间
}
```

##### `CrackStats`

破解统计信息

```go
type CrackStats struct {
    Elapsed   time.Duration // 已用时间
    Tried     uint64        // 已尝试密码数
    Speed     float64       // 当前速度（keys/s）
    Found     int           // 已找到数量
    Remaining int64         // 剩余密码数
}
```

##### `CrackSession`

破解会话

```go
type CrackSession struct {
    // 私有字段
}
```

#### CrackSession 方法

##### `(*CrackSession).Stop()`

停止破解

```go
func (s *CrackSession) Stop()
```

##### `(*CrackSession).Wait() error`

等待破解结束

```go
func (s *CrackSession) Wait() error
```

##### `(*CrackSession).Results() []CrackResult`

获取破解结果

```go
func (s *CrackSession) Results() []CrackResult
```

##### `(*CrackSession).Stats() CrackStats`

获取当前统计

```go
func (s *CrackSession) Stats() CrackStats
```

##### `(*CrackSession).Found() bool`

是否已找到密码

```go
func (s *CrackSession) Found() bool
```

##### `(*CrackSession).Tried() uint64`

获取已尝试密码数

```go
func (s *CrackSession) Tried() uint64
```

##### `(*CrackSession).SaveSession(filename string) error`

保存破解会话到文件（支持断点恢复）

```go
func (s *CrackSession) SaveSession(filename string) error
```

---

#### 破解函数

##### `StartCrack(cfg CrackConfig) (*CrackSession, error)`

启动 WPA 穷举破解。内部使用 goroutine 池并发处理密码，每个 worker 预计算 PKE 数据避免重复计算。

```go
func StartCrack(cfg CrackConfig) (*CrackSession, error)
```

示例：
```go
targets, _ := wifie.LoadTargetsFromCap("wifi.cap", "MyWiFi")
cfg := wifie.CrackConfig{
    Wordlist: "passwords.txt",
    Targets:  targets,
    Workers:  8,
}
session, _ := wifie.StartCrack(cfg)
session.Wait()

for _, r := range session.Results() {
    fmt.Printf("找到密码: %s (BSSID=%s)\n", r.Passphrase, r.BSSID)
}
```

##### `CrackHandshake(cfg CrackConfig, statsCallback, resultCallback) ([]CrackResult, error)`

启动破解并带实时回调

```go
func CrackHandshake(
    cfg CrackConfig,
    statsCallback func(CrackStats),
    resultCallback func(CrackResult),
) ([]CrackResult, error)
```

##### `LoadTargetsFromCap(capFile, essid string) ([]CrackTarget, error)`

从 CAP 文件中自动提取 WPA 握手目标。基于 aircrack-ng 的 EAPOL 解析逻辑，自动识别 Msg1-Msg4 并提取 ANonce、SNonce、EAPOL 数据和 MIC。

```go
func LoadTargetsFromCap(capFile string, essid string) ([]CrackTarget, error)
```

示例：
```go
targets, err := wifie.LoadTargetsFromCap("capture.cap", "TargetWiFi")
if err != nil {
    log.Fatal("加载握手失败:", err)
}
for _, t := range targets {
    fmt.Printf("BSSID=%s STA=%s\n", t.BSSID, t.STAMAC)
}
```

---

#### GPU 设备

##### `CrackDeviceGPUInfo`

GPU 设备信息

```go
type CrackDeviceGPUInfo struct {
    Index        int    // 设备索引
    Name         string // 设备名称
    Vendor       string // 厂商
    MemoryMB     uint64 // 显存（MB）
    ComputeUnits int    // 计算单元数
    MaxWorkGroup int    // 最大工作组大小
}
```

##### `ListGPUCrackDevices() []CrackDeviceGPUInfo`

列出可用的 GPU 破解设备。需要 `-tags cuda` 或 `-tags opencl` 编译。

```go
func ListGPUCrackDevices() []CrackDeviceGPUInfo
```

##### `StartGPUCrack(cfg CrackConfig) (*CrackSession, error)`

使用 GPU 启动 WPA 破解。需要 `-tags cuda` 或 `-tags opencl` 编译。

```go
func StartGPUCrack(cfg CrackConfig) (*CrackSession, error)
```

##### `GpuAvailable() bool`

检查 GPU 是否可用

```go
func GpuAvailable() bool
```

##### `CalcPMKBatchGPU(passwords, essid) ([][32]byte, error)`

使用 GPU 批量计算 PMK。需要 `-tags cuda` 或 `-tags opencl` 编译。

```go
func CalcPMKBatchGPU(passwords [][]byte, essid []byte) ([][32]byte, error)
```

---

#### GPU 后端选择与编译

Wifie 支持三种计算后端，通过 Go 构建标签切换：

| 构建标签 | 后端 | 说明 |
|----------|------|------|
| 默认（无标签） | CPU 存根 | `GpuAvailable()` 返回 `false`，GPU 函数返回错误 |
| `cuda` | NVIDIA CUDA | 需要 NVIDIA GPU + CUDA Toolkit |
| `opencl` | OpenCL | 需要 OpenCL 驱动（AMD/NVIDIA/Intel GPU） |

**CUDA 后端架构**：

CUDA 后端基于 [gocnn/gocu](https://github.com/gocnn/gocu) 库，通过 CUDA Driver API 直接管理 GPU。核心组件：

| 组件 | 文件 | 说明 |
|------|------|------|
| CUDA 内核 | `crack_cuda.cu` | PBKDF2-SHA1 (4096 轮) + HMAC-SHA1，GPU 端并行计算 |
| PTX 汇编 | `crack_cuda.ptx` | 预编译的内核代码，通过 Go `embed` 嵌入二进制 |
| Go 绑定 | `crack_cuda.go` | 上下文管理、内存分配、内核启动、结果回读 |

**混合执行模型**：

```
字典文件 → readWordlist() → chan string
                                ↓
    ┌───────────────────────────┴───────────────────────────┐
    │                                                       │
    ▼ CPU Workers (N 个)                                    ▼ CUDA Worker (1 个)
    worker() goroutine × N                                  cudaWorker()
    从 chan 读取密码                                        批量收集密码 (1024/批次)
    分发给 CUDA Worker 批处理                               启动 CUDA 内核并行计算 PMK
                       ↓                                    回读 PMK，分发给 Workers 验证 MIC
              ┌────────┴────────┐
              ▼                 ▼
         MIC 匹配？          继续下一批
         → 找到密码！
```

**CUDA 编译命令**：

```bash
# 需要 NVIDIA GPU + CUDA Toolkit 13.x
# 设置 CUDA 头文件和库路径后编译
CGO_CFLAGS="-I/opt/cuda/include" CGO_LDFLAGS="-L/opt/cuda/lib64 -lcuda" \
    go build -tags cuda ./wifie/...

# 编译破解示例（CUDA 加速）
CGO_CFLAGS="-I/opt/cuda/include" CGO_LDFLAGS="-L/opt/cuda/lib64 -lcuda" \
    go build -tags cuda -o crack ./examples/wifie/crack/
```

**OpenCL 编译命令**：

```bash
# 需要 OpenCL 驱动和开发头文件
go build -tags opencl ./wifie/...

# 编译破解示例（OpenCL 加速）
go build -tags opencl -o crack ./examples/wifie/crack/
```

**GPU 设备选择优先级**：

调用 `StartCrack` 时设置 `Device: CrackDeviceGPU` 即可自动选择 GPU 后端：
- 编译时带 `cuda` 标签 → 优先使用 NVIDIA CUDA
- 编译时带 `opencl` 标签 → 使用 OpenCL
- `GpuAvailable()` 可用于运行时检测 GPU 是否就绪

---

#### 密码学底层函数

##### `CalcPMK(passphrase, essid []byte) [32]byte`

计算 PMK（PBKDF2-SHA1，4096 轮迭代）

```go
func CalcPMK(passphrase []byte, essid []byte) [32]byte
```

##### `CalcPTK(pmk, bssid, stamac string, anonce, snonce []byte, keyVer uint8) []byte`

计算 PTK（Pairwise Transient Key）

```go
func CalcPTK(pmk []byte, bssid, stamac string, anonce, snonce []byte, keyVer uint8) []byte
```

##### `CalcPTKWithData(pmk, pkeData []byte, keyVer uint8) []byte`

使用预计算的 PKE 数据计算 PTK（性能优化版本，避免每次重建 PTK 数据缓冲区）

```go
func CalcPTKWithData(pmk []byte, pkeData []byte, keyVer uint8) []byte
```

##### `PreComputePTKData(bssid, stamac string, anonce, snonce []byte) []byte`

预计算 PTK 数据缓冲区（对应 aircrack-ng 的 `calc_pke()`）

```go
func PreComputePTKData(bssid string, stamac string, anonce []byte, snonce []byte) []byte
```

##### `CalcEAPOLMIC(eapol, ptk []byte, keyVer uint8) ([]byte, error)`

计算 EAPOL MIC

```go
func CalcEAPOLMIC(eapol []byte, ptk []byte, keyVer uint8) ([]byte, error)
```

##### `TryWPAKey(pass, essid, bssid, stamac, anonce, snonce, eapolData []byte, eapolSize int, mic []byte, keyVer uint8) bool`

尝试一个密码是否匹配握手

```go
func TryWPAKey(
    pass, essid []byte,
    bssid, stamac string,
    anonce, snonce []byte,
    eapolData []byte, eapolSize int,
    mic []byte, keyVer uint8,
) bool
```

##### `TryPMKID(pmk, pmkid, bssid, stamac []byte) bool`

尝试 PMKID 匹配

```go
func TryPMKID(pmk []byte, pmkid []byte, bssid string, stamac string) bool
```

##### `CalcPMKID(pmk, bssid, stamac []byte) []byte`

计算 PMKID

```go
func CalcPMKID(pmk []byte, bssid string, stamac string) []byte
```

##### `CheckHandshakeMIC(handshake *WPAHandshake, pmk []byte) bool`

使用 PMK 验证 WPA 握手的 MIC

```go
func CheckHandshakeMIC(handshake *WPAHandshake, pmk []byte) bool
```

---

## 示例程序

### WPA 握手捕获示例

以下是完整的示例程序，支持：
- 指定接口和信道
- 指定 BSSID 或捕获所有 AP
- 自动停止在捕获到第一个握手
- 保存为 PCAP 文件

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xiguayiqiu/gyscan_code/wifie"
)

func main() {
	iface := flag.String("i", "", "Interface to use (required)")
	bssid := flag.String("b", "", "Target BSSID (supports multiple comma-separated list, or \"all\" for any handshake from all AP")
	channel := flag.Int("c", 0, "Channel number (required)")
	outFile := flag.String("w", "wifi.cap", "Output pcap file")
	timeout := flag.Int("t", 300, "Timeout in seconds (0 for no timeout)")
	stopOnFirst := flag.Bool("1", false, "Stop after capturing after first complete handshake")
	quiet := flag.Bool("q", false, "Quiet mode")
	flag.Parse()

	if *iface == "" || *channel == 0 {
		fmt.Println("Usage: ./wifie -i <interface> [-b <bssid> -c <channel> [-w output.cap] [-t timeout_secs] [-1] [-q]")
		fmt.Println()
		fmt.Println("  -i <iface>    Interface name of monitor mode wifi card (required)")
		fmt.Println("  -b <bssid>    BSSID or \"all\" to capture all handshakes (required)")
		fmt.Println("  -c <channel>  Channel number to lock (required)")
		fmt.Println("  -w <file>     Output pcap file (default: wifi.cap)")
		fmt.Println("  -t <secs>     Timeout in seconds, 0 to disable (default: 300)")
		fmt.Println("  -1             Stop when first complete handshake captured")
		fmt.Println("  -q             Quiet mode")
		os.Exit(1)
	}

	var targetBSSIDs map[string]bool
	if *bssid == "all" {
		targetBSSIDs = nil
	} else {
		targetBSSIDs = make(map[string]bool)
		for _, mac := range strings.Split(*bssid, ",") {
			targetBSSIDs[strings.ToLower(strings.TrimSpace(mac))] = true
		}
	}

	if !*quiet {
		fmt.Println("╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║                  WPA 握手被动捕获器                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Printf("┌─────────────────────────────────────────────────────────────\n")
		fmt.Printf("│ 网卡: %s\n", *iface)
		if targetBSSIDs == nil {
		fmt.Printf("│ 目标: 所有 AP\n")
		} else {
		fmt.Printf("│ 目标: ")
		i := 0
		for bssid := range targetBSSIDs {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", bssid)
			i++
		}
		fmt.Println()
		}
		fmt.Printf("│ 信道: %d\n", *channel)
		if *timeout == 0 {
		fmt.Printf("│ 超时: 永不\n")
		} else {
		fmt.Printf("│ 超时: %d 秒\n", *timeout)
		}
		fmt.Printf("│ 输出: %s\n", *outFile)
		fmt.Printf("└─────────────────────────────────────────────────────────────\n")
		fmt.Println()
	}

	// 锁定信道
	if !*quiet {
		fmt.Printf("  [*] 锁定信道 %d...\n", *channel)
	}
	if err := wifie.SetChannel(*iface, *channel); err != nil {
		fmt.Printf("  [x] 锁定信道失败: %v\n", err)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Printf("  [✓] 信道已锁定: %d\n", *channel)
		fmt.Println()
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Println("  [●] 开始被动监听 WPA 握手...")
		fmt.Println("  [●] 等待客户端连接/重连 (不做主动攻击)")
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Println()
	}

	// 准备捕获配置
	cfg := wifie.CaptureConfig{
		Iface:   *iface,
		Channel: *channel,
		Timeout: time.Duration(*timeout) * time.Second,
		PcapFile: *outFile,
	}
	if targetBSSIDs != nil && len(targetBSSIDs) > 0 {
		for bssid := range targetBSSIDs {
			cfg.BSSID = bssid
			break
		}
	}

	// 用于捕获过程中的统计
	pktCount := 0
	hsCount := 0
	handshakes := make(map[string]*wifie.WPAHandshake)
	startTime := time.Now()
	var session *wifie.CaptureSession

	// 回调: 握手捕获成功时
	hsCallback := func(hs *wifie.WPAHandshake) {
		if !hs.Complete {
			return
		}

		if targetBSSIDs != nil {
			handshakes[hs.BSSID] = hs

			if _, ok := targetBSSIDs[hs.BSSID]; !ok && len(targetBSSIDs) > 0 {
				return
			}
		} else {
			handshakes[hs.BSSID] = hs
		}

		hsCount++

		fmt.Printf("\n")
		fmt.Printf("  ════════════════════════════════════════════════════════\n")
		fmt.Printf("  ✨ WPA 握手捕获成功 #%d ✨\n", hsCount)
		fmt.Printf("  ════════════════════════════════════════════════════════\n")
		fmt.Printf("  ├─ AP BSSID:  %s\n", hs.BSSID)
		fmt.Printf("  ├─ 客户端:   %s\n", hs.STAMAC)
		fmt.Printf("  ├─ ANonce:    %x\n", hs.ANonce)
		fmt.Printf("  ├─ SNonce:    %x\n", hs.SNonce)
		fmt.Printf("  ├─ MIC:       %x\n", hs.MIC)
		if len(hs.PMKID) > 0 {
			fmt.Printf("  ├─ PMKID:     %x\n", hs.PMKID)
		}
		fmt.Printf("  ════════════════════════════════════════════════════════\n")
		fmt.Println()

		if *stopOnFirst {
			fmt.Printf("  [*] 停止捕获（已启用 -1 选项）\n")
			session.Stop()
		}
	}

	// 捕获
	var err error
	session, err = wifie.StartNativeCapture(cfg,
		func(frame *wifie.Frame80211, ts time.Time) {
			pktCount++
			if !*quiet && pktCount%500 == 0 {
				fmt.Printf("\r  [~] 监听中... (已过 %ds, 收包: %d, 握手: %d)",
					int(time.Since(startTime).Seconds()),
					pktCount,
					hsCount)
			}
		},
		hsCallback,
	)
	if err != nil {
		fmt.Printf("  [x] 启动监听失败: %v\n", err)
		os.Exit(1)
	}

	// 处理中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		session.Stop()
	}()

	// 等待结束
	err = session.Wait()
	fmt.Println()

	if err != nil {
		fmt.Printf("  [x] 监听异常结束: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("  [✓] 监听结束! 最终结果:\n")
	fmt.Printf("    总收包:   %d\n", session.PacketsIn())
	fmt.Printf("    总时长:   %s\n", time.Since(startTime).Round(time.Second))
	if hsCount > 0 {
		fmt.Printf("    握手捕获: %d\n", hsCount)
	}

	if hsCount > 0 {
		fmt.Println()
		fmt.Println("  捕获到的完整握手:")
		if len(handshakes) == 0 {
			// Fallback to session handshakes
			handshakes = session.Handshakes()
		}
		i := 0
		for bssid, hs := range handshakes {
			if hs.Complete {
				i++
				fmt.Printf("    [%d] %s (客户端: %s)\n", i, bssid, hs.STAMAC)
			}
		}
	}
	fmt.Println()
	fmt.Printf("  Pcap 文件已保存为: %s\n", *outFile)
	fmt.Println()
}
```

#### 使用方法

1. 编译：
   ```bash
   cd /home/yiqiu/projects/gyscan_code/examples/wifie
   go build -o wifie main.go
   ```

2. 捕获单个 AP 的握手：
   ```bash
   sudo ./wifie -i wlp0s20f0u1mon -b 00:90:5c:d4:2f:19 -c 4 -w mycap.cap -t 120
   ```

3. 捕获所有 AP 的握手并在第一个完成后停止：
   ```bash
   sudo ./wifie -i wlp0s20f0u1mon -b all -c 4 -1
   ```

4. 帮助信息：
   ```bash
   ./wifie -h
   ```

---

### WPA 握手穷举破解示例

以下是 `/home/yiqiu/projects/gyscan_code/examples/wifie/crack/main.go` 的完整代码，支持：
- 从 CAP 文件自动加载握手
- CPU 多协程并发穷举（默认使用全部 CPU 核）
- CUDA GPU 加速（`-D gpu`，需要 `-tags cuda` 编译）
- OpenCL GPU 加速（`-D gpu`，需要 `-tags opencl` 编译）
- 实时速度显示
- 信号中断优雅退出

```go
package main

import (
  "flag"
  "fmt"
  "os"
  "os/signal"
  "strings"
  "syscall"
  "time"

  "github.com/xiguayiqiu/gyscan_code/wifie"
)

func main() {
  capFile := flag.String("r", "", "CAP file with WPA handshake (required)")
  wordlist := flag.String("w", "", "Wordlist file (required)")
  essid := flag.String("e", "", "ESSID / network name (required)")
  bssid := flag.String("b", "", "Optional: filter by BSSID")
  workers := flag.Int("t", 0, "Number of workers (default: CPU count)")
  device := flag.String("D", "cpu", "Device: cpu or gpu")
  quiet := flag.Bool("q", false, "Quiet mode")
  flag.Parse()

  if *capFile == "" || *wordlist == "" || *essid == "" {
    fmt.Println("Usage: ./crack -r <capfile> -w <wordlist> -e <essid> [-b <bssid>] [-t workers] [-D cpu|gpu] [-q]")
    fmt.Println()
    fmt.Println("  -r <file>     CAP file with WPA handshake (required)")
    fmt.Println("  -w <file>     Wordlist file (required)")
    fmt.Println("  -e <essid>    Network ESSID / name (required)")
    fmt.Println("  -b <bssid>    Optional filter by BSSID")
    fmt.Println("  -t <num>      Number of workers (default: CPU count)")
    fmt.Println("  -D <device>   Device: cpu or gpu (default: cpu)")
    fmt.Println("  -q            Quiet mode")
    os.Exit(1)
  }

  // ... 完整代码见 examples/wifie/crack/main.go
}
```

**输出示例**：
```
╔════════════════════════════════════════════════════════════╗
║                  WPA 握手穷举破解器                           ║
╚════════════════════════════════════════════════════════════╝
┌─────────────────────────────────────────────────────────────
│ CAP 文件:  wifi.cap
│ ESSID:     MIFI-8752
│ 字典文件:  passwd.txt
│ 设备:      CPU (8 workers)
└─────────────────────────────────────────────────────────────

  [*] 从 CAP 文件加载握手...
  [✓] 找到 1 个握手目标:
      [1] BSSID=00:90:5c:d4:2f:19 STA=8a:59:66:9a:b1:eb

─────────────────────────────────────────────────────────────
  [●] 开始穷举...
─────────────────────────────────────────────────────────────

─────────────────────────────────────────────────────────────
  ★ 破解成功! ★
  ┌─ BSSID:     00:90:5c:d4:2f:19
  ├─ 密码:      luo15023383848+
  ├─ PMK:       6444727c9b321bbc...
  └─ 耗时:      6ms
```

#### 使用方法

1. 编译：
   ```bash
   cd /home/yiqiu/projects/gyscan_code/examples/wifie
   go build -o crack/crack ./crack/
   ```

2. CPU 穷举：
   ```bash
   ./crack/crack -r wifi.cap -w passwd.txt -e "MIFI-8752" -t 8
   ```

3. CUDA GPU 加速（需要 NVIDIA GPU + CUDA Toolkit）：
   ```bash
   CGO_CFLAGS="-I/opt/cuda/include" CGO_LDFLAGS="-L/opt/cuda/lib64 -lcuda" \
       go build -tags cuda -o crack/crack ./crack/
   ./crack/crack -r wifi.cap -w passwd.txt -e "MIFI-8752" -D gpu
   ```

4. OpenCL GPU 加速（需要 OpenCL 驱动）：
   ```bash
   go build -tags opencl -o crack/crack ./crack/
   ./crack/crack -r wifi.cap -w passwd.txt -e "MIFI-8752" -D gpu
   ```

5. 帮助信息：
   ```bash
   ./crack/crack -h
   ```

---

### 完整工作流：捕获 → 破解

完整的 WPA 破解工作流示例，展示从捕获握手到字典穷举的完整过程：

```go
package main

import (
  "fmt"
  "log"
  "time"

  "github.com/xiguayiqiu/gyscan_code/wifie"
)

func main() {
  // ========== 第1步：捕获 WPA 握手 ==========
  captureCfg := wifie.CaptureConfig{
    Iface:    "wlp0s20f0u1mon",
    BSSID:    "00:90:5c:d4:2f:19",
    Channel:  4,
    PcapFile: "capture.cap",
    Timeout:  120 * time.Second,
  }

  session, _ := wifie.StartNativeCapture(captureCfg,
    func(frame *wifie.Frame80211, ts time.Time) {},
    func(hs *wifie.WPAHandshake) {
      if hs.Complete {
        fmt.Printf("  ✓ 捕获到握手: BSSID=%s STA=%s\n", hs.BSSID, hs.STAMAC)
        session.Stop()
      }
    },
  )
  session.Wait()

  // ========== 第2步：从 CAP 加载握手目标 ==========
  targets, _ := wifie.LoadTargetsFromCap("capture.cap", "MyWiFi")
  fmt.Printf("  ✓ 加载 %d 个目标\n", len(targets))

  // ========== 第3步：穷举破解 ==========
  crackCfg := wifie.CrackConfig{
    Wordlist: "passwords.txt",
    Targets:  targets,
    Workers:  8,
  }

  crackSession, _ := wifie.StartCrack(crackCfg)
  crackSession.Wait()

  // ========== 第4步：输出结果 ==========
  for _, r := range crackSession.Results() {
    fmt.Printf("  ★ 破解成功! 密码: %s\n", r.Passphrase)
  }
}
```

### 架构设计

穷举破解的核心架构深度参考 aircrack-ng 设计：

**CPU 模式**：

| aircrack-ng | wifie 实现 |
|-------------|-----------|
| `do_wpa_crack()` 读取密码管道 | `readWordlist()` + `chan string` |
| `crack_wpa_thread()` 多线程 | `worker()` goroutine × N |
| `crypto_engine_calc_pke()` 预计算 | `buildTargetData()` + `PreComputePTKData()` |
| `crypto_engine_wpa_crack()` 批处理 | `processBatchFast()` 批量 MIC 验证 |
| SIMD 4/8 路并行 | goroutine 并发 + 零分配 PBKDF2 |
| `memset(eapol+81, 0, 16)` MIC 清零 | `captureEAPOLMIC()` 自动清零 |

**CUDA GPU 模式**：

| 步骤 | 实现 |
|------|------|
| 字典流式读取 | `readWordlist()` → `chan string` |
| 密码批量收集 | `cudaWorker()` goroutine，1024 条/批次 |
| GPU 并行 PMK 计算 | `crack_cuda.cu` 内核：每线程一个密码，PBKDF2-SHA1 × 4096 轮 |
| PMK 回读与 MIC 验证 | CPU Workers 批量验证 MIC，找到匹配即停止 |
| 错误恢复 | GPU 分配失败自动回退到 CPU 批处理 |

**文件组织**：

```
wifie/
├── crack.go              # CPU 破解核心（始终编译）
├── crack_gpu.go          # GPU 公开 API（始终编译）
├── crack_cuda.go         # CUDA Go 绑定（build: cuda）
├── crack_cuda.cu         # CUDA 内核源码
├── crack_cuda.ptx        # 预编译 CUDA PTX（go:embed）
├── crack_opencl.go       # OpenCL 实现（build: opencl）
├── crack_gpu_native.go   # CPU 存根（build: !opencl,!cuda）
└── crypto.go             # 密码学底层（CalcPMK、CalcPTK、CalcEAPOLMIC）
```

### 性能

| 模式 | 速度 | 说明 |
|------|------|------|
| CPU (Go 原生) | ~5,800 keys/s (8核) | 纯 Go，无 SIMD |
| CUDA GPU | 预计 100,000+ keys/s | NVIDIA GPU 并行计算，1024 线程/批次 |
| OpenCL GPU | 预计 50,000+ keys/s | 需要 OpenCL 驱动 |

---

## License

Apache License 2.0
