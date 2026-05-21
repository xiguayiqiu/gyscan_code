# HCX - Cap 转 HC22000 开发库

`hcx` 是一个用于将无线网络抓包文件（cap/pcap/pcapng）转换为 Hashcat 22000 模式（HC22000）格式的 Go 语言库。

输出结果与 [hcxtools](https://github.com/ZerBea/hcxtools) 中 `hcxpcapngtool` 的转换结果完全一致。

## HC22000 格式说明

HC22000 是 Hashcat 定义的 WPA/WPA2/WPA3 破解哈希格式，统一了 WPA-PMKID 和 WPA-EAPOL（4次握手）两种哈希类型。

### EAPOL 格式（hash type 02）

```
WPA*02*<MIC:32hex>*<MAC_AP:12hex>*<MAC_CLIENT:12hex>*<ESSID:hex>*<ANONCE:64hex>*<EAPOL_DATA:hex>*<MESSAGEPAIR:2hex>
```

| 字段 | 长度 | 说明 |
|------|------|------|
| `WPA*02` | - | 哈希类型标识，02 表示 EAPOL 4次握手 |
| MIC | 32 hex (16 bytes) | EAPOL 消息完整性校验码，已从 EAPOL 中提取 |
| MAC_AP | 12 hex (6 bytes) | AP 端 MAC 地址 |
| MAC_CLIENT | 12 hex (6 bytes) | 客户端 MAC 地址 |
| ESSID | 可变 hex | 网络名称（如 `4d4946492d38373532` = `MIFI-8752`） |
| ANonce | 64 hex (32 bytes) | AP 生成的随机挑战值 |
| EAPOL_DATA | 可变 hex | EAPOL 消息完整帧（MIC 位置已置零） |
| MESSAGEPAIR | 2 hex (1 byte) | 消息对类型和状态标志 |

MESSAGEPAIR 字段含义：

| 值 | 说明 |
|----|------|
| `00` | M12E2 — 使用 M1 ANonce + M2 EAPOL，无 NC |
| `80` | M12E2 + ST_NC — 同上，确认无非对称修正 |
| `01` | M14E4 |
| `02` | M32E2 |
| `03` | M32E3 |
| `04` | M34E3 |
| `05` | M34E4 |

> M12E2（ANonce 来自 M1，EAPOL 来自 M2）是最高优先级握手对，hcxpcapngtool 在有 M1+M2 时优先使用。

### PMKID 格式（hash type 01）

```
WPA*01*<PMKID:32hex>*<MAC_AP:12hex>*<MAC_CLIENT:12hex>*<ESSID:hex>***<STATUS:2hex>
```

### FT-PSK 格式（hash type 03/04）

```
WPA*03*<PMKID:32hex>*<MAC_AP:12hex>*<MAC_CLIENT:12hex>*<ESSID:hex>***<STATUS:2hex>*<MDID:4hex>*<R0KHID:hex>*<R1KHID:hex>
```

## 安装

```bash
go get github.com/xiguayiqiu/gyscan_code/hcx
```

## 使用示例

### 基本用法

```go
package main

import (
    "fmt"
    "github.com/xiguayiqiu/gyscan_code/hcx"
)

func main() {
    result, err := hcx.ConvertCapToHC22000("capture.cap")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("Packets: %d, Beacons: %d\n",
        result.Stats.RawPacketCount, result.Stats.BeaconCount)
    fmt.Printf("EAPOL: %d (M1=%d M2=%d M3=%d M4=%d)\n",
        result.Stats.EAPOLMsgCount,
        result.Stats.EAPOLM1Count, result.Stats.EAPOLM2Count,
        result.Stats.EAPOLM3Count, result.Stats.EAPOLM4Count)
    fmt.Printf("Handshakes: %d, PMKIDs: %d\n",
        result.Stats.EAPOLMPCount, result.Stats.PMKIDCount)

    for _, line := range hcx.FormatAllHashLines(result, false) {
        fmt.Print(line)
    }
}
```

### 直接输出到文件

```go
err := hcx.ConvertCapToHC22000File("capture.cap", "output.hc22000")
```

### 命令行工具

```bash
# 输出到 stdout（纯哈希，无干扰）
go run examples/hcx/main.go capture.cap

# 重定向到文件
go run examples/hcx/main.go capture.cap > output.hc22000

# 指定输出文件
go run examples/hcx/main.go capture.cap output.hc22000
```

输出的 HC22000 文件可直接用于 hashcat：

```bash
hashcat -m 22000 output.hc22000 wordlist.txt
```

## API 参考

### 核心函数

| 函数 | 说明 |
|------|------|
| `ConvertCapToHC22000(filename string) (*ConversionResult, error)` | 读取 cap/pcap/pcapng 文件，解析所有握手和 PMKID |
| `ConvertCapToHC22000File(input, output string) error` | 一站式转换并写入文件 |
| `FormatAllHashLines(result *ConversionResult, addTimestamp bool) []string` | 格式化所有结果为 HC22000 行（自动选择最佳握手对） |
| `FormatAllHashLinesString(result *ConversionResult, addTimestamp bool) string` | 返回所有 HC22000 行的拼接字符串 |
| `FormatEAPOLHash(entry HandshakeEntry, essid []byte, mic [16]byte, eapolData []byte, addTimestamp bool) string` | 格式化单个 EAPOL 哈希行 |
| `FormatPMKIDHash(entry PMKIDEntry, essid []byte, addTimestamp bool) string` | 格式化单个 PMKID 哈希行 |
| `FormatEAPOLFTPSKHash(entry HandshakeEntry, essid []byte, mic [16]byte, eapolData []byte, addTimestamp bool) string` | 格式化 FT-PSK EAPOL 哈希行 |
| `FormatPMKIDFTPSKHash(entry PMKIDEntry, essid []byte, addTimestamp bool) string` | 格式化 FT-PSK PMKID 哈希行 |
| `MACToBytes(mac string) ([6]byte, error)` | MAC 地址字符串（`aa:bb:cc:dd:ee:ff`）转字节数组 |

### 核心类型

| 类型 | 说明 |
|------|------|
| `ConversionResult` | 转换结果，包含 AP 列表、握手列表、PMKID 列表和统计信息 |
| `HandshakeEntry` | EAPOL 4次握手条目，含 M1/M3 ANonce、M2/M3 EAPOL 数据 |
| `PMKIDEntry` | PMKID 条目，含 16 字节 PMKID |
| `APEntry` | AP 信息条目，含 ESSID、加密套件、AKM 信息 |
| `MessageEntry` | 原始 EAPOL 消息条目 |
| `ConversionStats` | 转换统计信息 |

### HandshakeEntry 关键字段

| 字段 | 说明 |
|------|------|
| `AP` / `Client` | AP 和客户端 MAC（6 字节数组） |
| `ANonce` | M1 的 ANonce（32 字节），用于 EAPOL 哈希 |
| `EAPAuthLen` / `EAPOL` | M3 的 EAPOL 数据（用于 M32E2/M32E3/M34E3/M34E4 握手对） |
| `EAPAuthLenM2` / `EAPOLM2` | M2 的 EAPOL 数据（用于 M12E2/M14E4 握手对） |
| `Status` | 消息对类型 `|` 标志位（低 3 位 = 握手对类型，`0x80` = ST_NC） |

## 转换流程

```
cap/pcap/pcapng 文件
    │
    ▼
读取 pcap 头部（判断链路类型：802.11 / Radiotap）
    │
    ▼
逐包解析 802.11 帧
    ├── Management 帧（Beacon/Probe Response）
    │   ├── 提取 ESSID（IE Tag 0）
    │   └── 提取 RSN IE（IE Tag 48）
    │
    └── Data 帧（LLC SNAP + EAPOL）
        ├── 解析 EAPOL Key 消息（消息号 1-4）
        ├── 提取 ANonce（消息 1、3）
        ├── 提取 EAPOL 完整帧（消息 2、3）
        ├── 提取 PMKID（RSN IE / KDE Type 4）
        └── 追踪 4 次握手状态
    │
    ▼
消息排序 → 匹配握手对
    ├── 优先 M1+M2（M12E2）
    ├── 其次 M3+M2（M32E2）
    ├── 再其次 M3+M4（M34E3）
    └── 最后 M1+M4（M14E4）
    │
    ▼
提取 MIC → 清零 EAPOL 中 MIC 位置 → 格式化 HC22000 输出
```

## 支持的输入格式

- **PCAP**: 经典 libpcap 格式（小端 `0xa1b2c3d4` 和大端 `0xd4c3b2a1`）
- **PCAPNG**: pcap next generation 格式（`0x0a0d0d0a`）
- **CAP**: 与 pcap 兼容的旧格式

## 支持的链路类型

- `LINKTYPE_IEEE802_11` (105): 原始 802.11 帧
- `LINKTYPE_IEEE802_11_RADIOTAP` (127): 带 Radiotap 头的 802.11 帧

## 测试

```bash
go test ./hcx/ -v
```

## License

Apache License 2.0