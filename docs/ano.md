# ano — 网络协议操作库（Go 版 Scapy 核心）

基于 Scapy 设计理念的 Go 网络协议操作库。支持**多层数据包构造**、协议字段自定义、数据包序列化/反序列化、原始套接字发送/接收。

---

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/ano"
```

---

## 数据报构造总览

ano 对标 Scapy 的层叠式数据包构造：

```
Scapy:   Ether(dst="ff:...")/IP(src="10.0.0.1")/TCP(sport=12345, dport=80, flags="S")
ano:     Build(Ether, IPv4, TCP)
```

每一层是一个结构体，通过 `Build()` 从底至上（L2→L3→L4→Payload）层叠组装。  
`Build()` 接收任意数量的 `Layer`，按传入顺序序列化。

---

## 构造一个完整的数据报

### 基本流程

```go
// 1. 创建各层并设置字段
ether := ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff").SetSrc("00:de:ad:be:ef:01")
ip := ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1")
tcp := ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_SYN)

// 2. 层叠组装
pkt := ano.Build(ether, ip, tcp)

// 3. 序列化为字节
data := pkt.Bytes() // 54 字节以太网帧
```

### 链式写法（一行构造）

```go
pkt := ano.Build(
    ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff").SetSrc("00:de:ad:be:ef:01"),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1").SetTTL(64),
    ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_SYN|ano.TCP_ACK),
)
```

### 分步构造（灵活修改）

```go
ether := ano.NewEther()
ether.Dst = ano.MAC("ff:ff:ff:ff:ff:ff")  // 直接赋值 [6]byte
ether.Src = ano.MAC("00:de:ad:be:ef:01")
ether.Type = ano.ETH_P_IP                  // 直接设置 EtherType

ip := ano.NewIPv4()
ip.Src = ano.IP("10.0.0.1")               // 直接赋值 [4]byte
ip.Dst = ano.IP("192.168.1.1")
ip.TTL = 128
ip.Protocol = ano.IP_PROTO_TCP
ip.ID = 0x1234

tcp := ano.NewTCP()
tcp.SrcPort = 54321
tcp.DstPort = 80
tcp.Flags = ano.TCP_SYN | ano.TCP_ACK
tcp.Seq = 1000
tcp.Ack = 0
tcp.Window = 65535

pkt := ano.Build(ether, ip, tcp)
```

> **`[6]byte` / `[4]byte` 辅助转换**：`ano.MAC("xx:xx:xx:xx:xx:xx")` 将字符串转 `[6]byte`，`ano.IP("x.x.x.x")` 将字符串转 `[4]byte`。也可直接用 `ano.MACString(mac)` / `ano.IPBytes(ip)` 转回字符串。

---

## 数据报的"层"（Layer）

`Layer` 是 ano 的核心接口，任何实现了以下方法的类型都可以作为一层：

```go
type Layer interface {
    Serialize() []byte        // 序列化：从 Go 结构体 → 网络字节
    Deserialize([]byte) ([]byte, error)  // 反序列化：从网络字节 → Go 结构体
    Len() int                 // 固定长度（变长层返回最小长度）
    Next(data []byte) Layer   // 剩余载荷推测下一个协议层（nil 表示无后续）
    Copy() Layer              // 深拷贝
}
```

`ano` 将所有 reflect（反射）调用从核心路径中移除，改为基于 `Tag()` 的零反射机制。

```go
type Layer interface {
    Tag() string              // 返回唯一类型标识（如 "Ether", "IPv4", "TCP"）
    Serialize() []byte
    Deserialize([]byte) ([]byte, error)
    Len() int
    Next(data []byte) Layer
    Copy() Layer
}
```

各层 Tag 值：

| 层类型 | Tag |
|--------|-----|
| `*Ether` | `"Ether"` |
| `*IPv4` | `"IPv4"` |
| `*IPv6` | `"IPv6"` |
| `*TCP` | `"TCP"` |
| `*UDP` | `"UDP"` |
| `*ICMP` | `"ICMP"` |
| `*ARP` | `"ARP"` |
| `*DNS` | `"DNS"` |
| `*Raw` | `"Raw"` |

### 通过 Tag 操作层（推荐，零反射）

```go
// 查找层（新式 Tag 名称）
ip := pkt.Get("IPv4")
tcp := pkt.Get("TCP")

// 判断是否存在
if pkt.Has("UDP") { ... }

// 替换层
pkt.Set(ano.NewTCP().SetDPort(443))

// 删除层
pkt.Remove("ICMP")

// 层级展示
fmt.Println(pkt.Show())  // "Ether > IPv4 > TCP > "
```

### 向后兼容（旧式名称仍有效）

```go
pkt.Get("*ano.IPv4")   // 自动映射为 Tag "IPv4"
pkt.Get("ano.TCP")     // 自动映射为 Tag "TCP"
```

### 层类型工厂注册（替代 `BindLayer[T]` 泛型反射）

```go
// 注册协议号到层类型的工厂函数
ano.RegisterBinding(ano.IP_PROTO_TCP, func() ano.Layer { return &ano.TCP{} })
ano.RegisterBinding(ano.IP_PROTO_UDP, func() ano.Layer { return &ano.UDP{} })

// 根据协议号动态创建层实例
layer := ano.LookupBinding(ano.IP_PROTO_TCP)  // → *TCP
```

---

### 内建协议层

| 类型 | 创建函数 | 对标 Scapy | 长度 |
|------|---------|-----------|------|
| `*Ether` | `NewEther()` | `Ether()` | 14 |
| `*IPv4` | `NewIPv4()` | `IP()` | 20+ |
| `*IPv6` | `NewIPv6()` | `IPv6()` | 40 |
| `*TCP` | `NewTCP()` | `TCP()` | 20+ |
| `*UDP` | `NewUDP()` | `UDP()` | 8 |
| `*ICMP` | `NewICMP()` | `ICMP()` | 8+ |
| `*ARP` | `NewARP(op)` | `ARP()` | 28 |
| `*DNS` | `NewDNS()` / `NewDNSQR(name, type)` | `DNS()` | 变长 |
| `*Raw` | `NewRaw(data)` | `Raw()` | 变长 |

### 层的字段操作

每一层既可以通过 `.字段名` 直接赋值，也可以通过链式方法设置：

| 层 | 链式方法 | 直接字段 |
|----|---------|---------|
| Ether | `SetDst(s)` `SetSrc(s)` `SetType(t)` `SetDstMAC(m)` `SetSrcMAC(m)` | `.Dst [6]byte` `.Src [6]byte` `.Type uint16` |
| IPv4 | `SetSrc(s)` `SetDst(s)` `SetTTL(t)` `SetID(id)` `SetProtocol(p)` | `.Src [4]byte` `.Dst [4]byte` `.TTL uint8` `.Protocol uint8` `.ID uint16` |
| TCP | `SetSPort(p)` `SetDPort(p)` `SetSeq(s)` `SetAck(a)` `SetFlags(f)` `SetWindow(w)` | `.SrcPort uint16` `.DstPort uint16` `.Seq uint32` `.Flags uint8` |
| UDP | `SetSPort(p)` `SetDPort(p)` | `.SrcPort uint16` `.DstPort uint16` |
| ICMP | — | `.Type uint8` `.Code uint8` `.ID uint16` `.Seq uint16` |
| ARP | `Request()` `Reply()` `SrcMACStr(s)` `DstMACStr(s)` `SrcIPStr(s)` `DstIPStr(s)` | `.Op uint16` `.SrcMAC [6]byte` `.SrcIP [4]byte` |

---

## 数据报的操纵

### 层叠操作

```go
pkt := ano.Build(ano.NewEther(), ano.NewIPv4())  // 初始 2 层

// 追加层
pkt.Add(ano.NewTCP())

// 替换层（按类型匹配）
pkt.Set(ano.NewUDP())  // 将 TCP 替换为 UDP

// 获取层
ip := pkt.Get("*ano.IPv4").(*ano.IPv4)
ether := pkt.Get("Ether")

// 判断是否有某层
if pkt.Has("*ano.TCP") { ... }

// 移除层
pkt.Remove("*ano.ARP")

// 遍历所有层
for _, l := range pkt.Layers {
    switch v := l.(type) {
    case *ano.IPv4:
        fmt.Println(ano.IPBytes(v.Src))
    }
}
```

### 自定义负载（Payload）

最后一层之后剩余的字节自动成为 `Payload`：

```go
pkt := ano.Build(ano.NewEther(), ano.NewIPv4(), ano.NewTCP())
pkt.Payload = []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}  // "Hello" 作为 TCP 数据

data := pkt.Bytes()
// 54 字节头部 + 5 字节负载 = 59 字节
```

### 直接构造原始包（Raw 层）

如果需要标准的 TLS / HTTP / 自定义协议载荷：

```go
pkt := ano.Build(
    ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff"),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("10.0.0.2").SetProtocol(ano.IP_PROTO_TCP),
    ano.NewTCP().SetSPort(443).SetDPort(54321).SetFlags(ano.TCP_SYN|ano.TCP_ACK),
    ano.NewRaw([]byte{0x16, 0x03, 0x01, 0x00, 0x01}),  // TLS ClientHello 头部
)
```

---

## 各种协议数据报示例

### 1. 以太网 + ARP 请求

```go
pkt := ano.Build(
    ano.NewEther().SetDstMAC(ano.BroadcastMAC).SetType(ano.ETH_P_ARP),
    ano.NewARP(ano.ARP_REQUEST).
        SrcMACStr("00:de:ad:be:ef:01").
        SrcIPStr("192.168.1.100").
        DstIPStr("192.168.1.1"),
)
// 42 字节
```

### 2. 以太网 + IPv4 + TCP SYN

```go
pkt := ano.Build(
    ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff"),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1"),
    ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_SYN),
)
// 54 字节
```

### 3. 以太网 + IPv4 + UDP + DNS 查询

```go
pkt := ano.Build(
    ano.NewEther(),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("8.8.8.8").SetProtocol(ano.IP_PROTO_UDP),
    ano.NewUDP().SetSPort(12345).SetDPort(53),
    ano.NewDNSQR("example.com", ano.DNS_A),
)
```

### 4. 以太网 + IPv4 + ICMP Echo (ping)

```go
pkt := ano.Build(
    ano.NewEther(),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("8.8.8.8").SetProtocol(ano.IP_PROTO_ICMP),
    ano.NewICMP(),
)
```

### 5. TCP 校验和手动计算

TCP/UDP 校验和需要伪首部（含源/目的 IP），Serialze() 不会自动计算：

```go
ip := ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1")
tcp := ano.NewTCP().SetSPort(12345).SetDPort(80).SetFlags(ano.TCP_SYN)
tcp.Checksum = ano.TCPChecksum(tcp, ip.Src, ip.Dst)

pkt := ano.Build(ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff"), ip, tcp)
```

### 6. 分片发送大数据包

```go
payload := make([]byte, 3000)  // 超过 MTU 1500
pkt := ano.Build(
    ano.NewEther(),
    ano.NewIPv4().SetSrc("10.0.0.1").SetDst("10.0.0.2"),
    ano.NewTCP().SetSPort(12345).SetDPort(80),
    ano.NewRaw(payload),
)
// Bytes() = 14 + 20 + 20 + 3000 = 3054 字节（层叠不计分片）
```

### 7. IPv6 数据报

```go
pkt := ano.Build(
    ano.NewEther().SetType(ano.ETH_P_IPV6),
    ano.NewIPv6(),
    ano.NewTCP().SetSPort(12345).SetDPort(443),
)
```

---

## 从字节流解析数据报

### 手动解析

```go
raw := pkt.Bytes()
parsed := ano.Build(&ano.Ether{})  // 以以太网层为起点
parsed.Parse(raw)

for _, layer := range parsed.Layers {
    switch v := layer.(type) {
    case *ano.Ether:
        fmt.Println("MAC:", ano.MACString(v.Dst), "->", ano.MACString(v.Src))
    case *ano.IPv4:
        fmt.Println("IP:", ano.IPBytes(v.Src), "->", ano.IPBytes(v.Dst))
    case *ano.TCP:
        fmt.Println("TCP:", v.SrcPort, "->", v.DstPort, "Flags:", v.Flags)
    }
}
```

### ParseEther（自动推断后续层）

`ParseEther` 从以太网帧自动解析 L3/L4 层：

```go
parsed, err := ano.ParseEther(rawBytes)
// parsed.Layers 自动包含 Ether → IPv4 → TCP（根据 EtherType 和 IP Protocol 推断）
```

### 从 pcap 文件解析

```go
pkts, _ := ano.LoadPcap("capture.pcap")
for _, pkt := range pkts {
    fmt.Println(pkt.Summary())  // "10.0.0.1:54321 > 192.168.1.1:80"
}
```

---

## 随机化数据报字段（Fuzz）

对标 Scapy 的 `fuzz()` 函数：

```go
pkt := ano.Build(ano.NewEther(), ano.NewIPv4(), ano.NewTCP())

// 全部字段随机化
ano.FuzzPacket(pkt, nil)
// pkt 的 MAC/IP/Port/Seq/TTL/Flags 全部变为随机值

// 仅随机部分字段
ano.FuzzPacket(pkt, &ano.FuzzOpts{
    RandIP:   true,
    RandMAC:  true,
    RandPort: false,
})

// 单层随机化
ano.FuzzLayer(pkt.Get("*ano.IPv4"))
```

---

## 原始套接字发送（Linux，需 root）

```go
// 构造包
pkt := ano.Build(ano.NewEther(), ano.NewIPv4(), ano.NewTCP())

// 全局发送（自动选择接口）
ano.Send(pkt)

// 指定网卡
ano.SendOnIface("eth0", pkt)

// 构建套接字并发送
rs, _ := ano.NewRawSocket("eth0")
defer rs.Close()
rs.Send(pkt)

// 发送并接收回复
replies, _ := rs.Sr(pkt, 5*time.Second)
for _, reply := range replies {
    fmt.Println("Reply:", reply.Summary())
}
```

---

## 网卡识别

ano 提供完整的网卡信息查询功能，可列出所有网络接口的详细属性。

### NetInterface 结构体

```go
type NetInterface struct {
    Name        string    // 网卡名称（如 eth0、wlan0）
    Index       int       // 系统接口索引
    MAC         string    // MAC 地址字符串
    IPs         []string  // IP 地址列表（含 CIDR）
    Flags       []string  // 标志列表（UP、LOOPBACK、MULTICAST、BROADCAST、P2P）
    MTU         int       // 最大传输单元
    IsUp        bool      // 是否已启用
    IsLoopback  bool      // 是否为回环接口
    IsMulticast bool      // 是否支持多播
}
```

### 列出所有网卡

```go
nics, err := ano.ListNetInterfaces()
if err != nil {
    log.Fatal(err)
}
for _, nic := range nics {
    fmt.Printf("%s: mac=%s mtu=%d up=%v ips=%v\n",
        nic.Name, nic.MAC, nic.MTU, nic.IsUp, nic.IPs)
}
```

### 按名称查找网卡

```go
nic, err := ano.FindInterface("eth0")
if err != nil {
    log.Fatal(err)
}
fmt.Println(nic.MAC, nic.IPs)
```

### 获取默认网卡

自动选择第一个非回环、已启用、有 MAC 地址的网卡：

```go
nic, err := ano.DefaultInterface()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("默认网卡: %s (MAC: %s)\n", nic.Name, nic.MAC)
```

| 函数 | 返回 | 说明 |
|------|------|------|
| `ListNetInterfaces()` | `([]NetInterface, error)` | 列出所有网卡详细信息 |
| `FindInterface(name)` | `(*NetInterface, error)` | 按名称查找指定网卡 |
| `DefaultInterface()` | `(*NetInterface, error)` | 获取默认可用网卡 |

---

## ShellCode — 交互式 Shell（对标 Scapy `interact()`）

对标 Scapy 的 `interact()` 交互式控制台。启动一个 **Bash shell**，提示符为 `ano>> `，支持系统命令和 ano 数据包构造命令混用。

### 启动

```go
ano.ShellCode()
```

运行后效果：

```
+----------------------------------------------------+
|     ano shell  -  网络数据包构造器                 |
+----------------------------------------------------+

  help             查看帮助
  ano list         列出支持的协议
  ano build <协议>  构造数据包
  ano send <协议>  构造并发送
  输入 exit    退出

ano>>
```

### 提示符

```
ano>>
```

启动后自动进入 Bash shell，提示符为 `ano>> `。在此 shell 中：
- **系统命令**直接执行：`ls`, `cd`, `ping`, `curl`, `go` 等全部可用
- **ano 命令**通过 `ano <子命令>` 执行
- **退出**输入 `exit` 或 `Ctrl+D`

### 命令列表

| 命令 | 说明 |
|------|------|
| `help` | 显示帮助 |
| `ano list` | 列出所有支持的协议 |
| `ano build <协议>` | 构造指定协议数据包并显示 |
| `ano send <协议>` | 构造并发送数据包（需 root） |
| `ano eval <代码>` | 执行 Go/ano 代码（ano 已预导入） |
| `ano fuzz` | 模糊测试 |
| `ano import <pcap文件>` | 导入 pcap 文件进入交互式解析模式 |

### 支持的协议（ano build / ano send）

| 协议名 | 说明 | 参数 |
|--------|------|------|
| `tcp-syn` | TCP SYN 握手 | 目标IP [端口=80] |
| `tcp-synack` | TCP SYN-ACK 响应 | — |
| `tcp-rst` | TCP RST 重置 | — |
| `tcp-fin` | TCP FIN 结束 | — |
| `udp-dns` | DNS A 记录查询 | 域名 (默认 example.com) |
| `icmp-ping` | ICMP Echo 请求 | — |
| `icmp-unreach` | ICMP 目标不可达 | — |
| `arp-request` | ARP who-has 请求 | — |
| `arp-reply` | ARP 回复 | — |
| `ipv6` | IPv6 + TCP 包 | — |
| `tls-hello` | TLS ClientHello | — |
| `http-get` | HTTP GET 请求 | 主机名 (默认 example.com) |
| `dhcp` | DHCP Discover | — |

### build — 构造协议数据包

```bash
ano>> ano build tcp-syn
ano>> ano build tcp-synack
ano>> ano build icmp-ping
ano>> ano build arp-request
ano>> ano build udp-dns example.com
ano>> ano build http-get example.com
ano>> ano build tcp-syn 192.168.1.1 8080
```

输出示例：
```
0000   ff ff ff ff ff ff 00 de ad be ef 01 08 00  |..............|
0010   45 00 00 28 00 00 40 00 40 06 f4 1e 0a 00  |E..(..@.@.....|
0020   00 01 c0 a8 01 01 d4 31 00 50 00 00 00 00  |.......1.P....|
0030   00 00 00 00 50 02 ff ff 00 00 00 00 00 00  |....P.........|
Total: 54 bytes
Layers: Ether > IPv4 > TCP
```

### send — 构造并发送数据包（需 root）

```bash
ano>> sudo ano send arp-request
ano>> sudo ano send icmp-ping
ano>> sudo ano send tcp-syn 10.0.0.2 80
```

### list — 列出协议

```bash
ano>> ano list
```

输出：
```
可用协议:
  tcp-syn       TCP SYN 握手包
  tcp-synack    TCP SYN-ACK 响应
  tcp-rst       TCP RST 重置包
  tcp-fin       TCP FIN 结束包
  udp-dns       DNS 查询包 (ano build udp-dns <域名>)
  icmp-ping     ICMP Echo 请求
  icmp-unreach  ICMP 目标不可达
  arp-request   ARP 请求 who-has
  arp-reply     ARP 回复
  ipv6          IPv6 数据包
  tls-hello     TLS ClientHello
  http-get      HTTP GET 请求
  dhcp          DHCP Discover
```

### craft — 交互式数据包构造

逐层添加协议、设置字段值，完全控制数据包的每个字节。**发送时自动补全 checksum、源 MAC 和网卡**。

#### 子命令

| 子命令 | 说明 |
|--------|------|
| `new` | 创建新数据包 |
| `add <层>` | 添加协议层（ether / ip / tcp / udp / icmp / arp / raw） |
| `rm <层>` | 移除协议层 |
| `set <层>.<字段> <值>` | 设置字段值 |
| `show` | 显示所有层和字段值 |
| `hex` | 显示 Hex 转储 |
| `send [网卡]` | **发送数据包**（自动补 checksum + 源 MAC） |
| `save <文件>` | 保存为 pcap |
| `list` | 列出当前已有层 |

#### 快速入门

```bash
ano craft new                          # 创建新数据包
ano craft add ether                    # 添加以太网层
ano craft set ether.dst ff:ff:ff:ff:ff:ff
ano craft set ether.src 00:de:ad:be:ef:01
ano craft add ip                      # 添加 IP 层
ano craft set ip.src 10.0.0.1
ano craft set ip.dst 192.168.1.1
ano craft add tcp                     # 添加 TCP 层
ano craft set tcp.sport 54321
ano craft set tcp.dport 80
ano craft set tcp.flags syn           # 或 syn,ack / fin / rst
ano craft show                        # 查看当前包字段
ano craft hex                         # 查看 Hex 转储
sudo ano craft send                   # 自动补全后发送
ano craft save out.pcap               # 保存为 pcap
```

#### 支持的层与字段

| 层 | 字段 | 说明 | 示例值 |
|----|------|------|--------|
| `ether` | `dst` | 目标 MAC | `ff:ff:ff:ff:ff:ff` |
| | `src` | 源 MAC（发送时自动补网卡 MAC） | `00:de:ad:be:ef:01` |
| | `type` | EtherType（十进制） | `2048` (0x0800) |
| `ip` | `src` | 源 IP | `10.0.0.1` |
| | `dst` | 目标 IP | `192.168.1.1` |
| | `ttl` | TTL | `64` |
| | `proto` | 协议号 | `6` (TCP) |
| `tcp` | `sport` | 源端口 | `54321` |
| | `dport` | 目标端口 | `80` |
| | `seq` | 序列号 | `1000` |
| | `flags` | 标志位（逗号分隔） | `syn` / `syn,ack` / `fin` / `rst` |
| | `window` | 窗口大小 | `65535` |
| `udp` | `sport` | 源端口 | `12345` |
| | `dport` | 目标端口 | `53` |
| `icmp` | `type` | ICMP 类型 | `8` (Echo) |
| | `code` | ICMP 代码 | `0` |
| `arp` | `smac` | 源 MAC | `00:de:ad:be:ef:01` |
| | `dmac` | 目标 MAC | `00:00:00:00:00:00` |
| | `sip` | 源 IP | `192.168.1.100` |
| | `dip` | 目标 IP | `192.168.1.1` |

#### 发送流程（自动补全）

`ano craft send` 发送时自动完成以下操作：

1. **TCP/UDP checksum** — 根据 IP 层 src/dst 自动计算伪首部校验和
2. **源 MAC** — 如果 ether.src 为全零，从当前网卡读取真实 MAC 填入
3. **网卡检测** — 自动选择第一个非回环、UP 状态、有 MAC 的网卡

```
ano>> sudo ano craft send
自动补全源 MAC: 00:1a:2b:3c:4d:5e
Ether: dst=00:00:00:00:00:00 src=00:1a:2b:3c:4d:5e type=0x0800
IPv4:  src=10.0.0.1 dst=8.8.8.8 ttl=64 proto=6
TCP:   54321->53 seq=12345 flags=SYN window=65535
发送成功
```

> **注意**：目标 MAC 为 `00:00:00:00:00:00` 时交换机会丢包。要用 `set ether.dst` 填正确的下一跳 MAC（如网关 MAC），或用广播地址 `ff:ff:ff:ff:ff:ff`。

#### 完整示例：TCP SYN 扫描

```bash
ano>> ano craft new
ano>> ano craft add ether
ano>> ano craft set ether.dst 52:54:00:12:34:56
ano>> ano craft add ip
ano>> ano craft set ip.src 10.0.0.1
ano>> ano craft set ip.dst 110.242.68.66
ano>> ano craft add tcp
ano>> ano craft set tcp.dport 80
ano>> ano craft set tcp.flags syn
ano>> ano craft show
Ether: dst=52:54:00:12:34:56 src=00:00:00:00:00:00 type=0x0800
IPv4:  src=10.0.0.1 dst=110.242.68.66 ttl=64 proto=6
TCP:   54321->80 seq=... flags=SYN window=65535
ano>> sudo ano craft send
自动补全源 MAC: 00:1a:2b:3c:4d:5e
发送成功
```

#### 保存为 pcap 文件

```bash
ano>> ano craft save syn_scan.pcap
```

### eval — 执行 Go/ano 代码

`ano eval` 将 Go 代码编译为临时程序并执行，`ano` 包已预导入，可直接使用 `ano.FuncName()`。

```bash
# 生成随机 IP
ano>> ano eval 'fmt.Println(ano.RandIP("10.0.0.0/24"))'
10.0.0.142

# 生成随机 MAC
ano>> ano eval 'fmt.Println(ano.RandMAC("00:de:ad:*:*:*"))'
00:de:ad:3e:a1:7c

# 随机端口和序列号
ano>> ano eval 'fmt.Println(ano.RandPort(), ano.RandSeq())'
45123 3728491023

# 构建并显示数据包
ano>> ano eval '
  pkt := ano.Build(
      ano.NewEther().SetDst("ff:ff:ff:ff:ff:ff"),
      ano.NewIPv4().SetSrc("10.0.0.1").SetDst("8.8.8.8"),
      ano.NewTCP().SetSPort(12345).SetDPort(80).SetFlags(ano.TCP_SYN),
  )
  fmt.Print(ano.HexDump(pkt.Bytes()))
'

# 解析以太网帧
ano>> ano eval '
  pkt, _ := ano.ParseEther([]byte{...})
  fmt.Println(pkt.Summary())
'
```

### dns — 构造 DNS 查询包

```bash
ano>> ano dns example.com
```

输出 Hex 格式的 DNS 查询数据包。

### import — 导入并解析 pcap 文件

```bash
ano>> ano import capture.pcap
```

导入 pcap 文件后进入**解析模式**，提示符变为 `ano(pcap)>>`，支持以下命令：

| 命令 | 说明 |
|------|------|
| `cat` | 查看数据包列表（带序号和摘要） |
| `cat <序号>` | 查看指定数据包的 Hex 转储和逐层详情 |
| `quit` | 退出解析模式，返回 ano shell |

示例：

```bash
ano>> ano import test.pcap
成功导入 10 个数据包
输入 cat 查看列表, cat <序号> 查看详情, quit 退出
ano(pcap)>> cat
[1] 10.0.0.1:54321 > 192.168.1.1:80
[2] 192.168.1.1:80 > 10.0.0.1:54321
...
ano(pcap)>> cat 1
0000   ff ff ff ff ff ff 00 de ad be ef 01 08 00  |..............|
...
Total: 54 bytes
Layers: Ether > IPv4 > TCP
  Ether: 00:de:ad:be:ef:01 > ff:ff:ff:ff:ff:ff type=0x0800
  IPv4:  10.0.0.1 > 192.168.1.1 ttl=64 proto=6
  TCP:   54321->80 seq=0 flags=SYN window=65535
ano(pcap)>> quit
ano>>
```

### 库函数 API（import / cat 对应关系）

| Shell 命令 | Go 库函数 | 说明 |
|-----------|-----------|------|
| `ano import <文件>` | `ano.LoadPacketList(path)` / `ano.LoadPcap(path)` | 导入 pcap 文件 |
| `cat` | `pl.PrintList()` | 打印所有数据包摘要（带序号） |
| `cat <n>` | `pl.Show(n)` | 打印第 n 个数据包的 Hex 转储和逐层详情 |

```go
// 导入 pcap 文件
pl, err := ano.LoadPacketList("test.pcap")

// cat - 列出所有数据包
pl.PrintList()

// cat <n> - 查看第 1 个数据包详情
pl.Show(1)
```

### fuzz — 模糊测试

```bash
ano>> ano fuzz
```

构建一个 TCP SYN 包并将所有字段（MAC/IP/Port/Seq/TTL/Flags）随机化后显示。

### send — 发送数据包（需 root）

```bash
ano>> sudo ano send
```

构建一个 TCP SYN 包并通过原始套接字发送。

### 系统命令

shell 本身就是完整的 Bash 环境，可执行任意系统命令：

```bash
ano>> ls -la
ano>> ping -c 4 8.8.8.8
ano>> curl -I https://example.com
ano>> go build myproject
ano>> nmap -sS 192.168.1.1
```

### 退出

```bash
ano>> exit
```

或 `Ctrl+D`。

### 完整使用流程示例

```bash
# 启动
$ go run main.go

# 进入 shell 后
ano>> ano help
ano>> ano pkt
ano>> ano eval 'fmt.Println(ano.RandIP("10.0.0.0/24"))'
ano>> ano dns example.com
ano>> ls -la
ano>> ano fuzz
ano>> ping google.com
ano>> exit
```

### 对比 Scapy

| Scapy | ano |
|-------|-----|
| `interact()` | `ShellCode()` |
| 提示符 `>>> ` | 提示符 `ano>> ` |
| `Ether()/IP()/TCP()` 直接输入 | `ano pkt` 或 `ano eval 'Build(...)'` |
| `!ls` 执行系统命令 | 直接输入 `ls`（本身就是系统 shell） |
| 预导入所有 Scapy 符号 | `ano eval` 已预导入 `ano.*` |

---

## 嗅探与捕获数据包

### 底层嗅探器（Sniffer）

```go
// 阻塞式嗅探（超时+计数）
pkts, _ := ano.Sniff("eth0", 10*time.Second, 100)

// 仅计数
pkts, _ = ano.SniffCount("eth0", 50)

// 异步嗅探 + 回调
s := ano.NewSniffer().
    OnIface("eth0").
    WithTimeout(30*time.Second).
    WithCount(100).
    WithCallback(func(pkt *ano.Packet) {
        fmt.Println("Got:", pkt.Summary())
    })
ch, _ := s.Start()
for pkt := range ch {
    // 处理
}
```

### 便捷捕获函数

`Capture` 和 `CaptureWithCallback` 是对 `Sniffer` 的简化封装，无需手动创建 Sniffer 实例：

```go
// 阻塞式捕获
pkts, err := ano.Capture("eth0", 10*time.Second, 100)
for _, pkt := range pkts {
    fmt.Println(pkt.Summary())
}

// 回调式捕获（实时处理每个包）
err := ano.CaptureWithCallback("eth0", 30*time.Second, 0,
    func(pkt *ano.Packet) {
        fmt.Println(pkt.Summary())
    },
)
```

| 函数 | 说明 |
|------|------|
| `Capture(iface, timeout, count)` | 阻塞式捕获，返回数据包列表 |
| `CaptureWithCallback(iface, timeout, count, cb)` | 回调式捕获，每收到一个包即触发回调 |
| `CaptureWithFilter(iface, timeout, count, filter)` | 带 BPF 过滤的阻塞式捕获 |
| `CaptureWithFilterCallback(iface, timeout, count, filter, cb)` | 带 BPF 过滤的回调式捕获 |

### BPF 过滤器

ano 集成了 `golang.org/x/net/bpf`，支持在抓包时使用 BPF（Berkeley Packet Filter）表达式在内核层过滤数据包，极大提升嗅探性能——只捕获符合条件的数据包，避免用户态处理无用流量。

#### Sniffer 方式

```go
// 仅捕获 TCP 80 端口流量
pkts, _ := ano.SniffWithFilter("eth0", 10*time.Second, 100, "tcp port 80")

// Sniffer 链式配置
s := ano.NewSniffer().
    OnIface("eth0").
    WithTimeout(10*time.Second).
    WithCount(0).
    WithFilter("tcp and dst port 443")
ch, _ := s.Start()
```

#### 便捷函数方式

```go
// 带过滤的阻塞式捕获
pkts, _ := ano.CaptureWithFilter("eth0", 10*time.Second, 100, "icmp or udp port 53")

// 带过滤的回调式捕获
ano.CaptureWithFilterCallback("eth0", 30*time.Second, 0, "tcp",
    func(pkt *ano.Packet) {
        fmt.Println(pkt.Summary())
    },
)
```

#### RawSocket 直接设置

```go
rs, _ := ano.NewRawSocket("eth0")
defer rs.Close()
rs.SetBPF("tcp port 80")
```

#### 支持的 BPF 表达式语法

| 表达式 | 含义 | 示例 |
|--------|------|------|
| `tcp` / `udp` / `icmp` | IP 协议过滤 | `tcp` |
| `arp` / `ip` / `ip6` | 以太网帧类型过滤 | `arp` |
| `port N` | TCP/UDP 源或目标端口 | `port 80` |
| `tcp port N` | 仅 TCP 端口 | `tcp port 443` |
| `udp port N` | 仅 UDP 端口 | `udp port 53` |
| `host X.X.X.X` | 源或目标 IP | `host 192.168.1.1` |
| `src host X` | 仅源 IP | `src host 10.0.0.1` |
| `dst host X` | 仅目标 IP | `dst host 8.8.8.8` |
| `src port N` | 源端口 | `src port 80` |
| `dst port N` | 目标端口 | `dst port 443` |
| `net X.X.X.X/N` | 子网过滤 | `net 192.168.0.0/16` |
| `and` / `or` | 逻辑组合 | `tcp and port 80` |
| `not` | 逻辑取反 | `not arp` |

#### 编译与附加

```go
// 编译 BPF 表达式为字节码（无需 socket）
insns, err := ano.CompileBPF("tcp port 80")

// 编译并附加到 socket fd
err := ano.SetSocketBPF(fd, "udp port 53")
```

| 函数 | 说明 |
|------|------|
| `CompileBPF(expr)` | 编译 BPF 表达式为原始字节码 |
| `SetSocketBPF(fd, expr)` | 编译并附加 BPF 过滤器到 socket fd |
| `SniffWithFilter(iface, timeout, count, filter)` | 带过滤的便捷嗅探 |
| `RawSocket.SetBPF(expr)` | 在原始套接字上设置 BPF 过滤器 |

---

## 数据包列表与文件持久化

### PacketList 操作

```go
// 构造 PacketList
pl := ano.NewPacketList()
pl.Add(pkt1)
pl.Add(pkt2)
pl.Add(pkt3)

// 过滤
tcpPackets := pl.Filter("*ano.TCP")

// 打印数据包列表（带序号）
pl.PrintList()

// 查看指定数据包详情（1-indexed）
pl.Show(1)

// 保存为 pcap
pl.Save("output.pcap")

// 从 pcap 加载
loaded, _ := ano.LoadPacketList("output.pcap")
for _, s := range loaded.Summary() {
    fmt.Println(s)
}
```

### Dump 导出函数

ano 支持将数据包导出为 **CAP** 和 **PCAP** 两种格式：

```go
pkts := []*ano.Packet{pkt1, pkt2, pkt3}

// 导出为 CAP 格式（自定义格式，magic: 0x43415021）
ano.DumpCap("output.cap", pkts)

// 导出为 PCAP 格式（标准 libpcap 格式，兼容 Wireshark/tcpdump）
ano.DumpPcap("output.pcap", pkts)

// 自动选择格式（根据文件扩展名 .cap → CAP，其他 → PCAP）
ano.Dump("output.cap", pkts)   // → CAP 格式
ano.Dump("output.pcap", pkts)  // → PCAP 格式
```

### 从文件加载

```go
// 从 CAP 文件加载
pkts, err := ano.LoadCap("input.cap")

// 从 PCAP 文件加载
pkts, err := ano.LoadPcap("input.pcap")

// 从 PCAP 文件加载为 PacketList
pl, err := ano.LoadPacketList("input.pcap")
```

| 函数 | 说明 |
|------|------|
| `DumpCap(path, pkts)` | 导出为 CAP 格式文件 |
| `DumpPcap(path, pkts)` | 导出为 PCAP 格式文件（兼容 Wireshark） |
| `Dump(path, pkts)` | 自动根据扩展名选择格式 |
| `LoadCap(path)` | 从 CAP 文件加载数据包 |
| `LoadPcap(path)` | 从 PCAP 文件加载数据包 |
| `SavePcap(path, pkts)` | 保存为 PCAP（`DumpPcap` 的别名） |

---

## 常用协议常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `ETH_P_IP` | 0x0800 | IPv4 |
| `ETH_P_ARP` | 0x0806 | ARP |
| `ETH_P_IPV6` | 0x86DD | IPv6 |
| `IP_PROTO_TCP` | 6 | TCP |
| `IP_PROTO_UDP` | 17 | UDP |
| `IP_PROTO_ICMP` | 1 | ICMP |
| `TCP_SYN` / `TCP_ACK` / `TCP_FIN` / `TCP_RST` | 2/16/1/4 | TCP 标志位 |
| `ARP_REQUEST` / `ARP_REPLY` | 1/2 | ARP 操作码 |
| `ICMP_ECHO_REQUEST` / `ICMP_ECHO_REPLY` | 8/0 | ICMP Echo |

---

## 随机生成器（用于填充字段）

| 函数 | 返回 | 用途 |
|------|------|------|
| `RandIP(cidr)` | `string` | 随机源/目的 IP |
| `RandMAC(pattern)` | `string` | 随机 MAC |
| `RandPort()` | `int` | 随机端口 |
| `RandSeq()` | `uint32` | TCP 序列号 |
| `RandTTL()` | `int` | TTL 值 |
| `RandBytes(n)` | `[]byte` | 随机载荷 |
| `RandChoice(a,b,c...)` | `T` | 从列表随机选 |

---

## 完整示例对照

| 场景 | Scapy (Python) | ano (Go) |
|------|---------------|----------|
| TCP SYN | `Ether()/IP()/TCP(flags="S")` | `Build(Ether, IPv4, TCP.SetFlags(TCP_SYN))` |
| ARP who-has | `Ether()/ARP(op=1)` | `Build(Ether.SetType(ETH_P_ARP), ARP(ARP_REQUEST))` |
| DNS 查询 | `Ether()/IP()/UDP()/DNS(qd=DNSQR(...))` | `Build(Ether, IPv4, UDP, NewDNSQR(...))` |
| ping | `Ether()/IP()/ICMP(type=8)` | `Build(Ether, IPv4.SetProtocol(IP_PROTO_ICMP), ICMP())` |
| 解析 pcap | `rdpcap("file.pcap")` | `LoadPcap("file.pcap")` |
| 嗅探 | `sniff(iface="eth0", count=10)` | `Sniff("eth0", timeout, 10)` |
| 模糊测试 | `fuzz(pkt)` | `FuzzPacket(pkt, nil)` |

---

## 代码层快速构造（ano/easy.go）

对标 Scapy 的 `send()` / `sr()` 等顶层快捷函数，提供三层易用 API。

### 第一层：一键发送函数

最简单的用法——构造 + 发送一步完成：

```go
ano.SendSYN("10.0.0.1", "192.168.1.1", 80)
ano.SendPing("10.0.0.1", "8.8.8.8")
ano.SendDNSQuery("10.0.0.1", "8.8.8.8", "example.com")
ano.SendARPWhoHas("192.168.1.100", "192.168.1.1")
ano.SendRST("10.0.0.1", "192.168.1.1")
```

| 函数 | 说明 |
|------|------|
| `SendSYN(srcIP, dstIP, dport)` | 构建并发送 TCP SYN |
| `SendPing(srcIP, dstIP)` | 构建并发送 ICMP Echo |
| `SendDNSQuery(srcIP, dstIP, domain)` | 构建并发送 DNS 查询 |
| `SendARPWhoHas(srcIP, targetIP)` | 构建并发送 ARP 请求 |
| `SendRST(srcIP, dstIP)` | 构建并发送 TCP RST |

### 第二层：构建函数（返回 `*Packet`）

先构造、后发送，可修改或复用数据包：

```go
// 构造
pkt := ano.TCPSyn("10.0.0.1", "192.168.1.1", 80)
dnsPkt := ano.UDPDNS("10.0.0.1", "8.8.8.8", "example.com")
arpPkt := ano.ARPRequest("192.168.1.100", "192.168.1.1", "00:de:ad:be:ef:01")
pingPkt := ano.ICMPPing("10.0.0.1", "8.8.8.8")

// 发送
ano.Send(pkt)
ano.SendOnIface("eth0", pkt)
```

| 函数 | 返回 | 说明 |
|------|------|------|
| `TCPSyn(src, dst, dport)` | `*Packet` | TCP SYN |
| `TCPSynAck(src, dst)` | `*Packet` | TCP SYN-ACK |
| `TCPRst(src, dst)` | `*Packet` | TCP RST |
| `TCPFin(src, dst)` | `*Packet` | TCP FIN |
| `UDPDNS(src, dst, domain)` | `*Packet` | DNS 查询 |
| `ICMPPing(src, dst)` | `*Packet` | ICMP Echo |
| `ICMPUnreach(src, dst)` | `*Packet` | ICMP 不可达 |
| `ARPRequest(srcIP, targetIP, srcMAC)` | `*Packet` | ARP 请求 |
| `ARPReply(srcIP, srcMAC, dstIP, dstMAC)` | `*Packet` | ARP 回复 |
| `HTTPGet(srcIP, dstIP, host)` | `*Packet` | HTTP GET |

### 第三层：流式构建器（`PacketBuilder`）

对标 Scapy 的 `Ether()/IP()/TCP()` 链式写法，通过 `NewPacket()` 流式构造。

```go
pkt := ano.NewPacket().
    EtherBroadcast().                           // 以太网广播 MAC
    IPv4("10.0.0.1", "192.168.1.1").            // IPv4
    TCP(54321, 80, "syn").                      // TCP SYN
    Build()                                     // 获取 *Packet
ano.Send(pkt)

// 或直接发送
ano.NewPacket().
    Ether("52:54:00:12:34:56", "").
    IPv4("10.0.0.1", "8.8.8.8").
    ICMP(8, 0).
    Send()

// DNS 查询
ano.NewPacket().
    EtherBroadcast().
    IPv4("10.0.0.1", "8.8.8.8").
    UDP(12345, 53).
    DNS("example.com", ano.DNS_A).
    Send()

// TCP SYN 扫描
ano.NewPacket().
    EtherBroadcast().
    IPv4("10.0.0.1", "10.0.0.2").
    TCP(12345, 3306, "syn").
    Hex()    // 查看 Hex 内容
```

#### PacketBuilder 方法

| 方法 | 说明 |
|------|------|
| `NewPacket()` | 创建构建器 |
| `Ether(dst, src)` | 设以太网层（空串则保留默认） |
| `EtherBroadcast()` | 以太网广播目标 |
| `IPv4(src, dst)` | 设 IPv4 层 |
| `TCP(sport, dport, flags)` | 设 TCP 层（自动算 checksum） |
| `UDP(sport, dport)` | 设 UDP 层 |
| `ICMP(type, code)` | 设 ICMP 层 |
| `ARP(op, smac, sip, dmac, dip)` | 设 ARP 层 |
| `DNS(domain, qtype)` | 追加 DNS 查询 |
| `Raw(data)` | 追加原始负载 |
| `Build()` | 返回 `*Packet` |
| `Send()` | 发送并返回 error |
| `Hex()` | 返回 Hex 转储字符串 |

### Scapy 对照

| Scapy (Python) | ano (Go) |
|----------------|----------|
| `send(IP(dst="1.1.1.1")/TCP(dport=80))` | `ano.SendSYN("10.0.0.1", "1.1.1.1", 80)` |
| `sendp(Ether()/ARP(op=1, ...))` | `ano.SendARPWhoHas("192.168.1.100", "192.168.1.1")` |
| `send(IP(dst="8.8.8.8")/ICMP())` | `ano.SendPing("10.0.0.1", "8.8.8.8")` |
| `Ether()/IP()/TCP(dport=80,flags="S")` | `NewPacket().IPv4(...).TCP(0,80,"syn").Build()` |

---

## 架构一览

| 文件 | 对标 Scapy | 职责 |
|------|-----------|------|
| `packet.go` | `packet.py` | 数据包框架：Build/Parse/层叠/Get/Set/Remove/Summary，Tag 零反射机制 |
| `layers.go` | `layers/*` | 协议层实现：Ether/IPv4/IPv6/TCP/UDP/ICMP/ARP |
| `dns.go` | `layers/dns.py` | DNS 查询/应答构造与解析 |
| `fields.go` | `fields.py` / `fuzz.py` | 字段系统：FuzzPacket/FuzzLayer/RegisterBinding/工厂模式 |
| `raw.go` | `packet.py(Raw)` | 原始载荷层 |
| `easy.go` | `sendrecv.py` 快捷函数 | 一键构造与发送函数 + PacketBuilder |
| `sendrecv.go` | `sendrecv.py` + `supersocket.py` | AF_PACKET 原始套接字 |
| `nic.go` | — | 网卡识别、便捷捕获、CAP/PCAP 导出 |
| `sniffer.go` | `sniff.py` | 异步嗅探器 + BPF 过滤集成 |
| `bpf.go` | — | BPF 表达式编译器 + setsockopt(SO_ATTACH_FILTER) |
| `shell.go` | `main.py` (`interact()`) | 交互式 ShellCode 控制台 |
| `pcap.go` | `utils.py(rdpcap/wrpcap)` | Pcap 读写、PacketList、ParseEther |
| `rand.go` | `volatile.py` | 随机值生成 |
| `utils.go` | `utils.py` | MAC/IP/Hex/校验工具 |
| `consts.go` | `data.py` + `consts.py` | 协议常量 |

---

## License

Apache License 2.0
