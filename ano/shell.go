package ano

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ShellCode() error {
	anoPkg, err := findAnoPackage()
	if err != nil {
		return fmt.Errorf("ano: shellcode: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "anosh_*")
	if err != nil {
		return fmt.Errorf("ano: shellcode: create tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	modPath := filepath.Join(tmpDir, "go.mod")
	modContent := fmt.Sprintf(`module anosh

go 1.26

require %s v0.0.0

replace %s => %s
`, anoPkg, anoPkg, findModuleRoot())

	if err := os.WriteFile(modPath, []byte(modContent), 0644); err != nil {
		return fmt.Errorf("ano: shellcode: write go.mod: %w", err)
	}

	mainPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(buildMainGo(anoPkg)), 0644); err != nil {
		return fmt.Errorf("ano: shellcode: write main.go: %w", err)
	}

	rcPath := filepath.Join(tmpDir, "bashrc")
	rcContent := fmt.Sprintf(`if [ -f ~/.bashrc ]; then
	. ~/.bashrc
fi
alias ano='go run "%s/main.go"'

help() {
	cat <<'EOF'
ano shell - 网络数据包构造器

命令:
  ano build <协议>   构造指定协议数据包
  ano send <协议>    构造并发送数据包（需 root）
  ano craft          交互式逐层构造数据包
  ano eval <代码>    执行 Go/ano 代码
  ano list           列出所有支持的协议
  ano fuzz           模糊测试
  ano import <pcap文件>  导入并解析 pcap 文件

示例:
  ano craft new
  ano craft add ether
  ano craft set ether.dst ff:ff:ff:ff:ff:ff
  ano craft set ip.src 10.0.0.1
  ano craft add tcp
  ano craft set tcp.dport 80
  ano craft set tcp.flags syn
  sudo ano craft send

EOF
}

list() {
	echo "可用协议:"
	echo "  tcp-syn       TCP SYN 握手包"
	echo "  tcp-synack    TCP SYN-ACK 响应"
	echo "  tcp-rst       TCP RST 重置包"
	echo "  tcp-fin       TCP FIN 结束包"
	echo "  udp-dns       DNS 查询包 (ano build udp-dns <域名>)"
	echo "  icmp-ping     ICMP Echo 请求"
	echo "  icmp-unreach  ICMP 目标不可达"
	echo "  arp-request   ARP 请求 who-has"
	echo "  arp-reply     ARP 回复"
	echo "  ipv6          IPv6 数据包"
	echo "  tls-hello     TLS ClientHello"
	echo "  http-get      HTTP GET 请求"
	echo "  dhcp          DHCP Discover"
}

PS1="ano>> "
unset PROMPT_COMMAND 2>/dev/null
`, tmpDir)

	if err := os.WriteFile(rcPath, []byte(rcContent), 0644); err != nil {
		return fmt.Errorf("ano: shellcode: write bashrc: %w", err)
	}

	exec.Command("go", "build", "-o", filepath.Join(tmpDir, "anosh"), mainPath).Run()

	fmt.Println("+----------------------------------------------------+")
	fmt.Println("|     ano shell  -  网络数据包构造器                 |")
	fmt.Println("+----------------------------------------------------+")
	fmt.Println("")
	fmt.Println("  help             查看帮助")
	fmt.Println("  ano list         列出支持的协议")
	fmt.Println("  ano build <协议>  构造数据包")
	fmt.Println("  ano send <协议>  构造并发送")
	fmt.Println("  输入 exit    退出")
	fmt.Println("")

	cmd := exec.Command("/bin/bash", "--rcfile", rcPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	return nil
}

func buildMainGo(anoPkg string) string {
	return fmt.Sprintf(`package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"%s"
)

	const _EVAL_TPL = "package main\n\nimport (\n\t\"fmt\"\n\t\"%s\"\n)\n\nfunc main() {\n\t%%s\n}\n"

const _CRAFT_FILE = "/tmp/anosh_craft.bin"

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "build":
		cmdBuild(args)
	case "send":
		cmdSend(args)
	case "list":
		cmdList()
	case "eval":
		cmdEval(strings.Join(args, " "))
	case "fuzz":
		cmdFuzz()
	case "craft":
		cmdCraft(args)
	case "import":
		cmdImport(args)
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("ano shell - 网络数据包构造器")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  ano build <协议>  构造指定协议数据包")
	fmt.Println("  ano send <协议>   构造并发送数据包（需 root）")
	fmt.Println("  ano craft         交互式逐层构造数据包")
	fmt.Println("  ano eval <代码>   执行 Go/ano 代码")
	fmt.Println("  ano list          列出所有支持的协议")
	fmt.Println("  ano fuzz          模糊测试")
	fmt.Println("  ano import <pcap文件>  导入并解析 pcap 文件")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  ano build tcp-syn")
	fmt.Println("  ano craft new; ano craft add ether; ano craft add ip; ano craft add tcp")
	fmt.Println("  ano send arp-request")
	fmt.Println("  ano eval 'fmt.Println(ano.RandIP(\"10.0.0.0/24\"))'")
}

func cmdList() {
	fmt.Println("可用协议:")
	fmt.Println("  tcp-syn       TCP SYN 握手包")
	fmt.Println("  tcp-synack    TCP SYN-ACK 响应")
	fmt.Println("  tcp-rst       TCP RST 重置包")
	fmt.Println("  tcp-fin       TCP FIN 结束包")
	fmt.Println("  udp-dns       DNS 查询包 (ano build udp-dns <域名>)")
	fmt.Println("  icmp-ping     ICMP Echo 请求")
	fmt.Println("  icmp-unreach  ICMP 目标不可达")
	fmt.Println("  arp-request   ARP 请求 who-has")
	fmt.Println("  arp-reply     ARP 回复")
	fmt.Println("  ipv6          IPv6 数据包")
	fmt.Println("  tls-hello     TLS ClientHello")
	fmt.Println("  http-get      HTTP GET 请求")
	fmt.Println("  dhcp          DHCP Discover")
}

func cmdBuild(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("用法: ano build <协议> [参数]")
		fmt.Println()
		fmt.Println("可用协议:")
		fmt.Println("  tcp-syn [目标IP] [端口] [源端口] [源MAC]  TCP SYN")
		fmt.Println("  tcp-synack                 TCP SYN-ACK 响应")
		fmt.Println("  tcp-rst                    TCP RST 重置")
		fmt.Println("  tcp-fin                    TCP FIN 结束")
		fmt.Println("  udp-dns [域名]             DNS 查询（默认 example.com）")
		fmt.Println("  icmp-ping                  ICMP Echo 请求")
		fmt.Println("  icmp-unreach               ICMP 目标不可达")
		fmt.Println("  arp-request                ARP who-has 请求")
		fmt.Println("  arp-reply                  ARP 回复")
		fmt.Println("  ipv6                       IPv6 数据包")
		fmt.Println("  tls-hello                  TLS ClientHello")
		fmt.Println("  http-get [主机]             HTTP GET（默认 example.com）")
		fmt.Println("  dhcp                       DHCP Discover")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  ano build tcp-syn")
		fmt.Println("  ano build tcp-syn 192.168.1.1 8080")
		fmt.Println("  ano build udp-dns baidu.com")
		return
	}
	name := args[0]
	params := args[1:]

	var pkt *ano.Packet
	switch name {
	case "tcp-syn":
		pkt = buildTCPSyn(params)
	case "tcp-synack":
		pkt = buildTCPSynAck()
	case "tcp-rst":
		pkt = buildTCPRst()
	case "tcp-fin":
		pkt = buildTCPFin()
	case "udp-dns":
		domain := "example.com"
		if len(params) > 0 {
			domain = params[0]
		}
		pkt = buildUDPDNS(domain)
	case "icmp-ping":
		pkt = buildICMPPing()
	case "icmp-unreach":
		pkt = buildICMPUnreach()
	case "arp-request":
		pkt = buildARPRequest()
	case "arp-reply":
		pkt = buildARPReply()
	case "ipv6":
		pkt = buildIPv6()
	case "tls-hello":
		pkt = buildTLSHello()
	case "http-get":
		host := "example.com"
		if len(params) > 0 {
			host = params[0]
		}
		pkt = buildHTTPGet(host)
	case "dhcp":
		pkt = buildDHCP()
	default:
		fmt.Printf("未知协议: %%s\n", name)
		fmt.Println("运行 ano list 查看可用协议")
		return
	}

	if pkt != nil {
		fmt.Println(ano.HexDump(pkt.Bytes()))
		fmt.Printf("总计: %%d 字节\n", len(pkt.Bytes()))
		fmt.Printf("层次: %%s\n", pkt.Show())
	}
}

func cmdSend(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("用法: ano send <协议> [参数]")
		fmt.Println()
		fmt.Println("支持发送的协议:")
		fmt.Println("  tcp-syn [目标IP] [端口] [源端口] [源MAC]  TCP SYN")
		fmt.Println("  tcp-synack                 TCP SYN-ACK")
		fmt.Println("  tcp-rst                    TCP RST")
		fmt.Println("  tcp-fin                    TCP FIN")
		fmt.Println("  icmp-ping                  ICMP Echo")
		fmt.Println("  arp-request                ARP 请求")
		fmt.Println("  arp-reply                  ARP 回复")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  sudo ano send arp-request")
		fmt.Println("  sudo ano send icmp-ping")
		fmt.Println("  sudo ano send tcp-syn 10.0.0.2 80")
		fmt.Println()
		fmt.Println("需要 root 权限")
		return
	}
	name := args[0]
	params := args[1:]

	var pkt *ano.Packet
	switch name {
	case "tcp-syn":
		pkt = buildTCPSyn(params)
	case "tcp-synack":
		pkt = buildTCPSynAck()
	case "tcp-rst":
		pkt = buildTCPRst()
	case "tcp-fin":
		pkt = buildTCPFin()
	case "icmp-ping":
		pkt = buildICMPPing()
	case "arp-request":
		pkt = buildARPRequest()
	case "arp-reply":
		pkt = buildARPReply()
	default:
		fmt.Printf("send 不支持 %%s\n", name)
		return
	}
	if pkt != nil {
		err := ano.Send(pkt)
		if err != nil {
			fmt.Println("发送失败:", err)
		} else {
			fmt.Println("发送成功")
		}
	}
}

func showPacket(pkt *ano.Packet) {
	if pkt == nil {
		return
	}
	fmt.Println(ano.HexDump(pkt.Bytes()))
	fmt.Printf("Total: %%d bytes\n", len(pkt.Bytes()))
	fmt.Printf("Layers: %%s\n", pkt.Show())
}

func buildTCPSyn(params []string) *ano.Packet {
	dstIP := "192.168.1.1"
	srcIP := "10.0.0.1"
	srcMAC := "00:de:ad:be:ef:01"
	dport := 80
	sport := 54321
	switch len(params) {
	case 4:
		srcMAC = params[3]
		fallthrough
	case 3:
		sport = atoi(params[2])
		fallthrough
	case 2:
		dport = atoi(params[1])
		fallthrough
	case 1:
		dstIP = params[0]
	}
	ether := ano.NewEther().SetSrc(srcMAC).SetDst(ano.RandMAC("*:*:*:*:*:*"))
	ip := ano.NewIPv4().SetSrc(srcIP).SetDst(dstIP).SetTTL(64)
	tcp := ano.NewTCP().SetSPort(uint16(sport)).SetDPort(uint16(dport)).SetFlags(ano.TCP_SYN)
	tcp.Checksum = ano.TCPChecksum(tcp, ip.Src, ip.Dst)
	return ano.Build(ether, ip, tcp)
}

func buildTCPSynAck() *ano.Packet {
	ip := ano.NewIPv4().SetSrc("192.168.1.1").SetDst("10.0.0.1")
	tcp := ano.NewTCP().SetSPort(80).SetDPort(54321).SetFlags(ano.TCP_SYN|ano.TCP_ACK)
	tcp.Ack = 1
	tcp.Checksum = ano.TCPChecksum(tcp, ip.Src, ip.Dst)
	return ano.Build(ano.NewEther(), ip, tcp)
}

func buildTCPRst() *ano.Packet {
	ip := ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1")
	tcp := ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_RST)
	tcp.Checksum = ano.TCPChecksum(tcp, ip.Src, ip.Dst)
	return ano.Build(ano.NewEther(), ip, tcp)
}

func buildTCPFin() *ano.Packet {
	ip := ano.NewIPv4().SetSrc("10.0.0.1").SetDst("192.168.1.1")
	tcp := ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_FIN|ano.TCP_ACK)
	tcp.Checksum = ano.TCPChecksum(tcp, ip.Src, ip.Dst)
	return ano.Build(ano.NewEther(), ip, tcp)
}

func buildUDPDNS(domain string) *ano.Packet {
	dns := ano.NewDNSQR(domain, ano.DNS_A)
	return ano.Build(
		ano.NewEther(),
		ano.NewIPv4().SetSrc("10.0.0.1").SetDst("8.8.8.8").SetProtocol(ano.IP_PROTO_UDP),
		ano.NewUDP().SetSPort(12345).SetDPort(53),
		dns,
	)
}

func buildICMPPing() *ano.Packet {
	return ano.Build(
		ano.NewEther(),
		ano.NewIPv4().SetSrc("10.0.0.1").SetDst("8.8.8.8").SetProtocol(ano.IP_PROTO_ICMP),
		ano.NewICMP(),
	)
}

func buildICMPUnreach() *ano.Packet {
	return ano.Build(
		ano.NewEther(),
		ano.NewIPv4().SetSrc("10.0.0.1").SetDst("8.8.8.8").SetProtocol(ano.IP_PROTO_ICMP),
		&ano.ICMP{Type: ano.ICMP_DST_UNREACH, Code: 0, ID: uint16(ano.RandID()), Seq: 1},
	)
}

func buildARPRequest() *ano.Packet {
	return ano.Build(
		ano.NewEther().SetDstMAC(ano.BroadcastMAC).SetType(ano.ETH_P_ARP),
		ano.NewARP(ano.ARP_REQUEST).
			SrcMACStr("00:de:ad:be:ef:01").
			SrcIPStr("192.168.1.100").
			DstIPStr("192.168.1.1"),
	)
}

func buildARPReply() *ano.Packet {
	return ano.Build(
		ano.NewEther().SetDst("00:de:ad:be:ef:01").SetType(ano.ETH_P_ARP),
		ano.NewARP(ano.ARP_REPLY).
			SrcMACStr("aa:bb:cc:dd:ee:ff").
			SrcIPStr("192.168.1.1").
			DstMACStr("00:de:ad:be:ef:01").
			DstIPStr("192.168.1.100"),
	)
}

func buildIPv6() *ano.Packet {
	return ano.Build(
		ano.NewEther().SetType(ano.ETH_P_IPV6),
		ano.NewIPv6(),
		ano.NewTCP().SetSPort(12345).SetDPort(443),
	)
}

func buildTLSHello() *ano.Packet {
	tlsHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x00, // TLS record: handshake
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientHello
	}
	return ano.Build(
		ano.NewEther(),
		ano.NewIPv4().SetSrc("10.0.0.1").SetDst("93.184.216.34").SetProtocol(ano.IP_PROTO_TCP),
		ano.NewTCP().SetSPort(54321).SetDPort(443).SetFlags(ano.TCP_SYN),
		ano.NewRaw(tlsHello),
	)
}

func buildHTTPGet(host string) *ano.Packet {
	body := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %%s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", host)
	return ano.Build(
		ano.NewEther(),
		ano.NewIPv4().SetSrc("10.0.0.1").SetDst("93.184.216.34").SetProtocol(ano.IP_PROTO_TCP),
		ano.NewTCP().SetSPort(54321).SetDPort(80).SetFlags(ano.TCP_SYN|ano.TCP_ACK),
		ano.NewRaw([]byte(body)),
	)
}

func buildDHCP() *ano.Packet {
	dhcp := make([]byte, 240)
	dhcp[0] = 1
	dhcp[1] = 1
	dhcp[2] = 6
	dhcp[3] = 0
	dhcp[4] = 0x39
	dhcp[5] = 0x03
	copy(dhcp[12:16], []byte{0, 0, 0, 0})
	copy(dhcp[16:20], []byte{0, 0, 0, 0})
	copy(dhcp[20:24], []byte{0, 0, 0, 0})
	copy(dhcp[24:28], []byte{0, 0, 0, 0})
	dhcp[28] = 0xaa
	dhcp[29] = 0xbb
	dhcp[30] = 0xcc
	dhcp[31] = 0xdd
	dhcp[32] = 0xee
	dhcp[33] = 0xff
	copy(dhcp[44:108], []byte{
		0x63, 0x82, 0x53, 0x63,
		53, 1, 1,
		61, 7, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		12, 3, 112, 99, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		55, 4, 1, 3, 6, 15, 255, 0, 0, 0,
	})
	return ano.Build(
		ano.NewEther().SetDstMAC(ano.BroadcastMAC),
		ano.NewIPv4().SetSrc("0.0.0.0").SetDst("255.255.255.255").SetProtocol(ano.IP_PROTO_UDP),
		ano.NewUDP().SetSPort(68).SetDPort(67),
		ano.NewRaw(dhcp),
	)
}

func cmdEval(code string) {
	src := fmt.Sprintf(_EVAL_TPL, code)
	tmp, err := os.CreateTemp("", "anoeval_*.go")
	if err != nil {
		fmt.Println("错误:", err)
		return
	}
	defer os.Remove(tmp.Name())
	tmp.Write([]byte(src))
	tmp.Close()
	out, err := exec.Command("go", "run", tmp.Name()).CombinedOutput()
	if err != nil {
		fmt.Println("Error:", string(out))
		return
	}
	fmt.Print(string(out))
}

func cmdFuzz() {
	pkt := ano.Build(ano.NewEther(), ano.NewIPv4(), ano.NewTCP())
	ano.FuzzPacket(pkt, nil)
	fmt.Println(ano.HexDump(pkt.Bytes()))
}

func cmdImport(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("用法: ano import <pcap文件>")
		fmt.Println()
		fmt.Println("导入 pcap 文件后进入解析模式，支持以下命令:")
		fmt.Println("  cat                    查看数据包列表")
		fmt.Println("  cat <序号>             查看数据包详情")
		fmt.Println("  cat list               查看数据包列表")
		fmt.Println("  cat list <起始>-<终点>  查看数据包范围（如：20-30）")
		fmt.Println("  cat list <序号>,<序号>  查看指定数据包（如：3,7,15）")
		fmt.Println("  cat bpf <表达式>        显示过滤器过滤数据包（如：tcp.port==80）")
		fmt.Println("  cat bpf help           显示过滤器支持的字段和语法")
		fmt.Println("  help                   显示帮助")
		fmt.Println("  !<命令>                执行系统命令（如：!ls -la）")
		fmt.Println("  quit                   退出解析模式")
		return
	}
	pl, err := ano.LoadPacketList(args[0])
	if err != nil {
		fmt.Println("导入失败:", err)
		return
	}
	fmt.Printf("成功导入 %%d 个数据包\n", pl.Len())
	if pl.Len() == 0 {
		return
	}
	fmt.Println("输入 help 查看命令, quit 退出, !命令 执行系统命令")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("ano(pcap)>> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "quit" || line == "exit" {
			break
		}
		if line == "help" {
			fmt.Println()
			fmt.Println("pcap 解析模式命令:")
			fmt.Println("  cat                    查看数据包列表")
			fmt.Println("  cat <序号>             查看数据包详情")
			fmt.Println("  cat list               查看数据包列表")
			fmt.Println("  cat list <起>-<终>      查看范围（如：20-30）")
			fmt.Println("  cat list <序>,<序>      查看指定（如：3,7,15）")
			fmt.Println("  cat bpf <表达式>        显示过滤器过滤数据包")
			fmt.Println("  cat bpf help           查看过滤器字段和语法帮助")
			fmt.Println("  help                   显示帮助")
			fmt.Println("  !<命令>                 执行系统命令（如：!ls, !pwd）")
			fmt.Println("  quit / exit             退出解析模式")
			fmt.Println()
			continue
		}
		if line[0] == '!' {
			cmdStr := strings.TrimSpace(line[1:])
			if cmdStr == "" {
				continue
			}
			parts := strings.Fields(cmdStr)
			cmd := exec.Command(parts[0], parts[1:]...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			continue
		}
		if line == "cat" || line == "cat list" {
			pl.PrintList()
		} else if strings.HasPrefix(line, "cat bpf ") {
			bpfExpr := strings.TrimSpace(line[8:])
			if bpfExpr == "help" {
				printBPFHelp()
			} else {
				filtered, err := pl.FilterByDisplay(bpfExpr)
				if err != nil {
					fmt.Println("过滤器错误:", err)
				} else if filtered.Len() == 0 {
					fmt.Println("没有匹配的数据包")
				} else {
					fmt.Printf("匹配 %%d / %%d 个数据包:\n\n", filtered.Len(), pl.Len())
					filtered.PrintList()
				}
			}
		} else if len(line) > 4 && line[:4] == "cat " {
			idxStr := strings.TrimSpace(line[4:])
			if strings.HasPrefix(idxStr, "list ") {
				listStr := strings.TrimSpace(idxStr[5:])
				if strings.Contains(listStr, ",") {
					parts := strings.Split(listStr, ",")
					var indices []int
					for _, p := range parts {
						indices = append(indices, atoi(strings.TrimSpace(p)))
					}
					pl.ShowIndices(indices)
				} else if strings.Contains(listStr, "-") {
					parts := strings.SplitN(listStr, "-", 2)
					start := atoi(strings.TrimSpace(parts[0]))
					end := atoi(strings.TrimSpace(parts[1]))
					pl.ShowRange(start, end)
				} else {
					fmt.Println("用法: cat list <序号>,<序号> 或 cat list <起始>-<终点>")
				}
			} else {
				idx := atoi(idxStr)
				pl.Show(idx)
			}
		} else {
			fmt.Println("未知命令，输入 help 查看帮助, !命令 执行系统命令")
		}
	}
}

func printBPFHelp() {
	fmt.Println()
	fmt.Println("=== 显示过滤器 (Display Filter) 帮助 ===")
	fmt.Println()
	fmt.Println("语法规则:")
	fmt.Println("  等于: ==    不等于: !=    大于: >    小于: <")
	fmt.Println("  包含: contains    与: &&    或: ||    非: !")
	fmt.Println("  分组: ()    引号: \"值\" 或 '值'")
	fmt.Println()
	fmt.Println("常用组合示例:")
	fmt.Println("  tcp.flags.syn==1 && tcp.flags.ack==0      只抓SYN握手")
	fmt.Println("  tcp.flags.fin==1                          结束挥手")
	fmt.Println("  ip.src==192.168.1.1 && tcp.port==443      指定IP+HTTPS")
	fmt.Println("  udp.port==53                              DNS流量")
	fmt.Println("  dns.qry.type==1                           A记录查询")
	fmt.Println()
	fmt.Println("=== 通用/帧字段 ===")
	fmt.Println("  frame.len              数据包总长")
	fmt.Println("  frame.cap_len          实际抓取长度")
	fmt.Println("  eth.src                源MAC地址")
	fmt.Println("  eth.dst                目的MAC地址")
	fmt.Println("  eth.type               以太网类型")
	fmt.Println()
	fmt.Println("=== IP 字段 ===")
	fmt.Println("  ip.version             IP版本")
	fmt.Println("  ip.src                 源IP")
	fmt.Println("  ip.dst                 目的IP")
	fmt.Println("  ip.ttl                 TTL")
	fmt.Println("  ip.id                  IP标识")
	fmt.Println("  ip.proto               协议号 (6=TCP, 17=UDP, 1=ICMP)")
	fmt.Println("  ip.flags.df            不分片标志 (1=设置)")
	fmt.Println("  ip.flags.mf            更多分片标志 (1=设置)")
	fmt.Println("  ip.frag_offset         分片偏移")
	fmt.Println()
	fmt.Println("=== TCP 字段 ===")
	fmt.Println("  tcp.srcport            源端口")
	fmt.Println("  tcp.dstport            目的端口")
	fmt.Println("  tcp.port               任意端口 (匹配源或目的)")
	fmt.Println("  tcp.seq                序列号")
	fmt.Println("  tcp.ack                确认号")
	fmt.Println("  tcp.hdr_len            TCP头部长度 (字节)")
	fmt.Println("  tcp.window_size        窗口大小")
	fmt.Println("  tcp.checksum           校验和")
	fmt.Println("  tcp.urgent_pointer     紧急指针")
	fmt.Println("  tcp.flags              所有标志位 (十六进制)")
	fmt.Println("  tcp.flags.syn          SYN标志 (1=设置)")
	fmt.Println("  tcp.flags.ack          ACK标志 (1=设置)")
	fmt.Println("  tcp.flags.fin          FIN标志 (1=设置)")
	fmt.Println("  tcp.flags.rst          RST标志 (1=设置)")
	fmt.Println("  tcp.flags.psh          PSH标志 (1=设置)")
	fmt.Println("  tcp.flags.urg          URG标志 (1=设置)")
	fmt.Println("  tcp.flags.cwr          CWR标志 (1=设置)")
	fmt.Println("  tcp.flags.ece          ECE标志 (1=设置)")
	fmt.Println()
	fmt.Println("=== UDP 字段 ===")
	fmt.Println("  udp.srcport            源端口")
	fmt.Println("  udp.dstport            目的端口")
	fmt.Println("  udp.port               任意端口 (匹配源或目的)")
	fmt.Println("  udp.length             UDP总长")
	fmt.Println("  udp.checksum           UDP校验和")
	fmt.Println()
	fmt.Println("=== ICMP 字段 ===")
	fmt.Println("  icmp.type              ICMP类型 (8=请求, 0=应答, 3=不可达)")
	fmt.Println("  icmp.code              子类型码")
	fmt.Println("  icmp.identifier        ping标识符")
	fmt.Println("  icmp.sequence          ping序号")
	fmt.Println()
	fmt.Println("=== ARP 字段 ===")
	fmt.Println("  arp.opcode             操作码 (1=请求, 2=应答)")
	fmt.Println("  arp.src.hw_mac         源MAC")
	fmt.Println("  arp.dst.hw_mac         目的MAC")
	fmt.Println("  arp.src.proto_ipv4     源IP")
	fmt.Println("  arp.dst.proto_ipv4     目的IP")
	fmt.Println()
	fmt.Println("=== DNS 字段 ===")
	fmt.Println("  dns.id                 DNS事务ID")
	fmt.Println("  dns.flags.response     响应标志 (1=响应)")
	fmt.Println("  dns.flags.opcode       操作码")
	fmt.Println("  dns.flags.aa           权威应答 (1=设置)")
	fmt.Println("  dns.flags.tc           截断 (1=设置)")
	fmt.Println("  dns.flags.rd           递归查询 (1=设置)")
	fmt.Println("  dns.flags.ra           递归可用 (1=设置)")
	fmt.Println("  dns.qry.name           查询域名")
	fmt.Println("  dns.qry.type           查询类型 (1=A, 28=AAAA)")
	fmt.Println("  dns.resp.name          响应域名")
	fmt.Println("  dns.resp.type          响应类型")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  cat bpf tcp.port==80")
	fmt.Println("  cat bpf ip.src==192.168.1.1")
	fmt.Println("  cat bpf tcp.flags.syn==1 && tcp.flags.ack==0")
	fmt.Println("  cat bpf udp.port==53")
	fmt.Println("  cat bpf dns.qry.name contains google")
	fmt.Println("  cat bpf arp.opcode==1")
	fmt.Println()
}

func cmdCraft(args []string) {
	if len(args) == 0 || args[0] == "help" {
		fmt.Println("ano craft - 交互式数据包构造器")
		fmt.Println()
		fmt.Println("子命令:")
		fmt.Println("  new                 创建新数据包")
		fmt.Println("  add <层>            添加协议层")
		fmt.Println("  rm <层>             移除协议层")
		fmt.Println("  set <层>.<字段> <值>  设置字段值")
		fmt.Println("  show                显示当前数据包")
		fmt.Println("  hex                 显示 Hex 转储")
		fmt.Println("  send [网卡]         发送数据包")
		fmt.Println("  save <文件>         保存为 pcap")
		fmt.Println("  list                列出已添加的层")
		fmt.Println()
		fmt.Println("可用层: ether, ip, tcp, udp, icmp, arp, raw")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  ano craft new")
		fmt.Println("  ano craft add ether")
		fmt.Println("  ano craft set ether.dst ff:ff:ff:ff:ff:ff")
		fmt.Println("  ano craft set ether.src 00:de:ad:be:ef:01")
		fmt.Println("  ano craft add ip")
		fmt.Println("  ano craft set ip.src 10.0.0.1")
		fmt.Println("  ano craft set ip.dst 192.168.1.1")
		fmt.Println("  ano craft add tcp")
		fmt.Println("  ano craft set tcp.dport 80")
		fmt.Println("  ano craft set tcp.flags syn")
		fmt.Println("  ano craft show")
		fmt.Println("  sudo ano craft send")
		return
	}

	switch args[0] {
	case "new":
		os.WriteFile(_CRAFT_FILE, nil, 0644)
		fmt.Println("新数据包已创建")
	case "add":
		if len(args) < 2 {
			fmt.Println("用法: ano craft add <层>")
			return
		}
		craftAdd(args[1])
	case "rm":
		if len(args) < 2 {
			fmt.Println("用法: ano craft rm <层>")
			return
		}
		craftRemove(args[1])
	case "set":
		if len(args) < 3 {
			fmt.Println("用法: ano craft set <层>.<字段> <值>")
			return
		}
		craftSet(args[1], args[2])
	case "show":
		craftShow()
	case "hex":
		craftHex()
	case "send":
		iface := ""
		if len(args) > 1 {
			iface = args[1]
		}
		craftSend(iface)
	case "save":
		if len(args) < 2 {
			fmt.Println("用法: ano craft save <文件名>")
			return
		}
		craftSave(args[1])
	case "list":
		craftList()
	default:
		fmt.Printf("未知子命令: %%s\n", args[0])
	}
}

func craftLoad() *ano.Packet {
	data, err := os.ReadFile(_CRAFT_FILE)
	if err != nil || len(data) == 0 {
		return ano.Build()
	}
	pkt, err := ano.ParseEther(data)
	if err != nil || pkt == nil {
		return ano.Build()
	}
	return pkt
}

func craftSaveState(pkt *ano.Packet) {
	if pkt != nil {
		os.WriteFile(_CRAFT_FILE, pkt.Bytes(), 0644)
	}
}

func craftAdd(name string) {
	pkt := craftLoad()
	switch name {
	case "ether":
		pkt.Set(ano.NewEther())
	case "ip":
		pkt.Set(ano.NewIPv4())
	case "tcp":
		pkt.Set(ano.NewTCP())
	case "udp":
		pkt.Set(ano.NewUDP())
	case "icmp":
		pkt.Set(ano.NewICMP())
	case "arp":
		pkt.Set(ano.NewARP(ano.ARP_REQUEST))
	case "raw":
		pkt.Add(ano.NewRaw(nil))
	default:
		fmt.Printf("未知层: %%s\n", name)
		return
	}
	craftSaveState(pkt)
	fmt.Printf("已添加层: %%s\n", name)
}

func craftRemove(name string) {
	pkt := craftLoad()
	pkt.Remove("*ano." + strings.ToUpper(name[:1]) + name[1:])
	craftSaveState(pkt)
	fmt.Printf("已移除层: %%s\n", name)
}

func craftSet(field, value string) {
	pkt := craftLoad()
	parts := strings.SplitN(field, ".", 2)
	if len(parts) != 2 {
		fmt.Println("格式: <层>.<字段>")
		return
	}
	layerName := parts[0]
	fieldName := parts[1]

	fullName := "*ano." + strings.ToUpper(layerName[:1]) + layerName[1:]
	l := pkt.Get(fullName)
	if l == nil {
		fmt.Printf("没有层: %%s，先用 add 添加\n", layerName)
		return
	}

	switch l := l.(type) {
	case *ano.Ether:
		switch fieldName {
		case "dst":
			l.Dst = ano.MAC(value)
		case "src":
			l.Src = ano.MAC(value)
		case "type":
			l.Type = parseUint16(value)
		default:
			fmt.Printf("未知字段: ether.%%s (可用: dst, src, type)\n", fieldName)
			return
		}
	case *ano.IPv4:
		switch fieldName {
		case "src":
			l.Src = ano.IP(value)
		case "dst":
			l.Dst = ano.IP(value)
		case "ttl":
			l.TTL = uint8(atoi(value))
		case "proto":
			l.Protocol = uint8(atoi(value))
		default:
			fmt.Printf("未知字段: ip.%%s (可用: src, dst, ttl, proto)\n", fieldName)
			return
		}
	case *ano.TCP:
		switch fieldName {
		case "sport":
			l.SrcPort = uint16(atoi(value))
		case "dport":
			l.DstPort = uint16(atoi(value))
		case "seq":
			l.Seq = uint32(atoi(value))
		case "flags":
			l.Flags = parseTCPFlags(value)
		case "window":
			l.Window = uint16(atoi(value))
		default:
			fmt.Printf("未知字段: tcp.%%s (可用: sport, dport, seq, flags, window)\n", fieldName)
			return
		}
	case *ano.UDP:
		switch fieldName {
		case "sport":
			l.SrcPort = uint16(atoi(value))
		case "dport":
			l.DstPort = uint16(atoi(value))
		default:
			fmt.Printf("未知字段: udp.%%s (可用: sport, dport)\n", fieldName)
			return
		}
	case *ano.ICMP:
		switch fieldName {
		case "type":
			l.Type = uint8(atoi(value))
		case "code":
			l.Code = uint8(atoi(value))
		default:
			fmt.Printf("未知字段: icmp.%%s (可用: type, code)\n", fieldName)
			return
		}
	case *ano.ARP:
		switch fieldName {
		case "smac":
			l.SrcMAC = ano.MAC(value)
		case "dmac":
			l.DstMAC = ano.MAC(value)
		case "sip":
			l.SrcIP = ano.IP(value)
		case "dip":
			l.DstIP = ano.IP(value)
		default:
			fmt.Printf("未知字段: arp.%%s (可用: smac, dmac, sip, dip)\n", fieldName)
			return
		}
	default:
		fmt.Printf("不支持修改: %%T\n", l)
		return
	}

	craftSaveState(pkt)
	fmt.Printf("已设置: %%s = %%s\n", field, value)
}

func craftShow() {
	pkt := craftLoad()
	if len(pkt.Layers) == 0 {
		fmt.Println("数据包为空，先用 add 添加层")
		return
	}
	for _, l := range pkt.Layers {
		switch v := l.(type) {
		case *ano.Ether:
			fmt.Printf("Ether: dst=%%s src=%%s type=0x%%04x\n",
				ano.MACString(v.Dst), ano.MACString(v.Src), v.Type)
		case *ano.IPv4:
			fmt.Printf("IPv4:  src=%%s dst=%%s ttl=%%d proto=%%d\n",
				ano.IPBytes(v.Src), ano.IPBytes(v.Dst), v.TTL, v.Protocol)
		case *ano.TCP:
			flags := ""
			if v.Flags&ano.TCP_SYN != 0 { flags += "SYN " }
			if v.Flags&ano.TCP_ACK != 0 { flags += "ACK " }
			if v.Flags&ano.TCP_FIN != 0 { flags += "FIN " }
			if v.Flags&ano.TCP_RST != 0 { flags += "RST " }
			fmt.Printf("TCP:    %%d->%%d seq=%%d flags=%%s window=%%d\n",
				v.SrcPort, v.DstPort, v.Seq, flags, v.Window)
		case *ano.UDP:
			fmt.Printf("UDP:    %%d->%%d len=%%d\n", v.SrcPort, v.DstPort, v.Length)
		case *ano.ICMP:
			fmt.Printf("ICMP:  type=%%d code=%%d id=%%d\n", v.Type, v.Code, v.ID)
		case *ano.ARP:
			fmt.Printf("ARP:   op=%%d smac=%%s sip=%%s dmac=%%s dip=%%s\n",
				v.Op, ano.MACString(v.SrcMAC), ano.IPBytes(v.SrcIP),
				ano.MACString(v.DstMAC), ano.IPBytes(v.DstIP))
		case *ano.Raw:
			fmt.Printf("Raw:   %%d bytes\n", len(v.Load))
		default:
			fmt.Printf("%%T: %%d bytes\n", l, l.Len())
		}
	}
}

func craftHex() {
	pkt := craftLoad()
	if len(pkt.Layers) == 0 {
		fmt.Println("数据包为空")
		return
	}
	fmt.Println(ano.HexDump(pkt.Bytes()))
	fmt.Printf("Total: %%d bytes\n", len(pkt.Bytes()))
}

func craftSend(iface string) {
	pkt := craftLoad()
	if len(pkt.Layers) == 0 {
		fmt.Println("数据包为空，先用 add 添加层")
		return
	}

	// 自动补全 checksum
	var srcIP, dstIP [4]byte
	ipLayer := pkt.Get("*ano.IPv4")
	if ipLayer != nil {
		ipv4 := ipLayer.(*ano.IPv4)
		srcIP = ipv4.Src
		dstIP = ipv4.Dst
	}
	tcpLayer := pkt.Get("*ano.TCP")
	if tcpLayer != nil {
		tcp := tcpLayer.(*ano.TCP)
		tcp.Checksum = ano.TCPChecksum(tcp, srcIP, dstIP)
	}
	udpLayer := pkt.Get("*ano.UDP")
	if udpLayer != nil {
		udp := udpLayer.(*ano.UDP)
		udp.Checksum = ano.UDPChecksum(udp, srcIP, dstIP)
	}

	// 自动补全源 MAC（从网卡读取）
	etherLayer := pkt.Get("*ano.Ether")
	if etherLayer != nil {
		ether := etherLayer.(*ano.Ether)
		if ether.Src == ano.ZeroMAC || ether.Src == [6]byte{} {
			if iface == "" {
				iface = ano.DetectInterface()
			}
			if iface != "" {
				if mac, err := ano.GetInterfaceMAC(iface); err == nil && len(mac) == 6 {
					copy(ether.Src[:], mac)
					fmt.Printf("自动补全源 MAC: %%s\n", ano.MACString(ether.Src))
				}
			}
		}
	}

	craftSaveState(pkt)
	craftShow()
	fmt.Println()

	var err error
	if iface != "" {
		fmt.Printf("发送到 %%s ...\n", iface)
		err = ano.SendOnIface(iface, pkt)
	} else {
		fmt.Println("发送中 ...")
		err = ano.Send(pkt)
	}
	if err != nil {
		fmt.Println("发送失败:", err)
	} else {
		fmt.Println("发送成功")
	}
}

func craftSave(filename string) {
	pkt := craftLoad()
	if len(pkt.Layers) == 0 {
		fmt.Println("数据包为空")
		return
	}
	err := ano.SavePcap(filename, []*ano.Packet{pkt})
	if err != nil {
		fmt.Println("保存失败:", err)
	} else {
		fmt.Printf("已保存: %%s\n", filename)
	}
}

func craftList() {
	pkt := craftLoad()
	if len(pkt.Layers) == 0 {
		fmt.Println("数据包为空")
		return
	}
	fmt.Println("当前层:")
	for i, l := range pkt.Layers {
		fmt.Printf("  [%%d] %%T\n", i+1, l)
	}
}

func parseTCPFlags(s string) uint8 {
	f := uint8(0)
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "syn", "SYN":
			f |= ano.TCP_SYN
		case "ack", "ACK":
			f |= ano.TCP_ACK
		case "fin", "FIN":
			f |= ano.TCP_FIN
		case "rst", "RST":
			f |= ano.TCP_RST
		case "psh", "PSH":
			f |= ano.TCP_PSH
		case "urg", "URG":
			f |= ano.TCP_URG
		}
	}
	return f
}

func parseUint16(s string) uint16 {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return uint16(n)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}
`, anoPkg, anoPkg)
}

func findAnoPackage() (string, error) {
	modRoot := findModuleRoot()
	if modRoot == "" {
		return "", fmt.Errorf("cannot find go.mod")
	}
	modBytes, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	moduleLine := strings.TrimSpace(strings.Split(string(modBytes), "\n")[0])
	moduleName := strings.TrimPrefix(moduleLine, "module ")
	return moduleName + "/ano", nil
}

func findModuleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	dir, _ = filepath.Abs(dir)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
