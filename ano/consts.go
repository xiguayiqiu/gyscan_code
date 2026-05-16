package ano

const (
	ETH_P_IP   = 0x0800
	ETH_P_ARP  = 0x0806
	ETH_P_IPV6 = 0x86DD
)

const (
	IP_PROTO_ICMP   = 1
	IP_PROTO_TCP    = 6
	IP_PROTO_UDP    = 17
	IP_PROTO_ICMPV6 = 58
)

var PrivateCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

var ServicePorts = map[uint16]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	3306: "MySQL",
	3389: "RDP",
	8080: "HTTP-Proxy",
}
