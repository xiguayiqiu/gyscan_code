package ano

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var reMAC = regexp.MustCompile(`^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$`)

func ValidMAC(mac string) bool {
	return reMAC.MatchString(mac)
}

func MAC2Bytes(mac string) ([]byte, error) {
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	return hex.DecodeString(mac)
}

func Bytes2MAC(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func ValidIP(addr string) bool {
	return net.ParseIP(addr) != nil
}

func ValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func IP2Int(ip string) uint32 {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func Int2IP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func CIDRMask(ones int) uint32 {
	if ones >= 32 {
		return 0xFFFFFFFF
	}
	return ^((1 << (32 - ones)) - 1)
}

func IsPrivateIP(ip string) bool {
	for _, cidr := range PrivateCIDRs {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func IsMulticastMAC(mac string) bool {
	b, err := MAC2Bytes(mac)
	if err != nil || len(b) < 1 {
		return false
	}
	return b[0]&0x01 == 0x01
}

func IsBroadcastMAC(mac string) bool {
	return mac == "ff:ff:ff:ff:ff:ff" || mac == "FF:FF:FF:FF:FF:FF"
}

func HexDump(data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(&b, "%04x  ", i)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(&b, "%02x ", data[i+j])
			} else {
				b.WriteString("   ")
			}
			if j == 7 {
				b.WriteString(" ")
			}
		}
		b.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			c := data[i+j]
			if c >= 32 && c <= 126 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

func HexDiff(a, b []byte) string {
	var result strings.Builder
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	result.WriteString(fmt.Sprintf("Hex diff (%d vs %d bytes):\n", len(a), len(b)))
	for i := 0; i < maxLen; i += 16 {
		result.WriteString(fmt.Sprintf("%04x ", i))
		for j := 0; j < 16; j++ {
			idx := i + j
			if idx < len(a) && idx < len(b) && a[idx] != b[idx] {
				result.WriteString(fmt.Sprintf("\033[31m%02x\033[0m ", a[idx]))
			} else if idx < len(a) {
				result.WriteString(fmt.Sprintf("%02x ", a[idx]))
			} else {
				result.WriteString("   ")
			}
			if j == 7 {
				result.WriteString(" ")
			}
		}
		result.WriteString(" ")
		for j := 0; j < 16; j++ {
			idx := i + j
			if idx < len(a) && idx < len(b) && a[idx] != b[idx] {
				result.WriteString(fmt.Sprintf("\033[31m%c\033[0m", printableChar(a[idx])))
			} else if idx < len(a) {
				result.WriteByte(printableChar(a[idx]))
			}
		}
		result.WriteString("\n")
	}
	return result.String()
}

func printableChar(b byte) byte {
	if b >= 32 && b <= 126 {
		return b
	}
	return '.'
}

func XORBytes(a, b []byte) []byte {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	result := make([]byte, minLen)
	for i := 0; i < minLen; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func SafeString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
