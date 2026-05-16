package ano

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
)

type RandRange struct {
	min, max int64
}

func RandInt64(min, max int64) int64 {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(max-min+1))
	return min + n.Int64()
}

func RandInt(min, max int) int {
	return int(RandInt64(int64(min), int64(max)))
}

func RandPort() int {
	return RandInt(1024, 65535)
}

func RandID() int {
	return RandInt(1, 65535)
}

func RandSeq() uint32 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return uint32(n.Int64())
}

func RandIP(cidr string) string {
	if cidr == "" || cidr == "*" {
		return fmt.Sprintf("%d.%d.%d.%d",
			RandInt(1, 254), RandInt(0, 255),
			RandInt(0, 255), RandInt(1, 254))
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	ones, bits := ipnet.Mask.Size()
	hosts := 1 << (bits - ones)
	if hosts > 1<<20 {
		hosts = 1 << 20
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(hosts)))
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	for i := range ip {
		ip[i] |= byte(n.Int64() >> (8 * (len(ip) - 1 - i)))
	}
	return ip.String()
}

func RandIP6(subnet string) string {
	if subnet == "" || subnet == "*" {
		parts := make([]string, 8)
		for i := range parts {
			parts[i] = fmt.Sprintf("%x", RandInt(0, 65535))
		}
		return strings.Join(parts, ":")
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		parts := make([]string, 8)
		for i := range parts {
			parts[i] = fmt.Sprintf("%x", RandInt(0, 65535))
		}
		return strings.Join(parts, ":")
	}
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	hostBits := 128 - ones(ipnet.Mask)
	for i := 0; i < hostBits/8; i++ {
		ip[len(ip)-1-i] = byte(RandInt(0, 255))
	}
	return ip.String()
}

func ones(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

func RandMAC(pattern string) string {
	if pattern == "" || pattern == "*:*:*:*:*:*" {
		octets := make([]string, 6)
		for i := range octets {
			octets[i] = fmt.Sprintf("%02x", RandInt(0, 255))
		}
		return strings.Join(octets, ":")
	}
	parts := strings.Split(pattern, ":")
	if len(parts) != 6 {
		octets := make([]string, 6)
		for i := range octets {
			octets[i] = fmt.Sprintf("%02x", RandInt(0, 255))
		}
		return strings.Join(octets, ":")
	}
	for i, p := range parts {
		if p == "*" {
			parts[i] = fmt.Sprintf("%02x", RandInt(0, 255))
		} else if strings.Contains(p, "-") {
			var lo, hi int
			fmt.Sscanf(p, "%x-%x", &lo, &hi)
			parts[i] = fmt.Sprintf("%02x", RandInt(lo, hi))
		}
	}
	return strings.Join(parts, ":")
}

func RandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func RandString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[idx.Int64()]
	}
	return string(b)
}

func RandChoice[T any](items ...T) T {
	return items[RandInt(0, len(items)-1)]
}

func RandTTL() int {
	return RandChoice(64, 128, 255)
}

func RandWindowSize() int {
	return RandChoice(14600, 29200, 5840, 65535, 8192, 65535)
}

func RandMSS() int {
	return RandChoice(1460, 1440, 1360, 896, 536)
}

func RandWeighted[T any](items []T, weights []int) T {
	if len(items) == 0 || len(items) != len(weights) {
		var zero T
		return zero
	}
	total := 0
	for _, w := range weights {
		total += w
	}
	r := RandInt(1, total)
	running := 0
	for i, w := range weights {
		running += w
		if r <= running {
			return items[i]
		}
	}
	return items[0]
}

func RandSubnet(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	ones, bits := ipnet.Mask.Size()
	newOnes := RandInt(ones, bits-1)
	mask := net.CIDRMask(newOnes, bits)
	newNet := ipnet.IP.Mask(mask)
	return fmt.Sprintf("%s/%d", newNet.String(), newOnes)
}

func RandIPVersion() string {
	return RandChoice("ipv4", "ipv4", "ipv4", "ipv6")
}

func RandTimestamp() int64 {
	return RandInt64(1700000000, 1899999999)
}

func RandTimezone() string {
	return RandChoice(
		"Asia/Shanghai", "Asia/Tokyo", "Asia/Seoul",
		"America/New_York", "America/Los_Angeles",
		"Europe/London", "Europe/Berlin", "Europe/Paris",
		"Australia/Sydney", "Pacific/Auckland",
	)
}

func RandScreenSize() (int, int) {
	sizes := [][2]int{
		{1920, 1080}, {1366, 768}, {1536, 864},
		{1440, 900}, {2560, 1440}, {1280, 720},
		{390, 844}, {414, 896}, {430, 932},
	}
	return RandChoice(sizes...)[0], RandChoice(sizes...)[1]
}

func RandColorDepth() int {
	return RandChoice(24, 30, 48)
}

func RandDeviceMemory() int {
	return RandChoice(4, 8, 16, 32, 64)
}

func RandPixelRatio() float64 {
	return float64(RandChoice(1, 2, 3)) / float64(RandChoice(1, 1, 2, 2))
}
