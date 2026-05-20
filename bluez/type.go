package bluez

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	HCI_DEV_UP     = 1
	HCI_DEV_DOWN   = 0
	HCI_MAX_DEVICES = 16

	OGF_LINK_CONTROL  = 0x01
	OGF_LINK_POLICY   = 0x02
	OGF_HOST_CTL      = 0x03
	OGF_INFO_PARAM    = 0x04
	OGF_STATUS_PARAM  = 0x05
	OGF_LE_CTL        = 0x08
	OGF_VENDOR_CMD    = 0x3F

	OCF_INQUIRY           = 0x0001
	OCF_INQUIRY_CANCEL    = 0x0002
	OCF_CREATE_CONN       = 0x0005
	OCF_DISCONNECT        = 0x0006
	OCF_ACCEPT_CONN_REQ   = 0x0009
	OCF_REJECT_CONN_REQ   = 0x000A
	OCF_LINK_KEY_REQ_REPLY   = 0x000B
	OCF_LINK_KEY_REQ_NEG_REPLY = 0x000C
	OCF_PIN_CODE_REQ_REPLY    = 0x000D
	OCF_PIN_CODE_REQ_NEG_REPLY = 0x000E
	OCF_CHANGE_CONN_PKT_TYPE  = 0x000F
	OCF_AUTH_REQUESTED      = 0x0011
	OCF_SET_CONN_ENCRYPT    = 0x0013
	OCF_REMOTE_NAME_REQ     = 0x0019

	OCF_SET_EVENT_MASK   = 0x0001
	OCF_RESET            = 0x0003
	OCF_WRITE_LOCAL_NAME = 0x0013
	OCF_READ_LOCAL_NAME  = 0x0014

	OCF_READ_RSSI          = 0x0005
	OCF_READ_TX_POWER      = 0x0007
	OCF_LE_SET_SCAN_PARAM  = 0x000B
	OCF_LE_SET_SCAN_ENABLE = 0x000C
	OCF_LE_CREATE_CONN     = 0x000D

	BDADDR_BREDR = 0
	BDADDR_LE_PUBLIC = 1
	BDADDR_LE_RANDOM = 2

	ACL_LINK = 1
	SCO_LINK = 0
	LE_LINK  = 2

	HCI_EVENT_PKT = 0x04
	ACL_DATA_PKT  = 0x02

	EVT_INQUIRY_COMPLETE    = 0x01
	EVT_INQUIRY_RESULT      = 0x02
	EVT_CONN_COMPLETE       = 0x03
	EVT_CONN_REQUEST        = 0x04
	EVT_DISCONN_COMPLETE    = 0x05
	EVT_AUTH_COMPLETE       = 0x06
	EVT_REMOTE_NAME_REQ_COMPLETE = 0x07
	EVT_ENCRYPT_CHANGE      = 0x08
	EVT_LINK_KEY_REQ        = 0x17
	EVT_LINK_KEY_NOTIFY     = 0x18
	EVT_PIN_CODE_REQ        = 0x16
	EVT_IO_CAPA_REQ         = 0x31
	EVT_IO_CAPA_RESP        = 0x32
	EVT_USER_CONFIRM_REQ    = 0x33
	EVT_USER_PASSKEY_REQ    = 0x34
	EVT_LE_META_EVENT       = 0x3E
	EVT_SIMPLE_PAIRING_COMPLETE = 0x36
	EVT_NUM_COMPLETED_PKTS  = 0x13

	HCI_COMMAND_PKT = 0x01
	HCI_ACLDATA_PKT = 0x02

	IO_CAP_DISPLAY_ONLY     = 0x00
	IO_CAP_DISPLAY_YESNO    = 0x01
	IO_CAP_KEYBOARD_ONLY    = 0x02
	IO_CAP_NO_INPUT_NO_OUTPUT = 0x03

	AUTH_REQ_MITM_PROTECTION = 0x01
	AUTH_REQ_NO_BONDING      = 0x00

	ENCRYPT_SIZE_MIN = 7
	ENCRYPT_SIZE_MAX = 16

	BTPROTO_HCI = 1
	BTPROTO_L2CAP = 0
	BTPROTO_RFCOMM = 3

	SOL_HCI    = 0
	HCI_FILTER = 2
	HCI_DATA_DIR = 1

	AF_BLUETOOTH = 31
	SOL_BLUETOOTH = 274

	L2CAP_PSM_SDP = 0x0001
	L2CAP_PSM_RFCOMM = 0x0003

	HCI_CHANNEL_RAW = 0
	HCI_CHANNEL_CONTROL = 1
	HCI_CHANNEL_MONITOR = 2

	PAIRING_PIN_CODE    = 0
	PAIRING_SECURE_SIMPLE = 1

	SCAN_DISABLED = 0x00
	SCAN_INQUIRY  = 0x01
	SCAN_PAGE     = 0x02

	LMP_NO_BREDR     = 0x00
	LMP_3SLOT        = 0x01
	LMP_5SLOT        = 0x02
	LMP_ENCRYPTION   = 0x04
	LMP_SLOT_OFFSET  = 0x08
	LMP_TIMING_ACC   = 0x10
	LMP_SWITCH       = 0x20
	LMP_HOLD         = 0x40
	LMP_SNIFF        = 0x80
	LMP_RSSI_INQ     = 0x0001
	LMP_EV4          = 0x0002
	LMP_EV5          = 0x0004
	LMP_AFH_CAP_SLV  = 0x0008
	LMP_AFH_CLS_SLV  = 0x0010
	LMP_NO_BREDR_1   = 0x0020
	LMP_LE           = 0x0040
	LMP_3SLOT_EV5    = 0x0080
	LMP_5SLOT_EV5    = 0x0100

	CLASS_SERVICE_LIMITED  = 0x000020
	CLASS_SERVICE_POSITIONING = 0x010000
	CLASS_SERVICE_NETWORKING  = 0x020000
	CLASS_SERVICE_RENDERING   = 0x040000
	CLASS_SERVICE_CAPTURING   = 0x080000
	CLASS_SERVICE_OBJECT_TRANSFER = 0x100000
	CLASS_SERVICE_AUDIO       = 0x200000
	CLASS_SERVICE_TELEPHONY   = 0x400000
	CLASS_SERVICE_INFORMATION = 0x800000

	CLASS_MAJOR_MISC          = 0x0000
	CLASS_MAJOR_COMPUTER      = 0x0100
	CLASS_MAJOR_PHONE         = 0x0200
	CLASS_MAJOR_LAN_ACCESS    = 0x0300
	CLASS_MAJOR_AUDIO_VIDEO   = 0x0400
	CLASS_MAJOR_PERIPHERAL    = 0x0500
	CLASS_MAJOR_IMAGING       = 0x0600
	CLASS_MAJOR_WEARABLE      = 0x0700
	CLASS_MAJOR_TOY           = 0x0800
	CLASS_MAJOR_HEALTH        = 0x0900
	CLASS_MAJOR_UNCATEGORIZED = 0x1F00
)

type BDAddr [6]byte

func (a BDAddr) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		a[5], a[4], a[3], a[2], a[1], a[0])
}

func ParseBDAddr(s string) (BDAddr, error) {
	var addr BDAddr
	_, err := fmt.Sscanf(s, "%02X:%02X:%02X:%02X:%02X:%02X",
		&addr[5], &addr[4], &addr[3], &addr[2], &addr[1], &addr[0])
	return addr, err
}

type DeviceInfo struct {
	Address  BDAddr
	Name     string
	Class    [3]byte
	RSSI     int8
	LastSeen time.Time
	Flags    uint8
	Services []UUID
}

type UUID [16]byte

func (u UUID) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		binary.BigEndian.Uint32(u[0:4]),
		binary.BigEndian.Uint16(u[4:6]),
		binary.BigEndian.Uint16(u[6:8]),
		binary.BigEndian.Uint16(u[8:10]),
		u[10:16])
}

type HCICommand struct {
	OpCode uint16
	Params []byte
}

type HCIEvent struct {
	EventCode uint8
	Params    []byte
}

type TrackRecord struct {
	Address  BDAddr
	RSSI     int8
	Time     time.Time
	Location string
}

type AttackConfig struct {
	Target      BDAddr
	Interface   string
	Timeout     time.Duration
	Retries     int
	Verbose     bool
	EncryptSize uint8
	IOCap       uint8
	AuthReq     uint8
	PinCode     string
	KeySize     uint8
}

type KNOBResult struct {
	Success        bool
	NegotiatedSize uint8
	OriginalSize   uint8
	AttackTime     time.Duration
	Details        string
}

type BIASResult struct {
	Success      bool
	SpoofedAddr  BDAddr
	TargetAddr   BDAddr
	AuthBypassed bool
	Details      string
}

type MITMResult struct {
	Success        bool
	CapturedData   []byte
	ModifiedData   []byte
	SessionKey     []byte
	Details        string
}

type ReplayResult struct {
	Success      bool
	ReplayedData []byte
	Response     []byte
	Details      string
}

type BlueBorneResult struct {
	Vulnerable   bool
	ExploitType  string
	PayloadSent  []byte
	ResponseData []byte
	Details      string
}

type BluesnarfingResult struct {
	Success     bool
	TargetAddr  BDAddr
	Extracted   map[string][]byte
	OBEXChannel int
	Details     string
}

type BluebuggingResult struct {
	Success       bool
	TargetAddr    BDAddr
	CommandsSent  []string
	Responses     []string
	ControlGained bool
	Details       string
}

type FirmwareResult struct {
	Success      bool
	TargetAddr   BDAddr
	FirmwareVer  string
	Patchable    bool
	Details      string
}

type BluejackingConfig struct {
	Targets  []BDAddr
	Message  string
	VCard    string
	Channel  int
	Verbose  bool
}

type BluejackingResult struct {
	Success      bool
	DevicesSent  int
	MessagesSent []string
	Details      string
}

type WPScanResult struct {
	Address     BDAddr
	Name        string
	PinTried    string
	Success     bool
	AuthSuccess bool
	EncryptSize uint8
	Details     string
}

type DiscoverableDevice struct {
	Address BDAddr
	Name    string
	Class   uint32
	RSSI    int8
	Flags   uint8
	Company uint16
}

type PacketRecord struct {
	Time      time.Time
	Direction string
	Type      uint8
	Data      []byte
	Length    int
}

type SnifferConfig struct {
	Interface string
	Timeout   time.Duration
	Filter    string
	MaxPackets int
	Verbose   bool
}

func DefaultAttackConfig() *AttackConfig {
	return &AttackConfig{
		Timeout:     10 * time.Second,
		Retries:     3,
		Verbose:     false,
		EncryptSize: ENCRYPT_SIZE_MIN,
		IOCap:       IO_CAP_NO_INPUT_NO_OUTPUT,
		AuthReq:     AUTH_REQ_NO_BONDING,
		PinCode:     "0000",
		KeySize:     1,
	}
}

func DefaultSnifferConfig() *SnifferConfig {
	return &SnifferConfig{
		Timeout:    30 * time.Second,
		MaxPackets: 1000,
		Verbose:    false,
	}
}

func DefaultBluejackingConfig() *BluejackingConfig {
	return &BluejackingConfig{
		Channel: 10,
		Verbose: false,
	}
}

type ScanResult struct {
	Devices      []DeviceInfo
	Discoverable []DiscoverableDevice
	BLEDevices   []BLEDevice
	Duration     time.Duration
}

type AuditReport struct {
	Time          time.Time
	TotalDevices  int
	TotalFindings int
	RiskLevel     string
	Findings      []AuditFinding
}

type AuditFinding struct {
	Severity string
	Category string
	Title    string
	Device   string
	Detail   string
}

func ClassToString(class [3]byte) string {
	c := uint32(class[0]) | uint32(class[1])<<8 | uint32(class[2])<<16

	service := ""
	switch {
	case c&CLASS_SERVICE_LIMITED != 0:
		service = "Limited Discoverable"
	case c&CLASS_SERVICE_POSITIONING != 0:
		service = "Positioning"
	case c&CLASS_SERVICE_NETWORKING != 0:
		service = "Networking"
	case c&CLASS_SERVICE_RENDERING != 0:
		service = "Rendering"
	case c&CLASS_SERVICE_CAPTURING != 0:
		service = "Capturing"
	case c&CLASS_SERVICE_OBJECT_TRANSFER != 0:
		service = "Object Transfer"
	case c&CLASS_SERVICE_AUDIO != 0:
		service = "Audio"
	case c&CLASS_SERVICE_TELEPHONY != 0:
		service = "Telephony"
	case c&CLASS_SERVICE_INFORMATION != 0:
		service = "Information"
	}

	major := c & 0x1F00
	majorStr := ""
	switch major {
	case CLASS_MAJOR_MISC:
		majorStr = "Miscellaneous"
	case CLASS_MAJOR_COMPUTER:
		majorStr = "Computer"
	case CLASS_MAJOR_PHONE:
		majorStr = "Phone"
	case CLASS_MAJOR_LAN_ACCESS:
		majorStr = "LAN/Network Access"
	case CLASS_MAJOR_AUDIO_VIDEO:
		majorStr = "Audio/Video"
	case CLASS_MAJOR_PERIPHERAL:
		majorStr = "Peripheral"
	case CLASS_MAJOR_IMAGING:
		majorStr = "Imaging"
	case CLASS_MAJOR_WEARABLE:
		majorStr = "Wearable"
	case CLASS_MAJOR_TOY:
		majorStr = "Toy"
	case CLASS_MAJOR_HEALTH:
		majorStr = "Health"
	case CLASS_MAJOR_UNCATEGORIZED:
		majorStr = "Uncategorized"
	}

	return fmt.Sprintf("Service: %s, Major: %s (0x%06X)", service, majorStr, c)
}

type HCIInquiryResult struct {
	BDAddr    BDAddr
	PageRep   uint8
	Reserved  uint8
	Class     [3]byte
	ClockOff  uint16
}

type HCIInquiryComplete struct {
	Status    uint8
	NumResps  uint8
}

type HCILEAdvertisingReport struct {
	EvtType   uint8
	AddrType  uint8
	BDAddr    BDAddr
	DataLen   uint8
	Data      []byte
	RSSI      int8
}

type HCISocket struct {
	fd   int
	dev  int
}

func NewHCISocket() (*HCISocket, error) {
	fd, err := hciOpenDevice()
	if err != nil {
		return nil, err
	}
	return &HCISocket{fd: fd}, nil
}

func (s *HCISocket) Close() error {
	return closeHCI(s.fd)
}

type HCIFilter struct {
	TypeMask     uint32
	EventMask    [2]uint32
	Opcode       uint16
}

func NewHCIFilter() HCIFilter {
	return HCIFilter{
		TypeMask: HCI_EVENT_PKT,
	}
}

func (f *HCIFilter) SetEvent(evt uint8) {
	idx := evt / 32
	bit := evt % 32
	if idx < 2 {
		f.EventMask[idx] |= 1 << bit
	}
}

func (f *HCIFilter) ClearEvent(evt uint8) {
	idx := evt / 32
	bit := evt % 32
	if idx < 2 {
		f.EventMask[idx] &^= 1 << bit
	}
}

func (f *HCIFilter) SetPacketType(pt uint8) {
	switch pt {
	case HCI_COMMAND_PKT:
		f.TypeMask |= 1
	case HCI_EVENT_PKT:
		f.TypeMask |= 2
	case HCI_ACLDATA_PKT:
		f.TypeMask |= 4
	}
}

type HCIConnInfo struct {
	Handle    uint16
	LinkType  uint8
	BDAddr    BDAddr
	Encrypted bool
	AuthType  uint8
}

func hciCommand(opcode uint16, params []byte) []byte {
	plen := len(params)
	buf := make([]byte, 3+plen)
	buf[0] = HCI_COMMAND_PKT
	binary.LittleEndian.PutUint16(buf[1:3], opcode)
	copy(buf[3:], params)
	return buf
}

func hciOpcode(ogf, ocf uint16) uint16 {
	return (ocf & 0x03FF) | (ogf << 10)
}

func netDialBluetooth() (net.Conn, error) {
	return net.Dial("bluetooth", fmt.Sprintf("%d", HCI_CHANNEL_RAW))
}

func hciOpenDevice() (int, error) {
	return hciOpenDev(0)
}

func hciOpenDev(devID int) (int, error) {
	return openHCI(devID)
}

func closeHCI(fd int) error {
	return closeSocket(fd)
}