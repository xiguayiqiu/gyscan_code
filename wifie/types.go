package wifie

type FrameType uint8

func (t FrameType) String() string {
	switch t {
	case IEEE80211_FC0_TYPE_MGT:
		return "Management"
	case IEEE80211_FC0_TYPE_CTL:
		return "Control"
	case IEEE80211_FC0_TYPE_DATA:
		return "Data"
	default:
		return "Unknown"
	}
}

type FrameSubtype uint8

func (s FrameSubtype) String() string {
	switch s {
	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
		return "Association Request"
	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
		return "Association Response"
	case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
		return "Reassociation Request"
	case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
		return "Reassociation Response"
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		return "Probe Request"
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
		return "Probe Response"
	case IEEE80211_FC0_SUBTYPE_BEACON:
		return "Beacon"
	case IEEE80211_FC0_SUBTYPE_ATIM:
		return "ATIM"
	case IEEE80211_FC0_SUBTYPE_DISASSOC:
		return "Disassociation"
	case IEEE80211_FC0_SUBTYPE_AUTH:
		return "Authentication"
	case IEEE80211_FC0_SUBTYPE_DEAUTH:
		return "Deauthentication"
	case IEEE80211_FC0_SUBTYPE_ACTION:
		return "Action"
	case IEEE80211_FC0_SUBTYPE_DATA:
		return "Data"
	case IEEE80211_FC0_SUBTYPE_NODATA:
		return "Null Data"
	case IEEE80211_FC0_SUBTYPE_QOS_DATA:
		return "QoS Data"
	case IEEE80211_FC0_SUBTYPE_QOS_NULL:
		return "QoS Null"
	default:
		if s&IEEE80211_FC0_TYPE_MASK == IEEE80211_FC0_TYPE_CTL {
			switch s {
			case IEEE80211_FC0_SUBTYPE_RTS:
				return "RTS"
			case IEEE80211_FC0_SUBTYPE_CTS:
				return "CTS"
			case IEEE80211_FC0_SUBTYPE_ACK:
				return "ACK"
			case IEEE80211_FC0_SUBTYPE_PS_POLL:
				return "PS-Poll"
			case IEEE80211_FC0_SUBTYPE_BAR:
				return "BlockAckReq"
			case IEEE80211_FC0_SUBTYPE_BA:
				return "BlockAck"
			case IEEE80211_FC0_SUBTYPE_CF_END:
				return "CF-End"
			case IEEE80211_FC0_SUBTYPE_CTL_EXT:
				return "Control Extension"
			}
		}
		return "Unknown"
	}
}

type RadiotapInfo struct {
	Version    uint8
	Pad        uint8
	Length     uint16
	Present    uint32
	TSFT       uint64
	Flags      uint8
	Rate       uint8
	Channel    int
	ChannelFlags uint16
	Freq       int
	AntSignal  int8
	AntNoise   int8
	Antenna    uint8
	DataRate   float64
	HasFCS     bool
	BadFCS     bool
	WEP        bool
	Frag       bool
}

type Frame80211 struct {
	Raw       []byte
	FC0       uint8
	FC1       uint8
	Type      FrameType
	Subtype   FrameSubtype
	Duration  uint16
	Addr1     string
	Addr2     string
	Addr3     string
	Addr4     string
	Seq       uint16
	Fragment  uint8
	QoSCtl    uint16
	ToDS      bool
	FromDS    bool
	Protected bool
	Retry     bool
	PwrMgmt   bool
	MoreData  bool
	MoreFrag  bool
	Order     bool
	Body      []byte
	FCS       uint32
	Radiotap  *RadiotapInfo
}

type WiFiNetwork struct {
	BSSID       string
	ESSID       string
	Channel     int
	Freq        int
	Signal      int
	Noise       int
	Privacy     bool
	Cipher      string
	Auth        string
	Standard    string
	Rates       []float64
	MaxRate     float64
	BeaconCount int
	DataCount   int
	FirstSeen   int64
	LastSeen    int64
	WPS         bool
	Country     string
	Vendor      string
	HTCap       bool
	VHTCap      bool
	InfoElements map[int][]byte
}

type WiFiStation struct {
	MAC        string
	BSSID      string
	Signal     int
	Noise      int
	Rate       float64
	FirstSeen  int64
	LastSeen   int64
	Packets    int
	ProbedSSIDs []string
}

type WiFiInterface struct {
	Name       string
	Index      int
	MAC        string
	Type       string
	Mode       string
	Channel    int
	Freq       int
	TXPower    int
	IsUp       bool
	IsMonitor  bool
	Driver     string
	Chipset    string
}

type ScanResult struct {
	Networks  []*WiFiNetwork
	Stations  []*WiFiStation
	Duration  float64
	Channel   int
}

type ChannelHopConfig struct {
	Channels []int
	HopDelay int
}

type DeauthResult struct {
	TargetMAC  string
	BSSID      string
	Count      int
	SuccessCount int
	Duration   float64
}

type SecurityInfo struct {
	Standard   string
	Auth       string
	Cipher     string
	IsWEP      bool
	IsWPA      bool
	IsWPA2     bool
	IsWPA3     bool
	IsOpen     bool
	IsTKIP     bool
	IsCCMP     bool
	HasPMKID   bool
	PMKID      []byte
	EAPOLCount int
}

type WEPKeyInfo struct {
	KeyIndex uint8
	KeyLen   int
	IVCount  int
	WeakIVs  int
}

type WPAPair struct {
	BSSID    string
	ESSID    string
	PMKID    []byte
	Handshake []byte
	Mic       []byte
}

type CapabilityInfo struct {
	ESS              bool
	IBSS             bool
	Privacy          bool
	ShortPreamble    bool
	ShortSlotTime    bool
	RSN              bool
	DSSSOFDM         bool
	SpectrumMgmt     bool
}

type EAPOLFrame struct {
	Version     uint8
	Type        uint8
	Length      uint16
	KeyDescType uint8
	KeyInfo     uint16
	KeyLength   uint16
	ReplayCtr   uint64
	KeyNonce    [32]byte
	KeyIV       [16]byte
	KeyRSC      [8]byte
	KeyID       [8]byte
	KeyMIC      [16]byte
	KeyDataLen  uint16
	KeyData     []byte
	Raw         []byte
}

const (
	WPA_STATE_ANONCE   = 1
	WPA_STATE_SNONCE   = 2
	WPA_STATE_EAPOLMIC = 4
	WPA_STATE_COMPLETE = 7
)

type WPAHandshake struct {
	BSSID       string
	STAMAC      string
	ANonce      [32]byte
	SNonce      [32]byte
	EAPOLData   [256]byte
	EAPOLSize   int
	MIC         [20]byte
	Frame1      *EAPOLFrame
	Frame2      *EAPOLFrame
	Frame3      *EAPOLFrame
	Frame4      *EAPOLFrame
	Complete    bool
	State       int
	Version     uint8
	PMKID       []byte
}

type WEPPacket struct {
	IV      [3]byte
	KeyIdx  uint8
	Data    []byte
	ICV     [4]byte
	Raw     []byte
}

type RC4State struct {
	S    [256]byte
	I, J byte
}

type PTWState struct {
	Packets []WEPPacket
	KeySize int
}

type PcapRecord struct {
	Seconds      int64
	Microseconds int64
	CapturedLen  int32
	OriginalLen  int32
}

type PcapHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}