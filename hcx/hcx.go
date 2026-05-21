package hcx

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	HCX_TYPE_PMKID       = 1
	HCX_TYPE_EAPOL       = 2
	HCX_TYPE_PMKID_FTPSK = 3
	HCX_TYPE_EAPOL_FTPSK = 4
)

const (
	ESSID_LEN_MAX       = 32
	EAPOL_AUTHLEN_MAX   = 512
	EAPOL_AUTHLEN_OLD   = 255
	MESSAGELIST_MAX     = 64
	HANDSHAKELIST_MAX   = 100000
	PMKIDLIST_MAX       = 100000
	MACLIST_MAX         = 100000
)

const (
	WPA_KEY_INFO_TYPE_MASK   = 0x0007
	WPA_KEY_INFO_TYPE_HMAC_MD5_RC4  = 0x0001
	WPA_KEY_INFO_TYPE_HMAC_SHA1_AES = 0x0002
	WPA_KEY_INFO_INSTALL     = 0x0040
	WPA_KEY_INFO_KEY_ACK     = 0x0080
	WPA_KEY_INFO_KEY_MIC     = 0x0100
	WPA_KEY_INFO_SECURE      = 0x0200
	WPA_KEY_INFO_ENCR_KEY_DATA = 0x1000
)

const (
	MESSAGE_PAIR_M12E2 = 0
	MESSAGE_PAIR_M14E4 = 1
	MESSAGE_PAIR_M32E2 = 2
	MESSAGE_PAIR_M32E3 = 3
	MESSAGE_PAIR_M34E3 = 4
	MESSAGE_PAIR_M34E4 = 5
)

const (
	HS_M1    = 0x01
	HS_M2    = 0x02
	HS_M3    = 0x04
	HS_M4    = 0x08
	HS_PMKID = 0x10
)

const (
	ST_M12E2     = 0x00
	ST_M14E4     = 0x01
	ST_M32E2     = 0x02
	ST_M32E3     = 0x03
	ST_M34E3     = 0x04
	ST_M34E4     = 0x05
	ST_APLESS    = 0x10
	ST_LE        = 0x20
	ST_BE        = 0x40
	ST_ENDIANESS = 0x60
	ST_NC        = 0x80
)

const (
	PMKID_AP             = 0x01
	PMKID_APPSK256       = 0x02
	PMKID_CLIENT         = 0x04
	PMKID_AP_FTPSK       = 0x10
	PMKID_CLIENT_FTPSK   = 0x20
)

type HandshakeEntry struct {
	Timestamp    uint64
	Status       uint8
	MessageAP    uint8
	MessageClient uint8
	RC           uint64
	NC           uint8
	AP           [6]byte
	Client       [6]byte
	ANonce       [32]byte
	PMKID        [16]byte
	MDIDLen      uint8
	MDID         uint16
	R0KHIDLen    uint8
	R0KHID       [48]byte
	R1KHIDLen    uint8
	R1KHID       [6]byte
	EAPAuthLen   uint16
	EAPOL        [EAPOL_AUTHLEN_MAX]byte
	EAPAuthLenM2 uint16
	EAPOLM2      [EAPOL_AUTHLEN_MAX]byte
}

type PMKIDEntry struct {
	Timestamp  uint64
	Status     uint8
	AP         [6]byte
	Client     [6]byte
	ANonce     [32]byte
	PMKID      [16]byte
	MDIDLen    uint8
	MDID       uint16
	R0KHIDLen  uint8
	R0KHID     [48]byte
	R1KHIDLen  uint8
	R1KHID     [6]byte
}

type APEntry struct {
	Timestamp uint64
	Count     int
	Type      uint8
	Status    uint8
	Addr      [6]byte
	KDVersion uint8
	GroupCipher uint8
	Cipher    uint8
	AKM       uint8
	Algorithm uint8
	ESSIDLen  uint8
	ESSID     [ESSID_LEN_MAX]byte
}

type MessageEntry struct {
	Timestamp    uint64
	EAPOLMsgCount int64
	Status       uint8
	AP           [6]byte
	Client       [6]byte
	Message      uint8
	RC           uint64
	Nonce        [32]byte
	PMKID        [16]byte
	MDIDLen      uint8
	MDID         uint16
	R0KHIDLen    uint8
	R0KHID       [48]byte
	R1KHIDLen    uint8
	R1KHID       [6]byte
	EAPAuthLen   uint16
	EAPOL        [EAPOL_AUTHLEN_MAX]byte
}

type ConversionResult struct {
	APs        []APEntry
	Handshakes []HandshakeEntry
	PMKIDs     []PMKIDEntry
	Stats      ConversionStats
}

type ConversionStats struct {
	RawPacketCount      int64
	BeaconCount         int64
	EAPOLMsgCount      int64
	EAPOLMPCount       int64
	EAPOLMPBestCount   int64
	EAPOLWrittenCount  int64
	EAPOLNotWrittenCount int64
	EAPOLM1Count       int64
	EAPOLM2Count       int64
	EAPOLM3Count       int64
	EAPOLM4Count       int64
	PMKIDCount         int64
	PMKIDBestCount     int64
	PMKIDWrittenCount  int64
	BroadcastSkipCount int64
	SkippedPacketCount int64
}

const (
	IEEE80211_FC0_TYPE_MGT  = 0x00
	IEEE80211_FC0_TYPE_CTL  = 0x04
	IEEE80211_FC0_TYPE_DATA = 0x08

	IEEE80211_FC0_SUBTYPE_BEACON     = 0x80
	IEEE80211_FC0_SUBTYPE_PROBE_RESP = 0x50
	IEEE80211_FC0_SUBTYPE_ASSOC_REQ  = 0x00
	IEEE80211_FC0_SUBTYPE_ASSOC_RESP = 0x10
	IEEE80211_FC0_SUBTYPE_REASSOC_REQ = 0x20
	IEEE80211_FC0_SUBTYPE_REASSOC_RESP = 0x30

	IEEE80211_FC1_DIR_TODS   = 0x01
	IEEE80211_FC1_DIR_FROMDS = 0x02
	IEEE80211_FC1_DIR_DSTODS = 0x03

	IEEE80211_ELEMID_SSID   = 0
	IEEE80211_ELEMID_RSN    = 48
	IEEE80211_ELEMID_VENDOR = 221

	EAPOL_KEY = 3

	LINKTYPE_IEEE802_11          = 105
	LINKTYPE_IEEE802_11_RADIOTAP = 127

	ETHER_TYPE_EAPOL = 0x888e

	LLC_SNAP = 0xaa
)

var rsnOUI = [3]byte{0x00, 0x0f, 0xac}
var msOUI  = [3]byte{0x00, 0x50, 0xf2}
var wfaOUI = [3]byte{0x50, 0x6f, 0x9a}

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var nullMAC = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

var macRe = regexp.MustCompile(`^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$`)

func MACToBytes(mac string) ([6]byte, error) {
	var result [6]byte
	if !macRe.MatchString(mac) {
		return result, fmt.Errorf("hcx: invalid MAC address: %s", mac)
	}
	clean := strings.NewReplacer(":", "", "-", "").Replace(mac)
	b, err := hexDecode(clean)
	if err != nil || len(b) != 6 {
		return result, fmt.Errorf("hcx: invalid MAC address: %s", mac)
	}
	copy(result[:], b)
	return result, nil
}

func hexDecode(s string) ([]byte, error) {
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		result[i/2] = byte(v)
	}
	return result, nil
}

func byteToHex(b []byte) string {
	return fmt.Sprintf("%02x", b)
}

func getEAPOLKeyVer(keyInfo uint16) int {
	switch keyInfo & WPA_KEY_INFO_TYPE_MASK {
	case WPA_KEY_INFO_TYPE_HMAC_MD5_RC4:
		return 1
	case WPA_KEY_INFO_TYPE_HMAC_SHA1_AES:
		return 2
	default:
		return 2
	}
}

func readU16BE(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return binary.BigEndian.Uint16(data[offset:])
}

func readU16LE(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint16(data[offset:])
}

func readU32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset:])
}