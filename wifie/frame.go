package wifie

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func ParseFrame80211(data []byte) (*Frame80211, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("wifie: packet too short for 802.11 frame: %d bytes", len(data))
	}

	f := &Frame80211{
		Raw:  data,
		FC0:  data[0],
		FC1:  data[1],
	}

	f.Type = FrameType(f.FC0 & IEEE80211_FC0_TYPE_MASK)
	f.Subtype = FrameSubtype(f.FC0 & (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK))
	f.ToDS = (f.FC1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_TODS || (f.FC1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS
	f.FromDS = (f.FC1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_FROMDS || (f.FC1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS
	f.Protected = (f.FC1 & IEEE80211_FC1_PROTECTED) != 0
	f.Retry = (f.FC1 & IEEE80211_FC1_RETRY) != 0
	f.PwrMgmt = (f.FC1 & IEEE80211_FC1_PWR_MGT) != 0
	f.MoreData = (f.FC1 & IEEE80211_FC1_MORE_DATA) != 0
	f.MoreFrag = (f.FC1 & IEEE80211_FC1_MORE_FRAG) != 0
	f.Order = (f.FC1 & IEEE80211_FC1_ORDER) != 0

	if len(data) < 4 {
		return f, nil
	}
	f.Duration = binary.LittleEndian.Uint16(data[2:4])

	offset := 4

	switch f.Type {
	case IEEE80211_FC0_TYPE_MGT, IEEE80211_FC0_TYPE_DATA:
		if len(data) < 24 {
			return f, nil
		}
		f.Addr1 = macToString(data[offset : offset+6])
		offset += 6
		f.Addr2 = macToString(data[offset : offset+6])
		offset += 6
		f.Addr3 = macToString(data[offset : offset+6])
		offset += 6

		if len(data) > offset+2 {
			sc := binary.LittleEndian.Uint16(data[offset:])
			f.Fragment = uint8(sc & 0x000f)
			f.Seq = (sc & 0xfff0) >> 4
			offset += 2
		}

		hasQoS := f.FC0&IEEE80211_FC0_SUBTYPE_QOS_DATA == IEEE80211_FC0_SUBTYPE_QOS_DATA

		if hasQoS && len(data) > offset+2 {
			f.QoSCtl = binary.LittleEndian.Uint16(data[offset:])
			offset += 2
		}

		if (f.FC1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS {
			if len(data) > offset+6 {
				f.Addr4 = macToString(data[offset : offset+6])
				offset += 6
			}
		}

		if int(offset) < len(data) {
			f.Body = data[offset:]
		}

	case IEEE80211_FC0_TYPE_CTL:
		switch f.Subtype {
		case IEEE80211_FC0_SUBTYPE_PS_POLL:
			if len(data) >= 16 {
				f.Addr2 = macToString(data[offset+8:])
			}
		default:
			if len(data) >= 10 {
				f.Addr1 = macToString(data[offset : offset+6])
			}
		}
	}

	return f, nil
}

func macToString(mac []byte) string {
	if len(mac) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func ParseBeacon(f *Frame80211) *WiFiNetwork {
	if f.Subtype != IEEE80211_FC0_SUBTYPE_BEACON && f.Subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP {
		return nil
	}

	body := f.Body
	if len(body) < 12 {
		return nil
	}

	net := &WiFiNetwork{
		BSSID:       f.Addr3,
		InfoElements: make(map[int][]byte),
	}

	if f.Radiotap != nil {
		net.Signal = int(f.Radiotap.AntSignal)
		net.Noise = int(f.Radiotap.AntNoise)
		net.Freq = f.Radiotap.Freq
		net.Channel = f.Radiotap.Channel
	}

	timestamp := body[0:8]
	_ = timestamp
	beaconInterval := binary.LittleEndian.Uint16(body[8:10])
	_ = beaconInterval
	capability := binary.LittleEndian.Uint16(body[10:12])

	net.Privacy = (capability & IEEE80211_CAPINFO_PRIVACY) != 0

	ies := body[12:]
	parseInfoElements(net, ies)

	if net.ESSID == "" {
		net.ESSID = "<hidden>"
	}

	net.Cipher, net.Auth, net.Standard = classifySecurity(net)

	return net
}

func parseInfoElements(net *WiFiNetwork, data []byte) {
	offset := 0
	for offset+2 <= len(data) {
		elemID := data[offset]
		elemLen := int(data[offset+1])
		offset += 2

		if offset+elemLen > len(data) {
			break
		}

		elemData := data[offset : offset+elemLen]
		net.InfoElements[int(elemID)] = elemData

		switch elemID {
		case IEEE80211_ELEMID_SSID:
			net.ESSID = string(elemData)
		case IEEE80211_ELEMID_RATES, IEEE80211_ELEMID_XRATES:
			for _, r := range elemData {
				rate := float64(r&0x7f) * 0.5
				net.Rates = append(net.Rates, rate)
				if rate > net.MaxRate {
					net.MaxRate = rate
				}
			}
		case IEEE80211_ELEMID_DSPARMS:
			if len(elemData) > 0 {
				net.Channel = int(elemData[0])
				net.Freq = FreqFromChannel(net.Channel)
			}
		case IEEE80211_ELEMID_COUNTRY:
			if len(elemData) >= 3 {
				net.Country = string(elemData[0:3])
			}
		case IEEE80211_ELEMID_HTCAP:
			net.HTCap = true
		case IEEE80211_ELEMID_VHT_CAP:
			net.VHTCap = true
		case IEEE80211_ELEMID_VENDOR:
			if len(elemData) >= 4 {
				if elemData[0] == 0x00 && elemData[1] == 0x50 && elemData[2] == 0xf2 && elemData[3] == 0x04 {
					net.WPS = true
				}
			}
		}

		offset += elemLen
	}
}

func classifySecurity(net *WiFiNetwork) (cipher, auth, standard string) {
	hasRSN := false
	hasWPA := false

	if rsnData, ok := net.InfoElements[IEEE80211_ELEMID_RSN]; ok {
		hasRSN = true
		if len(rsnData) >= 4 {
			groupCipher := parseCipherSuite(rsnData[2:6])
			if groupCipher != "" {
				cipher = groupCipher
			}
			offset := 6
			if offset+2 <= len(rsnData) {
				pairwiseCount := int(binary.LittleEndian.Uint16(rsnData[offset:]))
				offset += 2
				if pairwiseCount > 0 && offset+4 <= len(rsnData) {
					cipher = parseCipherSuite(rsnData[offset : offset+4])
					offset += int(pairwiseCount) * 4
				}
			}
			if offset+2 <= len(rsnData) {
				authCount := int(binary.LittleEndian.Uint16(rsnData[offset:]))
				offset += 2
				if authCount > 0 && offset+4 <= len(rsnData) {
					auth = parseAKMSuite(rsnData[offset : offset+4])
				}
			}
		}
		standard = "WPA2"
	}

	if vendorData, ok := net.InfoElements[IEEE80211_ELEMID_VENDOR]; ok && !hasRSN {
		if len(vendorData) >= 6 {
			if vendorData[0] == 0x00 && vendorData[1] == 0x50 && vendorData[2] == 0xf2 && vendorData[3] == 0x01 {
				hasWPA = true
				offset := 6
				if offset+4 <= len(vendorData) {
					cipher = parseCipherSuite(vendorData[offset : offset+4])
					offset += 4
				}
				if offset+2 <= len(vendorData) {
					pairwiseCount := int(binary.LittleEndian.Uint16(vendorData[offset:]))
					offset += 2
					if pairwiseCount > 0 && offset+4 <= len(vendorData) {
						cipher = parseCipherSuite(vendorData[offset : offset+4])
						offset += int(pairwiseCount) * 4
					}
				}
				if offset+2 <= len(vendorData) {
					authCount := int(binary.LittleEndian.Uint16(vendorData[offset:]))
					offset += 2
					if authCount > 0 && offset+4 <= len(vendorData) {
						auth = parseAKMSuite(vendorData[offset : offset+4])
					}
				}
			}
		}
		standard = "WPA"
	}

	if !hasRSN && !hasWPA {
		if net.Privacy {
			standard = "WEP"
			cipher = "WEP"
			auth = "PSK"
		} else {
			standard = "Open"
			cipher = ""
			auth = "Open"
		}
	}

	if auth == "SAE" {
		standard = "WPA3"
	}

	if cipher == "GCMP" {
		standard = "WPA3"
	}

	return
}

func parseCipherSuite(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	oui := data[0:3]
	cipher := data[3]

	if oui[0] == 0x00 && oui[1] == 0x0f && oui[2] == 0xac {
		switch cipher {
		case 1:
			return "WEP40"
		case 2:
			return "TKIP"
		case 4:
			return "CCMP"
		case 5:
			return "WEP104"
		case 6:
			return "BIP"
		case 8:
			return "GCMP"
		case 9:
			return "GCMP-256"
		case 10:
			return "CCMP-256"
		case 11:
			return "BIP-GMAC-128"
		case 12:
			return "BIP-GMAC-256"
		case 13:
			return "BIP-CMAC-256"
		}
	}
	return fmt.Sprintf("Unknown(0x%02x)", cipher)
}

func parseAKMSuite(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	oui := data[0:3]
	akm := data[3]

	if oui[0] == 0x00 && oui[1] == 0x0f && oui[2] == 0xac {
		switch akm {
		case 1:
			return "MGT"
		case 2:
			return "PSK"
		case 3:
			return "FT"
		case 4:
			return "PSK-SHA256"
		case 5:
			return "MGT-SHA256"
		case 6:
			return "FT-SHA256"
		case 7:
			return "TLS"
		case 8:
			return "SAE"
		case 9:
			return "FT-SAE"
		case 10:
			return "AP-PEER"
		case 11:
			return "MGT-SHA384"
		case 12:
			return "FT-SHA384"
		case 18:
			return "OWE"
		}
	}
	return fmt.Sprintf("Unknown(0x%02x)", akm)
}

func (f *Frame80211) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "802.11 Frame:\n")
	fmt.Fprintf(&b, "  Type: %s (%d)\n", f.Type, f.FC0&IEEE80211_FC0_TYPE_MASK)
	fmt.Fprintf(&b, "  Subtype: %s (0x%02x)\n", f.Subtype, f.FC0)
	fmt.Fprintf(&b, "  Duration: %d\n", f.Duration)
	fmt.Fprintf(&b, "  Addr1: %s\n", f.Addr1)
	fmt.Fprintf(&b, "  Addr2: %s\n", f.Addr2)
	fmt.Fprintf(&b, "  Addr3: %s\n", f.Addr3)
	if f.Addr4 != "" {
		fmt.Fprintf(&b, "  Addr4: %s\n", f.Addr4)
	}
	fmt.Fprintf(&b, "  Seq: %d, Frag: %d\n", f.Seq, f.Fragment)
	fmt.Fprintf(&b, "  Protected: %v, Retry: %v\n", f.Protected, f.Retry)
	fmt.Fprintf(&b, "  ToDS: %v, FromDS: %v\n", f.ToDS, f.FromDS)
	if f.Radiotap != nil {
		fmt.Fprintf(&b, "  Signal: %d dBm, Noise: %d dBm\n", int(f.Radiotap.AntSignal), int(f.Radiotap.AntNoise))
		fmt.Fprintf(&b, "  Channel: %d, Freq: %d MHz\n", f.Radiotap.Channel, f.Radiotap.Freq)
		fmt.Fprintf(&b, "  DataRate: %.1f Mbps\n", f.Radiotap.DataRate)
	}
	return b.String()
}

func (n *WiFiNetwork) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "WiFi Network:\n")
	fmt.Fprintf(&b, "  BSSID: %s\n", n.BSSID)
	fmt.Fprintf(&b, "  ESSID: %s\n", n.ESSID)
	fmt.Fprintf(&b, "  Channel: %d (%d MHz)\n", n.Channel, n.Freq)
	fmt.Fprintf(&b, "  Signal: %d dBm\n", n.Signal)
	fmt.Fprintf(&b, "  Standard: %s\n", n.Standard)
	fmt.Fprintf(&b, "  Cipher: %s\n", n.Cipher)
	fmt.Fprintf(&b, "  Auth: %s\n", n.Auth)
	fmt.Fprintf(&b, "  Max Rate: %.1f Mbps\n", n.MaxRate)
	if n.HTCap {
		fmt.Fprintf(&b, "  HT Capable\n")
	}
	if n.VHTCap {
		fmt.Fprintf(&b, "  VHT Capable\n")
	}
	if n.WPS {
		fmt.Fprintf(&b, "  WPS Enabled\n")
	}
	return b.String()
}

func GetFrameType(data []byte) FrameType {
	if len(data) < 2 {
		return 0
	}
	return FrameType(data[0] & IEEE80211_FC0_TYPE_MASK)
}

func GetFrameSubtype(data []byte) FrameSubtype {
	if len(data) < 2 {
		return 0
	}
	return FrameSubtype(data[0] & (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK))
}

func IsBeacon(data []byte) bool {
	return GetFrameSubtype(data) == IEEE80211_FC0_SUBTYPE_BEACON
}

func IsProbeRequest(data []byte) bool {
	return GetFrameSubtype(data) == IEEE80211_FC0_SUBTYPE_PROBE_REQ
}

func IsProbeResponse(data []byte) bool {
	return GetFrameSubtype(data) == IEEE80211_FC0_SUBTYPE_PROBE_RESP
}

func IsDeauth(data []byte) bool {
	return GetFrameSubtype(data) == IEEE80211_FC0_SUBTYPE_DEAUTH
}

func IsDisassoc(data []byte) bool {
	return GetFrameSubtype(data) == IEEE80211_FC0_SUBTYPE_DISASSOC
}

func IsAuth(data []byte) bool {
	return GetFrameSubtype(data) == IEEE80211_FC0_SUBTYPE_AUTH
}

func IsData(data []byte) bool {
	return GetFrameType(data) == IEEE80211_FC0_TYPE_DATA
}

func IsProtected(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return (data[1] & IEEE80211_FC1_PROTECTED) != 0
}

func FreqToChannel(freq int) int {
	if ch, ok := FreqToChannel24GHz[freq]; ok {
		return ch
	}
	if ch, ok := FreqToChannel5GHz[freq]; ok {
		return ch
	}
	return 0
}

func FreqFromChannel(ch int) int {
	if freq, ok := Channel24GHzFreq[ch]; ok {
		return freq
	}
	if freq, ok := Channel5GHzFreq[ch]; ok {
		return freq
	}
	return 0
}

func Is2GHz(freq int) bool {
	return freq >= 2400 && freq <= 2500
}

func Is5GHz(freq int) bool {
	return freq >= 5000 && freq <= 6000
}

func ParseAuthFrame(f *Frame80211) (alg uint16, seq uint16, status uint16) {
	if f == nil || f.Body == nil || len(f.Body) < 6 {
		return
	}
	alg = binary.LittleEndian.Uint16(f.Body[0:2])
	seq = binary.LittleEndian.Uint16(f.Body[2:4])
	status = binary.LittleEndian.Uint16(f.Body[4:6])
	return
}

func ParseWEPDataFrame(f *Frame80211) (*WEPPacket, error) {
	if f == nil || f.Body == nil || len(f.Body) < 8 {
		return nil, fmt.Errorf("wifie: body too short for WEP frame")
	}

	wp := &WEPPacket{
		Raw: make([]byte, len(f.Body)),
	}
	copy(wp.Raw, f.Body)

	copy(wp.IV[:], f.Body[0:3])
	wp.KeyIdx = f.Body[3] & 0x03

	dataLen := len(f.Body) - 8
	wp.Data = make([]byte, dataLen)
	copy(wp.Data, f.Body[4:4+dataLen])

	copy(wp.ICV[:], f.Body[4+dataLen:8+dataLen])

	return wp, nil
}

func ParseLLCSNAP(f *Frame80211) (ethertype uint16, payload []byte) {
	if f == nil || f.Body == nil || len(f.Body) < 8 {
		return
	}

	if f.Body[0] == 0xAA && f.Body[1] == 0xAA && f.Body[2] == 0x03 {
		payload = f.Body[8:]
		if len(f.Body) >= 8 {
			ethertype = binary.BigEndian.Uint16(f.Body[6:8])
		}
		return
	}

	if len(f.Body) >= 2 {
		ethertype = binary.BigEndian.Uint16(f.Body[0:2])
		payload = f.Body[2:]
	}

	return
}

func IsARP(ethertype uint16) bool {
	return ethertype == ETHERTYPE_ARP
}

func IsIP(ethertype uint16) bool {
	return ethertype == ETHERTYPE_IP
}

func IsEAPOLFrame(f *Frame80211) bool {
	if f == nil || f.Type != IEEE80211_FC0_TYPE_DATA {
		return false
	}
	ethertype, _ := ParseLLCSNAP(f)
	return ethertype == ETHERTYPE_EAPOL
}

func ExtractEAPOL(f *Frame80211) ([]byte, error) {
	if !IsEAPOLFrame(f) {
		return nil, fmt.Errorf("wifie: not an EAPOL frame")
	}
	_, payload := ParseLLCSNAP(f)
	return payload, nil
}

func DetectWPAHandshake(f *Frame80211, handshake *WPAHandshake) bool {
	if !IsEAPOLFrame(f) {
		return false
	}

	eapolData, err := ExtractEAPOL(f)
	if err != nil || len(eapolData) < 4 {
		return false
	}

	eapol, err := ParseEAPOL(eapolData)
	if err != nil || eapol == nil {
		return false
	}

	ProcessHandshakeFrame(eapol, f, handshake)

	return true
}

func GetBSSID(f *Frame80211) string {
	if f == nil {
		return ""
	}
	switch {
	case f.ToDS && !f.FromDS:
		return f.Addr1
	case !f.ToDS && f.FromDS:
		return f.Addr2
	default:
		return f.Addr3
	}
}

func GetSourceMAC(f *Frame80211) string {
	if f == nil {
		return ""
	}
	return f.Addr2
}

func GetDestMAC(f *Frame80211) string {
	if f == nil {
		return ""
	}
	return f.Addr1
}

func GetTransmitterMAC(f *Frame80211) string {
	if f == nil {
		return ""
	}
	if f.FromDS {
		return f.Addr3
	}
	return f.Addr2
}

func ParseFrameWithRadiotap(packet []byte) (*Frame80211, error) {
	rtInfo, rtLen := ParseRadiotap(packet)
	if rtLen <= 0 || rtLen >= len(packet) {
		return ParseFrame80211(packet)
	}

	frame, err := ParseFrame80211(packet[rtLen:])
	if err != nil {
		return nil, err
	}
	frame.Radiotap = rtInfo

	frameWithHeader := &Frame80211{}
	*frameWithHeader = *frame
	frameWithHeader.Raw = packet
	frameWithHeader.Radiotap = rtInfo

	return frameWithHeader, nil
}

func SignalStrength(f *Frame80211) int {
	if f != nil && f.Radiotap != nil {
		return int(f.Radiotap.AntSignal)
	}
	return -100
}

func IsManagementFrame(f *Frame80211) bool {
	return f != nil && f.Type == IEEE80211_FC0_TYPE_MGT
}

func IsControlFrame(f *Frame80211) bool {
	return f != nil && f.Type == IEEE80211_FC0_TYPE_CTL
}

func IsDataFrame(f *Frame80211) bool {
	return f != nil && f.Type == IEEE80211_FC0_TYPE_DATA
}

func IsQoSFrame(f *Frame80211) bool {
	if f == nil {
		return false
	}
	return f.FC0&IEEE80211_FC0_SUBTYPE_QOS_DATA == IEEE80211_FC0_SUBTYPE_QOS_DATA
}

func (f *Frame80211) GetHeaderLen() int {
	len := 2
	if f.Type == IEEE80211_FC0_TYPE_MGT || f.Type == IEEE80211_FC0_TYPE_DATA {
		len += 22
		if IsQoSFrame(f) {
			len += 2
		}
		if (f.FC1 & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS {
			len += 6
		}
	}
	return len
}

func (f *Frame80211) GetBody() []byte {
	hl := f.GetHeaderLen()
	if len(f.Raw) > hl {
		return f.Raw[hl:]
	}
	return nil
}