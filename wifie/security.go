package wifie

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func AnalyzeSecurity(net *WiFiNetwork) *SecurityInfo {
	info := &SecurityInfo{}

	if rsnData, ok := net.InfoElements[IEEE80211_ELEMID_RSN]; ok {
		if len(rsnData) >= 2 {
			info.Standard = "WPA2"
			info.IsWPA2 = true
			info.Standard = net.Standard

			offset := 0
			if offset+2 <= len(rsnData) {
				offset += 2
			}
			if offset+4 <= len(rsnData) {
				info.Cipher = parseCipherSuite(rsnData[offset : offset+4])
				offset += 4
			}
			if offset+2 <= len(rsnData) {
				pairwiseCount := int(binary.LittleEndian.Uint16(rsnData[offset:]))
				offset += 2
				if pairwiseCount > 0 && offset+4 <= len(rsnData) {
					info.Cipher = parseCipherSuite(rsnData[offset : offset+4])
					offset += int(pairwiseCount) * 4
				}
			}
			if offset+2 <= len(rsnData) {
				authCount := int(binary.LittleEndian.Uint16(rsnData[offset:]))
				offset += 2
				if authCount > 0 && offset+4 <= len(rsnData) {
					info.Auth = parseAKMSuite(rsnData[offset : offset+4])
				}

				if strings.Contains(info.Auth, "SAE") {
					info.IsWPA3 = true
					info.IsWPA2 = false
				}
			}

			if offset+2 <= len(rsnData) {
				rsnCap := binary.LittleEndian.Uint16(rsnData[offset:])
				_ = rsnCap
				offset += 2
			}

			if offset+2 <= len(rsnData) {
				pmkidCount := int(binary.LittleEndian.Uint16(rsnData[offset:]))
				offset += 2
				if pmkidCount > 0 {
					info.HasPMKID = true
					if offset+16 <= len(rsnData) {
						info.PMKID = make([]byte, 16)
						copy(info.PMKID, rsnData[offset:offset+16])
					}
				}
			}
		}
	}

	if vendorData, ok := net.InfoElements[IEEE80211_ELEMID_VENDOR]; ok && info.Standard == "" {
		if len(vendorData) >= 6 {
			if vendorData[0] == 0x00 && vendorData[1] == 0x50 && vendorData[2] == 0xf2 && vendorData[3] == 0x01 {
				info.IsWPA = true
				info.Standard = "WPA"
			}
		}
	}

	if info.Standard == "" {
		if net.Standard != "" && net.Standard != "Unknown" {
			info.Standard = net.Standard
			switch net.Standard {
			case "WEP":
				info.IsWEP = true
				info.Cipher = "WEP"
				info.Auth = "PSK"
			case "WPA":
				info.IsWPA = true
				if net.Cipher != "" {
					info.Cipher = net.Cipher
				}
				if net.Auth != "" {
					info.Auth = net.Auth
				}
			case "WPA2":
				info.IsWPA2 = true
				if net.Cipher != "" {
					info.Cipher = net.Cipher
				}
				if net.Auth != "" {
					info.Auth = net.Auth
				}
			case "WPA3":
				info.IsWPA3 = true
				if net.Cipher != "" {
					info.Cipher = net.Cipher
				}
				if net.Auth != "" {
					info.Auth = net.Auth
				}
			case "Open":
				info.IsOpen = true
				info.Auth = "Open"
			}
		} else if net.Privacy {
			info.IsWEP = true
			info.Standard = "WEP"
			info.Cipher = "WEP"
			info.Auth = "PSK"
		} else {
			info.IsOpen = true
			info.Standard = "Open"
			info.Auth = "Open"
		}
	}

	switch {
	case strings.Contains(info.Cipher, "TKIP"):
		info.IsTKIP = true
	case strings.Contains(info.Cipher, "CCMP"):
		info.IsCCMP = true
	}

	return info
}

func CheckWEPWeakIV(iv []byte) bool {
	if len(iv) < 3 {
		return false
	}

	for _, weak := range WEPWeakIVs {
		if iv[0] == weak[0] && iv[1] == weak[1] && iv[2] == weak[2] {
			return true
		}
	}

	var b byte = (iv[0] + 3) & 0xff
	var xp2 uint32 = uint32(b)*uint32(b)*uint32(b) + uint32(0xff)*uint32(0xff)
	var xp3 uint32 = uint32(0xff)*uint32(0xff)*uint32(0xff) + uint32(0xff)*uint32(0xff)
	var xp uint32 = uint32(iv[2])*uint32(iv[2])*uint32(iv[2]) + uint32(iv[1])*uint32(iv[1])

	if xp2 <= xp && xp <= xp3 {
		return true
	}

	return false
}

func CheckWPS(net *WiFiNetwork) bool {
	if net.WPS {
		return true
	}

	if vendorData, ok := net.InfoElements[IEEE80211_ELEMID_VENDOR]; ok {
		if len(vendorData) >= 4 {
			if vendorData[0] == 0x00 && vendorData[1] == 0x50 && vendorData[2] == 0xf2 && vendorData[3] == 0x04 {
				net.WPS = true
				return true
			}
		}
	}

	return false
}

func ParseEAPOLFrame(f *Frame80211) *WPAPair {
	if f == nil || f.Body == nil || len(f.Body) < 16 {
		return nil
	}

	if f.Type != IEEE80211_FC0_TYPE_DATA {
		return nil
	}

	body := f.Body

	if len(body) < 8 {
		return nil
	}

	if body[0] != 0xAA || body[1] != 0xAA || body[2] != 0x03 {
		return nil
	}

	llcOffset := 8
	if llcOffset+2 > len(body) {
		return nil
	}

	etherType := binary.BigEndian.Uint16(body[llcOffset-2:])
	if etherType != 0x888E {
		return nil
	}

	eapolData := body[llcOffset:]
	if len(eapolData) < 4 {
		return nil
	}

	eapolVersion := eapolData[0]
	eapolType := eapolData[1]
	eapolLen := binary.BigEndian.Uint16(eapolData[2:4])

	_ = eapolVersion
	_ = eapolLen

	if eapolType == 3 {
		pair := &WPAPair{
			Handshake: make([]byte, len(eapolData)),
		}
		copy(pair.Handshake, eapolData)

		return pair
	}

	return nil
}

func (si *SecurityInfo) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security Analysis:\n")
	fmt.Fprintf(&b, "  Standard: %s\n", si.Standard)
	fmt.Fprintf(&b, "  Auth: %s\n", si.Auth)
	fmt.Fprintf(&b, "  Cipher: %s\n", si.Cipher)

	risks := make([]string, 0)

	if si.IsWEP {
		risks = append(risks, "WEP encryption (easily cracked)")
	}
	if si.IsTKIP {
		risks = append(risks, "TKIP cipher (deprecated)")
	}
	if si.IsOpen {
		risks = append(risks, "Open network (no encryption)")
	}
	if si.HasPMKID {
		risks = append(risks, "PMKID available (roaming attack)")
	}

	if len(risks) > 0 {
		fmt.Fprintf(&b, "  Risks:\n")
		for _, r := range risks {
			fmt.Fprintf(&b, "    - %s\n", r)
		}
	} else {
		fmt.Fprintf(&b, "  Status: Secure\n")
	}

	return b.String()
}

func (si *SecurityInfo) RiskLevel() string {
	if si.IsWEP || si.IsOpen {
		return "CRITICAL"
	}
	if si.IsTKIP {
		return "HIGH"
	}
	if si.HasPMKID {
		return "MEDIUM"
	}
	if si.IsWPA {
		return "LOW"
	}
	return "NONE"
}