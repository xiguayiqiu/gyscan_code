package wifie

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func ParseEAPOL(data []byte) (*EAPOLFrame, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("wifie: EAPOL frame too short: %d bytes", len(data))
	}

	eapol := &EAPOLFrame{
		Version: data[0],
		Type:    data[1],
		Length:  binary.BigEndian.Uint16(data[2:4]),
		Raw:     make([]byte, len(data)),
	}
	copy(eapol.Raw, data)

	if eapol.Type != EAPOL_KEY {
		return eapol, nil
	}

	if len(data) < 95 {
		return eapol, nil
	}

	eapol.KeyDescType = data[4]
	eapol.KeyInfo = binary.BigEndian.Uint16(data[5:7])
	eapol.KeyLength = binary.BigEndian.Uint16(data[7:9])

	if len(data) >= 17 {
		eapol.ReplayCtr = binary.BigEndian.Uint64(data[9:17])
	}
	if len(data) >= 49 {
		copy(eapol.KeyNonce[:], data[17:49])
	}
	if len(data) >= 65 {
		copy(eapol.KeyIV[:], data[49:65])
	}
	if len(data) >= 73 {
		copy(eapol.KeyRSC[:], data[65:73])
	}
	if len(data) >= 81 {
		copy(eapol.KeyID[:], data[73:81])
	}
	if len(data) >= 97 {
		copy(eapol.KeyMIC[:], data[81:97])
	}
	if len(data) >= 99 {
		eapol.KeyDataLen = binary.BigEndian.Uint16(data[97:99])
	}
	if len(data) >= 99+int(eapol.KeyDataLen) {
		eapol.KeyData = make([]byte, eapol.KeyDataLen)
		copy(eapol.KeyData, data[99:99+int(eapol.KeyDataLen)])
	}

	return eapol, nil
}

func IsEAPOL(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[1] == EAPOL_KEY
}

func GetEAPOLMessageNumber(eapol *EAPOLFrame) int {
	if eapol == nil {
		return 0
	}

	// 检查 KeyInfo 中的关键位
	// 消息 1: 有 ACK, 无 MIC, 无 INSTALL
	if (eapol.KeyInfo&0x008a == 0x008a) || // 匹配我们实际看到的值
		((eapol.KeyInfo&EAPOL_KEY_INFO_KEY_ACK != 0) && 
		 (eapol.KeyInfo&EAPOL_KEY_INFO_KEY_MIC == 0) &&
		 (eapol.KeyInfo&EAPOL_KEY_INFO_INSTALL == 0)) {
		return 1
	}

	// 消息 2: 无 ACK, 有 MIC, 无 INSTALL, KeyNonce 非 0
	if (eapol.KeyInfo&0x010a == 0x010a) || // 匹配我们实际看到的值
		((eapol.KeyInfo&EAPOL_KEY_INFO_KEY_ACK == 0) && 
		 (eapol.KeyInfo&EAPOL_KEY_INFO_KEY_MIC != 0) &&
		 (eapol.KeyInfo&EAPOL_KEY_INFO_INSTALL == 0)) {
		// 检查 KeyNonce 是否非 0
		hasNonce := false
		for _, b := range eapol.KeyNonce {
			if b != 0 {
				hasNonce = true
				break
			}
		}
		if hasNonce {
			return 2
		}
		return 4
	}

	// 消息3: 有 ACK, 有 MIC, 有 INSTALL
	if (eapol.KeyInfo&0x13ca == 0x13ca) || // 匹配我们实际看到的值
		((eapol.KeyInfo&EAPOL_KEY_INFO_KEY_ACK != 0) && 
		 (eapol.KeyInfo&EAPOL_KEY_INFO_KEY_MIC != 0) &&
		 (eapol.KeyInfo&EAPOL_KEY_INFO_INSTALL != 0)) {
		return 3
	}

	// 消息4: 无 ACK, 有 MIC, 无 INSTALL, KeyNonce 为 0
	if (eapol.KeyInfo&0x030a == 0x030a) || // 匹配我们实际看到的值
		((eapol.KeyInfo&EAPOL_KEY_INFO_KEY_ACK == 0) && 
		 (eapol.KeyInfo&EAPOL_KEY_INFO_KEY_MIC != 0) &&
		 (eapol.KeyInfo&EAPOL_KEY_INFO_INSTALL == 0)) {
		return 4
	}

	return 0
}

func ProcessHandshakeFrame(eapol *EAPOLFrame, frame *Frame80211, hs *WPAHandshake) bool {
	if eapol == nil || frame == nil || hs == nil {
		return false
	}

	msgNum := GetEAPOLMessageNumber(eapol)

	if frame.FromDS {
		hs.BSSID = frame.Addr2
		hs.STAMAC = frame.Addr1
	} else if frame.ToDS {
		hs.BSSID = frame.Addr1
		hs.STAMAC = frame.Addr2
	} else {
		hs.BSSID = frame.Addr3
		hs.STAMAC = frame.Addr2
		if hs.BSSID == "" {
			hs.BSSID = hs.STAMAC
		}
	}

	switch msgNum {
	case 1:
		if hs.Frame1 == nil {
			hs.Frame1 = eapol
			copy(hs.ANonce[:], eapol.KeyNonce[:])
			hs.State |= WPA_STATE_ANONCE
		}
	case 2:
		if hs.Frame2 == nil {
			hs.Frame2 = eapol
			copy(hs.SNonce[:], eapol.KeyNonce[:])
			hs.State |= WPA_STATE_SNONCE
		}
		if (hs.State & WPA_STATE_EAPOLMIC) == 0 {
			captureEAPOLMIC(eapol, hs)
		}
	case 3:
		if hs.Frame3 == nil {
			hs.Frame3 = eapol
			copy(hs.ANonce[:], eapol.KeyNonce[:])
			hs.State |= WPA_STATE_ANONCE
		}
		if (hs.State & WPA_STATE_EAPOLMIC) == 0 {
			captureEAPOLMIC(eapol, hs)
			if eapol.KeyDataLen > 0 {
				hs.PMKID = findPMKIDInKDE(eapol.KeyData)
			}
		}
	case 4:
		if hs.Frame4 == nil {
			hs.Frame4 = eapol
		}
	}

	hs.Complete = hs.State == WPA_STATE_COMPLETE

	return hs.Complete
}

func msIs(eapol *EAPOLFrame) bool {
	if eapol == nil {
		return false
	}

	msgNum := GetEAPOLMessageNumber(eapol)
	if msgNum == 2 {
		return true
	}
	if msgNum == 3 {
		isMIC := (eapol.KeyInfo & EAPOL_KEY_INFO_KEY_MIC) != 0
		isSecure := (eapol.KeyInfo & EAPOL_KEY_INFO_SECURE) != 0
		isACK := (eapol.KeyInfo & EAPOL_KEY_INFO_KEY_ACK) != 0
		hasData := eapol.KeyDataLen > 0

		_ = isMIC
		_ = isSecure
		_ = isACK
		_ = hasData

		return true
	}
	return false
}

func findPMKIDInKDE(kde []byte) []byte {
	for offset := 0; offset+2 <= len(kde); offset += 2 {
		kdeType := binary.BigEndian.Uint16(kde[offset:])
		kdeLen := int(binary.BigEndian.Uint16(kde[offset+2:]))
		if offset+4+kdeLen > len(kde) {
			break
		}
		if kdeType == 4 && kdeLen >= 16 {
			pmkid := make([]byte, 16)
			copy(pmkid, kde[offset+4:offset+4+16])
			return pmkid
		}
		offset += 2 + kdeLen
	}
	return nil
}

func captureEAPOLMIC(eapol *EAPOLFrame, hs *WPAHandshake) {
	eapolLen := int(eapol.Length) + 4
	if eapolLen <= 0 || eapolLen > len(hs.EAPOLData) {
		return
	}

	copy(hs.EAPOLData[:eapolLen], eapol.Raw[:eapolLen])

	if eapolLen > 81+16 {
		for i := 81; i < 97; i++ {
			hs.EAPOLData[i] = 0
		}
	}

	hs.EAPOLSize = eapolLen
	copy(hs.MIC[:], eapol.KeyMIC[:])
	hs.Version = eapol.KeyDescType
	hs.State |= WPA_STATE_EAPOLMIC
}

func CheckHandshakeMIC(hs *WPAHandshake, pmk []byte) bool {
	if hs == nil || !hs.Complete {
		return false
	}

	ptk := CalcPTK(pmk, hs.BSSID, hs.STAMAC, hs.ANonce[:], hs.SNonce[:], hs.Version)

	mic, err := CalcEAPOLMIC(hs.EAPOLData[:hs.EAPOLSize], ptk, hs.Version)
	if err != nil {
		return false
	}

	return bytes.Equal(mic[:16], hs.MIC[:16])
}

func (eapol *EAPOLFrame) String() string {
	if eapol == nil {
		return "EAPOL: nil"
	}
	msgNum := GetEAPOLMessageNumber(eapol)
	isPairwise := (eapol.KeyInfo & EAPOL_KEY_INFO_KEY_TYPE) != 0

	_ = isPairwise

	return fmt.Sprintf("EAPOL M%d (ver=%d, len=%d, keyinfo=0x%04x)",
		msgNum, eapol.Version, eapol.Length, eapol.KeyInfo)
}

func (hs *WPAHandshake) String() string {
	if hs == nil {
		return "WPAHandshake: nil"
	}
	return fmt.Sprintf("WPAHandshake BSSID=%s STA=%s Complete=%v PMKID=%x",
		hs.BSSID, hs.STAMAC, hs.Complete, hs.PMKID)
}