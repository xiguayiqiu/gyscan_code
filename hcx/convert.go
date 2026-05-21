package hcx

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

const (
	PCAP_MAGIC         = 0xa1b2c3d4
	PCAP_SWAPPED_MAGIC = 0xd4c3b2a1
	PCAPNG_MAGIC       = 0x0a0d0d0a
)

type pcapHdr struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

type pcapRecHdr struct {
	TSec   uint32
	TSUsec uint32
	InclLen uint32
	OrigLen uint32
}

type radiotapHdr struct {
	Version uint8
	Pad     uint8
	Len     uint16
	Present uint32
}

func ConvertCapToHC22000(filename string) (*ConversionResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("hcx: failed to read file: %w", err)
	}

	if len(data) < 24 {
		return nil, fmt.Errorf("hcx: file too short: %d bytes", len(data))
	}

	magic := binary.LittleEndian.Uint32(data[0:4])

	switch magic {
	case PCAP_MAGIC:
		return convertPcap(data)
	case PCAP_SWAPPED_MAGIC:
		return convertPcapSwapped(data)
	default:
		pcapngMagic := binary.LittleEndian.Uint32(data[8:12])
		if pcapngMagic == PCAPNG_MAGIC || data[0] == 0x0a {
			return convertPcapNG(data)
		}
		return convertPcap(data)
	}
}

func convertPcap(data []byte) (*ConversionResult, error) {
	result := &ConversionResult{}
	apList := make([]APEntry, 0, MACLIST_MAX)
	messageList := make([]MessageEntry, 0, MESSAGELIST_MAX)
	handshakeList := make([]HandshakeEntry, 0, HANDSHAKELIST_MAX)
	pmkidList := make([]PMKIDEntry, 0, PMKIDLIST_MAX)

	if len(data) < 24 {
		return result, fmt.Errorf("hcx: pcap header too short")
	}

	hdr := pcapHdr{
		MagicNumber:  binary.LittleEndian.Uint32(data[0:4]),
		VersionMajor: binary.LittleEndian.Uint16(data[4:6]),
		VersionMinor: binary.LittleEndian.Uint16(data[6:8]),
		ThisZone:     int32(binary.LittleEndian.Uint32(data[8:12])),
		SigFigs:      binary.LittleEndian.Uint32(data[12:16]),
		SnapLen:      binary.LittleEndian.Uint32(data[16:20]),
		Network:      binary.LittleEndian.Uint32(data[20:24]),
	}

	offset := 24
	linkType := int(hdr.Network)

	for offset+16 <= len(data) {
		rec := pcapRecHdr{
			TSec:   binary.LittleEndian.Uint32(data[offset:]),
			TSUsec: binary.LittleEndian.Uint32(data[offset+4:]),
			InclLen: binary.LittleEndian.Uint32(data[offset+8:]),
			OrigLen: binary.LittleEndian.Uint32(data[offset+12:]),
		}
		offset += 16

		if int(rec.InclLen) > len(data)-offset {
			break
		}

		packet := make([]byte, rec.InclLen)
		copy(packet, data[offset:offset+int(rec.InclLen)])
		offset += int(rec.InclLen)

		result.Stats.RawPacketCount++

		timestamp := uint64(rec.TSec)*1000000000 + uint64(rec.TSUsec)*1000

		var frameData []byte
		if linkType == LINKTYPE_IEEE802_11_RADIOTAP {
			if len(packet) < 4 {
				result.Stats.SkippedPacketCount++
				continue
			}
			rtHdr := radiotapHdr{
				Version: packet[0],
				Pad:     packet[1],
				Len:     binary.LittleEndian.Uint16(packet[2:4]),
			}
			if int(rtHdr.Len) < 4 || int(rtHdr.Len) > len(packet) {
				result.Stats.SkippedPacketCount++
				continue
			}
			frameData = packet[rtHdr.Len:]
		} else {
			frameData = packet
		}

		if len(frameData) < 2 {
			result.Stats.SkippedPacketCount++
			continue
		}

		processFrame80211(frameData, timestamp, &apList, &messageList, &handshakeList, &pmkidList, result)
	}

	processHandshakes(&apList, &messageList, &handshakeList, &pmkidList, result)

	result.APs = apList
	result.Handshakes = handshakeList
	result.PMKIDs = pmkidList

	return result, nil
}

func convertPcapSwapped(data []byte) (*ConversionResult, error) {
	swapped := make([]byte, len(data))
	copy(swapped, data)

	for i := 0; i+4 <= len(swapped); i += 4 {
		swapped[i], swapped[i+1], swapped[i+2], swapped[i+3] =
			swapped[i+3], swapped[i+2], swapped[i+1], swapped[i]
	}

	hdrMagic := binary.LittleEndian.Uint32(swapped[0:4])
	_ = hdrMagic

	dataLE := make([]byte, len(data))
	copy(dataLE, data)

	for i := 0; i+2 <= len(dataLE); i += 2 {
		dataLE[i], dataLE[i+1] = dataLE[i+1], dataLE[i]
	}

	return convertPcap(dataLE)
}

func convertPcapNG(data []byte) (*ConversionResult, error) {
	return convertPcap(data)
}

func processFrame80211(frameData []byte, timestamp uint64,
	apList *[]APEntry, messageList *[]MessageEntry,
	handshakeList *[]HandshakeEntry, pmkidList *[]PMKIDEntry,
	result *ConversionResult) {

	if len(frameData) < 2 {
		return
	}

	fc0 := frameData[0]
	fc1 := frameData[1]
	fcType := fc0 & 0x0c
	fcSubtype := fc0 & 0xfc

	switch fcType {
	case IEEE80211_FC0_TYPE_MGT:
		processMgmtFrame(frameData, fc0, fc1, fcSubtype, timestamp, apList, result)
	case IEEE80211_FC0_TYPE_DATA:
		processDataFrame(frameData, fc0, fc1, timestamp, apList, messageList, handshakeList, pmkidList, result)
	}
}

func processMgmtFrame(data []byte, fc0, fc1, fcSubtype uint8, timestamp uint64,
	apList *[]APEntry, result *ConversionResult) {

	if fcSubtype != IEEE80211_FC0_SUBTYPE_BEACON && fcSubtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP {
		return
	}

	if len(data) < 24 {
		return
	}

	addr2 := [6]byte{}
	copy(addr2[:], data[10:16])
	addr3 := [6]byte{}
	copy(addr3[:], data[16:22])

	bssid := addr3
	if bssid == nullMAC || bssid == broadcastMAC {
		return
	}

	bodyOffset := 24
	if !(fc1&IEEE80211_FC1_DIR_DSTODS == IEEE80211_FC1_DIR_DSTODS) {
		bodyOffset = 24
	}

	if bodyOffset+12 > len(data) {
		return
	}

	ieData := data[bodyOffset+12:]
	essid, essidLen, rsnIE := parseIEs(ieData)

	if fcSubtype == IEEE80211_FC0_SUBTYPE_BEACON {
		result.Stats.BeaconCount++
	}

	existingIdx := -1
	for i := range *apList {
		if (*apList)[i].Addr == bssid {
			existingIdx = i
			break
		}
	}

	if existingIdx >= 0 {
		ap := &(*apList)[existingIdx]
		ap.Count++
		ap.Timestamp = timestamp
		if essidLen > 0 && essidLen <= ESSID_LEN_MAX && essid[0] != 0 {
			ap.ESSIDLen = essidLen
			copy(ap.ESSID[:], essid[:essidLen])
		}
	} else {
		ap := APEntry{
			Timestamp: timestamp,
			Count:     1,
			Type:      0x02,
			Status:    0x02,
		}
		copy(ap.Addr[:], bssid[:])
		if essidLen > 0 && essidLen <= ESSID_LEN_MAX && essid[0] != 0 {
			ap.ESSIDLen = essidLen
			copy(ap.ESSID[:], essid[:essidLen])
		}
		if rsnIE != nil {
			parseRSNIE(rsnIE, &ap)
		}
		*apList = append(*apList, ap)
	}
}

func processDataFrame(data []byte, fc0, fc1 uint8, timestamp uint64,
	apList *[]APEntry, messageList *[]MessageEntry,
	handshakeList *[]HandshakeEntry, pmkidList *[]PMKIDEntry,
	result *ConversionResult) {

	toDS := (fc1 & 0x03) == IEEE80211_FC1_DIR_TODS
	fromDS := (fc1 & 0x03) == IEEE80211_FC1_DIR_FROMDS

	if len(data) < 24 {
		return
	}

	addr1 := [6]byte{}
	copy(addr1[:], data[4:10])
	addr2 := [6]byte{}
	copy(addr2[:], data[10:16])
	addr3 := [6]byte{}
	copy(addr3[:], data[16:22])

	frameOffset := 24
	if fc0&0x80 == 0x80 {
		frameOffset += 2
	}

	if frameOffset >= len(data) {
		return
	}

	body := data[frameOffset:]

	if len(body) < 8 {
		return
	}

	if body[0] != LLC_SNAP || body[1] != LLC_SNAP || body[2] != 0x03 {
		return
	}

	etherType := binary.BigEndian.Uint16(body[6:8])
	if etherType != ETHER_TYPE_EAPOL {
		return
	}

	eapolData := body[8:]
	if len(eapolData) < 4 {
		return
	}

	if eapolData[1] != EAPOL_KEY {
		return
	}

	result.Stats.EAPOLMsgCount++

	apMAC, clientMAC := [6]byte{}, [6]byte{}
	if fromDS {
		apMAC = addr2
		clientMAC = addr1
	} else if toDS {
		apMAC = addr1
		clientMAC = addr2
	} else {
		return
	}

	if apMAC == broadcastMAC || clientMAC == broadcastMAC ||
		apMAC == nullMAC || clientMAC == nullMAC {
		result.Stats.BroadcastSkipCount++
		return
	}

	msg := processEAPOLMessage(eapolData, timestamp, apMAC, clientMAC,
		apList, messageList, handshakeList, pmkidList, result)
	_ = msg
}

func processEAPOLMessage(eapolData []byte, timestamp uint64,
	apMAC, clientMAC [6]byte,
	apList *[]APEntry, messageList *[]MessageEntry,
	handshakeList *[]HandshakeEntry, pmkidList *[]PMKIDEntry,
	result *ConversionResult) uint8 {

	eapolLen := len(eapolData)
	if eapolLen < 99 {
		return 0
	}

	keyDescType := eapolData[4]
	keyInfo := binary.BigEndian.Uint16(eapolData[5:7])
	_ = keyDescType

	replayCount := binary.BigEndian.Uint64(eapolData[9:17])

	var keyNonce [32]byte
	copy(keyNonce[:], eapolData[17:49])

	var keyMIC [16]byte
	copy(keyMIC[:], eapolData[81:97])

	keyDataLen := binary.BigEndian.Uint16(eapolData[97:99])

	msgNum := getEAPOLMessageNum(keyInfo, keyNonce)

	switch msgNum {
	case 1:
		result.Stats.EAPOLM1Count++
	case 2:
		result.Stats.EAPOLM2Count++
	case 3:
		result.Stats.EAPOLM3Count++
	case 4:
		result.Stats.EAPOLM4Count++
	}

	msgEntry := MessageEntry{
		Timestamp: timestamp,
		Status:    0,
		Message:   msgNum,
		RC:        replayCount,
	}
	msgEntry.AP = apMAC
	msgEntry.Client = clientMAC
	msgEntry.Nonce = keyNonce
	msgEntry.EAPAuthLen = uint16(eapolLen)
	copy(msgEntry.EAPOL[:], eapolData)

	if msgNum == 2 || msgNum == 3 {
		pmkid := findPMKIDInEAPOLKeyData(eapolData, int(keyDataLen), 99)
		if pmkid != nil {
			copy(msgEntry.PMKID[:], pmkid)
			msgEntry.Status |= HS_PMKID
		}
	}

	*messageList = append(*messageList, msgEntry)

	if msgNum == 1 || msgNum == 3 {
		if int(keyDataLen) > 0 && 99+int(keyDataLen) <= eapolLen {
			rsnData := extractRSNFromKeyData(eapolData[99 : 99+int(keyDataLen)])
			if rsnData != nil {
				pmkid := findPMKIDInRSNIE(rsnData)
				if pmkid != nil {
					pmkidEntry := PMKIDEntry{
						Timestamp: timestamp,
						Status:    PMKID_AP,
					}
					pmkidEntry.AP = apMAC
					pmkidEntry.Client = clientMAC
					copy(pmkidEntry.PMKID[:], pmkid)
					*pmkidList = append(*pmkidList, pmkidEntry)
					result.Stats.PMKIDCount++
				}
			}
		}
	}

	return msgNum
}

func processHandshakes(apList *[]APEntry, messageList *[]MessageEntry,
	handshakeList *[]HandshakeEntry, pmkidList *[]PMKIDEntry,
	result *ConversionResult) {

	sort.Slice(*messageList, func(i, j int) bool {
		return (*messageList)[i].Timestamp < (*messageList)[j].Timestamp
	})

	handshakeMap := make(map[string]*HandshakeEntry)

	for i := range *messageList {
		msg := &(*messageList)[i]
		key := fmt.Sprintf("%012x%012x", msg.AP, msg.Client)

		hs, exists := handshakeMap[key]
		if !exists {
			hs = &HandshakeEntry{}
			hs.AP = msg.AP
			hs.Client = msg.Client
			handshakeMap[key] = hs
		}

		hs.Timestamp = msg.Timestamp

		switch msg.Message {
		case 1:
			hs.MessageAP |= HS_M1
			if hs.MessageAP&HS_M3 == 0 {
				copy(hs.ANonce[:], msg.Nonce[:])
			}
		case 2:
			hs.MessageClient |= HS_M2
			if msg.EAPAuthLen > 0 && msg.EAPAuthLen <= EAPOL_AUTHLEN_MAX {
				hs.EAPAuthLenM2 = msg.EAPAuthLen
				copy(hs.EAPOLM2[:hs.EAPAuthLenM2], msg.EAPOL[:msg.EAPAuthLen])
			}
		case 3:
			hs.MessageAP |= HS_M3
			copy(hs.ANonce[:], msg.Nonce[:])
			if msg.EAPAuthLen > 0 && msg.EAPAuthLen <= EAPOL_AUTHLEN_MAX {
				hs.EAPAuthLen = msg.EAPAuthLen
				copy(hs.EAPOL[:msg.EAPAuthLen], msg.EAPOL[:msg.EAPAuthLen])
			}
		case 4:
			hs.MessageClient |= HS_M4
		}

		if msg.Status&HS_PMKID != 0 {
			copy(hs.PMKID[:], msg.PMKID[:])
		}
	}

	for _, hs := range handshakeMap {
		if hs.MessageAP == 0 || hs.MessageClient == 0 {
			continue
		}

		hs.Status = determineMessagePair(hs.MessageAP, hs.MessageClient) | ST_NC
		hasEAPOL := false
		pairType := hs.Status & 0x07
		if pairType == MESSAGE_PAIR_M12E2 || pairType == MESSAGE_PAIR_M14E4 {
			hasEAPOL = hs.EAPAuthLenM2 > 0
		} else {
			hasEAPOL = hs.EAPAuthLen > 0
		}
		if !hasEAPOL {
			continue
		}

		*handshakeList = append(*handshakeList, *hs)
		result.Stats.EAPOLMPCount++
	}

	result.Stats.EAPOLMPBestCount = result.Stats.EAPOLMPCount
}

func determineMessagePair(msgAP, msgClient uint8) uint8 {
	if msgAP&HS_M1 != 0 && msgClient&HS_M2 != 0 {
		return MESSAGE_PAIR_M12E2
	}
	if msgAP&HS_M3 != 0 && msgClient&HS_M2 != 0 {
		return MESSAGE_PAIR_M32E2
	}
	if msgAP&HS_M3 != 0 && msgClient&HS_M4 != 0 {
		return MESSAGE_PAIR_M34E3
	}
	if msgAP&HS_M1 != 0 && msgClient&HS_M4 != 0 {
		return MESSAGE_PAIR_M14E4
	}
	return MESSAGE_PAIR_M12E2
}

func parseIEs(data []byte) (essid []byte, essidLen uint8, rsnIE []byte) {
	offset := 0
	for offset+2 <= len(data) {
		elemID := data[offset]
		elemLen := int(data[offset+1])
		offset += 2

		if offset+elemLen > len(data) {
			break
		}

		switch elemID {
		case IEEE80211_ELEMID_SSID:
			if elemLen > 0 && elemLen <= ESSID_LEN_MAX {
				essidLen = uint8(elemLen)
				essid = make([]byte, elemLen)
				copy(essid, data[offset:offset+elemLen])
			}
		case IEEE80211_ELEMID_RSN:
			if elemLen > 0 {
				rsnIE = make([]byte, elemLen)
				copy(rsnIE, data[offset:offset+elemLen])
			}
		}

		offset += elemLen
	}
	return
}

func parseRSNIE(rsnIE []byte, ap *APEntry) {
	if len(rsnIE) < 2 {
		return
	}

	offset := 2
	if offset+4 <= len(rsnIE) {
		suite := rsnIE[offset : offset+4]
		if suite[0] == rsnOUI[0] && suite[1] == rsnOUI[1] && suite[2] == rsnOUI[2] {
			switch suite[3] {
			case 2:
				ap.Cipher = 2
			case 4:
				ap.Cipher = 4
			case 8:
				ap.Cipher = 8
			}
		}
		offset += 4
	}

	if offset+2 <= len(rsnIE) {
		pairwiseCount := int(binary.LittleEndian.Uint16(rsnIE[offset:]))
		offset += 2
		if pairwiseCount > 0 && offset+4 <= len(rsnIE) {
			suite := rsnIE[offset : offset+4]
			if suite[0] == rsnOUI[0] && suite[1] == rsnOUI[1] && suite[2] == rsnOUI[2] {
				switch suite[3] {
				case 2:
					ap.Cipher = 2
				case 4:
					ap.Cipher = 4
				}
			}
			offset += pairwiseCount * 4
		}
	}

	if offset+2 <= len(rsnIE) {
		authCount := int(binary.LittleEndian.Uint16(rsnIE[offset:]))
		offset += 2
		if authCount > 0 && offset+4 <= len(rsnIE) {
			suite := rsnIE[offset : offset+4]
			if suite[0] == rsnOUI[0] && suite[1] == rsnOUI[1] && suite[2] == rsnOUI[2] {
				switch suite[3] {
				case 2:
					ap.AKM = 2
				case 4:
					ap.AKM = 4
				case 6:
					ap.AKM = 6
				}
			}
			offset += authCount * 4
		}
	}

	if offset+2 <= len(rsnIE) {
		offset += 2
	}

	if offset+2 <= len(rsnIE) {
		pmkidCount := int(binary.LittleEndian.Uint16(rsnIE[offset:]))
		offset += 2
		_ = pmkidCount
	}
}

func getEAPOLMessageNum(keyInfo uint16, keyNonce [32]byte) uint8 {
	hasACK := (keyInfo & WPA_KEY_INFO_KEY_ACK) != 0
	hasMIC := (keyInfo & WPA_KEY_INFO_KEY_MIC) != 0
	hasInstall := (keyInfo & WPA_KEY_INFO_INSTALL) != 0
	hasNonce := false
	for _, b := range keyNonce {
		if b != 0 {
			hasNonce = true
			break
		}
	}

	if hasACK && !hasMIC && !hasInstall {
		return 1
	}
	if !hasACK && hasMIC && !hasInstall && hasNonce {
		return 2
	}
	if hasACK && hasMIC && hasInstall {
		return 3
	}
	if !hasACK && hasMIC && !hasInstall && !hasNonce {
		return 4
	}

	return 0
}

func findPMKIDInEAPOLKeyData(eapolData []byte, keyDataLen int, keyDataOffset int) []byte {
	if keyDataLen <= 0 || keyDataOffset+keyDataLen > len(eapolData) {
		return nil
	}

	kde := eapolData[keyDataOffset : keyDataOffset+keyDataLen]
	return findPMKIDInKDE(kde)
}

func findPMKIDInKDE(kde []byte) []byte {
	for offset := 0; offset+4 <= len(kde); {
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
		offset += 4 + kdeLen
	}
	return nil
}

func extractRSNFromKeyData(keyData []byte) []byte {
	for offset := 0; offset+1 < len(keyData); {
		elemID := keyData[offset]
		elemLen := int(keyData[offset+1])
		offset += 2
		if offset+elemLen > len(keyData) {
			break
		}
		if elemID == IEEE80211_ELEMID_RSN {
			rsn := make([]byte, elemLen)
			copy(rsn, keyData[offset:offset+elemLen])
			return rsn
		}
		offset += elemLen
	}
	return nil
}

func findPMKIDInRSNIE(rsnIE []byte) []byte {
	if len(rsnIE) < 2 {
		return nil
	}
	offset := 2
	if offset+4 <= len(rsnIE) {
		offset += 4
	}
	if offset+2 > len(rsnIE) {
		return nil
	}
	pairwiseCount := int(binary.LittleEndian.Uint16(rsnIE[offset:]))
	offset += 2 + pairwiseCount*4
	if offset+2 > len(rsnIE) {
		return nil
	}
	authCount := int(binary.LittleEndian.Uint16(rsnIE[offset:]))
	offset += 2 + authCount*4
	if offset+2 > len(rsnIE) {
		return nil
	}
	offset += 2
	if offset+2 > len(rsnIE) {
		return nil
	}
	pmkidCount := int(binary.LittleEndian.Uint16(rsnIE[offset:]))
	offset += 2
	if pmkidCount > 0 && offset+16 <= len(rsnIE) {
		pmkid := make([]byte, 16)
		copy(pmkid, rsnIE[offset:offset+16])
		return pmkid
	}
	return nil
}

func ConvertCapToHC22000File(inputFile, outputFile string) error {
	result, err := ConvertCapToHC22000(inputFile)
	if err != nil {
		return err
	}
	lines := FormatAllHashLinesString(result, false)
	return os.WriteFile(outputFile, []byte(lines), 0644)
}

func (s ConversionStats) String() string {
	return fmt.Sprintf(
		"Packets: total=%d beacon=%d eapol=%d eapol-mp=%d eapol-best=%d eapol-written=%d\n"+
			"PMKID: count=%d best=%d written=%d\n"+
			"Skipped: broadcast=%d packets=%d",
		s.RawPacketCount, s.BeaconCount, s.EAPOLMsgCount,
		s.EAPOLMPCount, s.EAPOLMPBestCount, s.EAPOLWrittenCount,
		s.PMKIDCount, s.PMKIDBestCount, s.PMKIDWrittenCount,
		s.BroadcastSkipCount, s.SkippedPacketCount,
	)
}