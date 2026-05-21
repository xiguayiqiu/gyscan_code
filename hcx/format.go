package hcx

import (
	"fmt"
	"strings"
)

func FormatPMKIDHash(entry PMKIDEntry, essid []byte, addTimestamp bool) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("WPA*%02d*", HCX_TYPE_PMKID))
	sb.WriteString(fmt.Sprintf("%032x*", entry.PMKID[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.AP[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.Client[:]))
	sb.WriteString(fmt.Sprintf("%x***", essid))
	sb.WriteString(fmt.Sprintf("%02x", entry.Status))

	if addTimestamp {
		sb.WriteString(fmt.Sprintf("\t%d", entry.Timestamp))
	}
	sb.WriteString("\n")

	return sb.String()
}

func FormatPMKIDFTPSKHash(entry PMKIDEntry, essid []byte, addTimestamp bool) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("WPA*%02d*", HCX_TYPE_PMKID_FTPSK))
	sb.WriteString(fmt.Sprintf("%032x*", entry.PMKID[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.AP[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.Client[:]))
	sb.WriteString(fmt.Sprintf("%x***", essid))
	sb.WriteString(fmt.Sprintf("%02x*", entry.Status&PMKID_CLIENT_FTPSK))
	sb.WriteString(fmt.Sprintf("%04x*", entry.MDID))
	sb.WriteString(fmt.Sprintf("%x*", entry.R0KHID[:entry.R0KHIDLen]))
	sb.WriteString(fmt.Sprintf("%x", entry.R1KHID[:entry.R1KHIDLen]))

	if addTimestamp {
		sb.WriteString(fmt.Sprintf("\t%d", entry.Timestamp))
	}
	sb.WriteString("\n")

	return sb.String()
}

func FormatEAPOLHash(entry HandshakeEntry, essid []byte, mic [16]byte, eapolData []byte, addTimestamp bool) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("WPA*%02d*", HCX_TYPE_EAPOL))
	sb.WriteString(fmt.Sprintf("%032x*", mic[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.AP[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.Client[:]))
	sb.WriteString(fmt.Sprintf("%x*", essid))
	sb.WriteString(fmt.Sprintf("%064x*", entry.ANonce[:]))
	sb.WriteString(fmt.Sprintf("%x*", eapolData))
	sb.WriteString(fmt.Sprintf("%02x", entry.Status))

	if addTimestamp {
		sb.WriteString(fmt.Sprintf("\t%d", entry.Timestamp))
	}
	sb.WriteString("\n")

	return sb.String()
}

func FormatEAPOLFTPSKHash(entry HandshakeEntry, essid []byte, mic [16]byte, eapolData []byte, addTimestamp bool) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("WPA*%02d*", HCX_TYPE_EAPOL_FTPSK))
	sb.WriteString(fmt.Sprintf("%032x*", mic[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.AP[:]))
	sb.WriteString(fmt.Sprintf("%012x*", entry.Client[:]))
	sb.WriteString(fmt.Sprintf("%x*", essid))
	sb.WriteString(fmt.Sprintf("%064x*", entry.ANonce[:]))
	sb.WriteString(fmt.Sprintf("%x*", eapolData))
	sb.WriteString(fmt.Sprintf("%02x*", entry.Status))
	sb.WriteString(fmt.Sprintf("%04x*", entry.MDID))
	sb.WriteString(fmt.Sprintf("%x*", entry.R0KHID[:entry.R0KHIDLen]))
	sb.WriteString(fmt.Sprintf("%x", entry.R1KHID[:entry.R1KHIDLen]))

	if addTimestamp {
		sb.WriteString(fmt.Sprintf("\t%d", entry.Timestamp))
	}
	sb.WriteString("\n")

	return sb.String()
}

func FormatAllHashLines(result *ConversionResult, addTimestamp bool) []string {
	var lines []string

	apMap := buildAPMap(result.APs)

	for i := range result.Handshakes {
		hs := &result.Handshakes[i]
		if hs.AP == nullMAC || hs.AP == broadcastMAC {
			continue
		}
		if hs.Client == nullMAC || hs.Client == broadcastMAC {
			continue
		}

		essid, found := findESSID(apMap, hs.AP)
		if !found {
			continue
		}

		useM2 := ((hs.Status & 0x07) == MESSAGE_PAIR_M12E2 || (hs.Status & 0x07) == MESSAGE_PAIR_M14E4)
		var eapAuthLen uint16
		var eapolData []byte
		if useM2 {
			eapAuthLen = hs.EAPAuthLenM2
			eapolData = hs.EAPOLM2[:eapAuthLen]
		} else {
			eapAuthLen = hs.EAPAuthLen
			eapolData = hs.EAPOL[:eapAuthLen]
		}

		if int(eapAuthLen) <= EAPOL_AUTHLEN_OLD {
			wpakOff := 4
			micOffset := wpakOff + 77
			if micOffset+16 <= int(eapAuthLen) {
				mic := [16]byte{}
				copy(mic[:], eapolData[micOffset:micOffset+16])

				eapolClean := make([]byte, eapAuthLen)
				copy(eapolClean, eapolData)
				for j := micOffset; j < micOffset+16 && j < len(eapolClean); j++ {
					eapolClean[j] = 0
				}

				line := FormatEAPOLHash(*hs, essid, mic, eapolClean, addTimestamp)
				lines = append(lines, line)
			}
		}
	}

	for i := range result.PMKIDs {
		pmkid := &result.PMKIDs[i]
		if pmkid.AP == nullMAC || pmkid.AP == broadcastMAC {
			continue
		}

		essid, found := findESSID(apMap, pmkid.AP)
		if !found {
			continue
		}

		if pmkid.MDIDLen != 0 && pmkid.R0KHIDLen != 0 && pmkid.R1KHIDLen != 0 {
			line := FormatPMKIDFTPSKHash(*pmkid, essid, addTimestamp)
			lines = append(lines, line)
		} else if pmkid.Status&PMKID_AP != 0 || pmkid.Status&PMKID_APPSK256 != 0 {
			line := FormatPMKIDHash(*pmkid, essid, addTimestamp)
			lines = append(lines, line)
		}
	}

	return lines
}

func FormatAllHashLinesString(result *ConversionResult, addTimestamp bool) string {
	lines := FormatAllHashLines(result, addTimestamp)
	var sb strings.Builder
	for _, line := range lines {
		sb.WriteString(line)
	}
	return sb.String()
}

func buildAPMap(aps []APEntry) map[[6]byte][]byte {
	apMap := make(map[[6]byte][]byte)
	for i := range aps {
		ap := &aps[i]
		if ap.ESSIDLen == 0 || ap.ESSIDLen > ESSID_LEN_MAX {
			continue
		}
		if ap.ESSID[0] == 0 {
			continue
		}
		existing, ok := apMap[ap.Addr]
		if !ok || ap.Count > 0 {
			essid := make([]byte, ap.ESSIDLen)
			copy(essid, ap.ESSID[:ap.ESSIDLen])
			apMap[ap.Addr] = essid
		}
		_ = existing
	}
	return apMap
}

func findESSID(apMap map[[6]byte][]byte, mac [6]byte) ([]byte, bool) {
	essid, ok := apMap[mac]
	return essid, ok
}