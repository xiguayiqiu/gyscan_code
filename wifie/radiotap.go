package wifie

import (
	"encoding/binary"
)

func ParseRadiotap(data []byte) (*RadiotapInfo, int) {
	if len(data) < 8 {
		return nil, 0
	}

	// Validate: Version must be 0x00, Pad must be 0x00, Length must be <= len(data)
	if data[0] != 0x00 || data[1] != 0x00 {
		return nil, 0
	}

	length := binary.LittleEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return nil, 0
	}

	info := &RadiotapInfo{
		Version: data[0],
		Pad:     data[1],
		Length:  length,
		Present: binary.LittleEndian.Uint32(data[4:8]),
	}

	offset := 8
	present := info.Present
	extIdx := 0

	for offset < int(info.Length) && offset < len(data) {
		for bit := 0; bit < 32; bit++ {
			if present&(1<<bit) == 0 {
				continue
			}

			switch bit {
			case RADIOTAP_TSFT:
				if offset+8 <= len(data) {
					info.TSFT = binary.LittleEndian.Uint64(data[offset:])
					offset += 8
				}
			case RADIOTAP_FLAGS:
				if offset < len(data) {
					info.Flags = data[offset]
					info.HasFCS = (info.Flags & RADIOTAP_F_FCS) != 0
					info.BadFCS = (info.Flags & RADIOTAP_F_BADFCS) != 0
					info.WEP = (info.Flags & RADIOTAP_F_WEP) != 0
					info.Frag = (info.Flags & RADIOTAP_F_FRAG) != 0
					offset++
				}
			case RADIOTAP_RATE:
				if offset < len(data) {
					info.Rate = data[offset]
					offset++
				}
			case RADIOTAP_CHANNEL:
				if offset+4 <= len(data) {
					info.Freq = int(binary.LittleEndian.Uint16(data[offset:]))
					info.ChannelFlags = binary.LittleEndian.Uint16(data[offset+2:])
					info.Channel = FreqToChannel(info.Freq)
					offset += 4
				}
			case RADIOTAP_DBM_ANTSIGNAL:
				if offset < len(data) {
					info.AntSignal = int8(data[offset])
					offset++
				}
			case RADIOTAP_DBM_ANTNOISE:
				if offset < len(data) {
					info.AntNoise = int8(data[offset])
					offset++
				}
			case RADIOTAP_ANTENNA:
				if offset < len(data) {
					info.Antenna = data[offset]
					offset++
				}
			case RADIOTAP_DB_ANTSIGNAL:
				if offset < len(data) {
					info.AntSignal = int8(data[offset])
					offset++
				}
			case RADIOTAP_DB_ANTNOISE:
				if offset < len(data) {
					info.AntNoise = int8(data[offset])
					offset++
				}
			case RADIOTAP_LOCK_QUALITY:
				if offset+2 <= len(data) {
					offset += 2
				}
			case RADIOTAP_TX_ATTENUATION:
				if offset+2 <= len(data) {
					offset += 2
				}
			case RADIOTAP_DB_TX_ATTENUATION:
				if offset+2 <= len(data) {
					offset += 2
				}
			case RADIOTAP_DBM_TX_POWER:
				if offset < len(data) {
					offset++
				}
			case RADIOTAP_FHSS:
				if offset+2 <= len(data) {
					offset += 2
				}
			case RADIOTAP_RX_FLAGS:
				if offset+2 <= len(data) {
					offset += 2
				}
			case RADIOTAP_TX_FLAGS:
				if offset+2 <= len(data) {
					offset += 2
				}
			case RADIOTAP_MCS:
				if offset+3 <= len(data) {
					known := data[offset]
					flag := data[offset+1]
					mcs := data[offset+2]
					offset += 3
					if known&0x01 != 0 {
						offset += 1
					}
					if known&0x02 != 0 {
						_ = mcs
					}
					if known&0x04 != 0 {
						_ = flag
					}
				}
			case RADIOTAP_AMPDU_STATUS:
				if offset+8 <= len(data) {
					offset += 8
				}
			case RADIOTAP_VHT:
				if offset+12 <= len(data) {
					offset += 12
				}
			case RADIOTAP_EXT:
				if offset+4 <= len(data) {
					present = binary.LittleEndian.Uint32(data[offset:])
					offset += 4
				}
				extIdx++
				if extIdx > 5 {
					return info, int(info.Length)
				}
			default:
				offset += 4
			}
		}

		if present&(1<<RADIOTAP_EXT) == 0 {
			break
		}
	}

	if info.Rate > 0 {
		info.DataRate = float64(info.Rate) * 0.5
	}

	return info, int(info.Length)
}
