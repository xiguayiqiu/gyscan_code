package wifie

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

const (
	PCAP_MAGIC        = 0xa1b2c3d4
	PCAP_SWAPPED_MAGIC = 0xd4c3b2a1
)

func OpenPcapFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func ParsePcapHeader(data []byte) (*PcapHeader, int, error) {
	if len(data) < 24 {
		return nil, 0, fmt.Errorf("wifie: data too short for pcap header")
	}

	hdr := &PcapHeader{
		MagicNumber:  binary.LittleEndian.Uint32(data[0:4]),
		VersionMajor: binary.LittleEndian.Uint16(data[4:6]),
		VersionMinor: binary.LittleEndian.Uint16(data[6:8]),
		ThisZone:     int32(binary.LittleEndian.Uint32(data[8:12])),
		SigFigs:      binary.LittleEndian.Uint32(data[12:16]),
		SnapLen:      binary.LittleEndian.Uint32(data[16:20]),
		Network:      binary.LittleEndian.Uint32(data[20:24]),
	}

	return hdr, 24, nil
}

func ReadPcapRecord(data []byte, offset int) (*PcapRecord, []byte, int, error) {
	if offset+16 > len(data) {
		return nil, nil, offset, fmt.Errorf("wifie: data too short for pcap record header")
	}

	rec := &PcapRecord{
		Seconds:      int64(binary.LittleEndian.Uint32(data[offset:])),
		Microseconds: int64(binary.LittleEndian.Uint32(data[offset+4:])),
		CapturedLen:  int32(binary.LittleEndian.Uint32(data[offset+8:])),
		OriginalLen:  int32(binary.LittleEndian.Uint32(data[offset+12:])),
	}

	offset += 16
	if offset+int(rec.CapturedLen) > len(data) {
		return nil, nil, offset, fmt.Errorf("wifie: data too short for pcap record")
	}

	packet := make([]byte, rec.CapturedLen)
	copy(packet, data[offset:offset+int(rec.CapturedLen)])
	offset += int(rec.CapturedLen)

	return rec, packet, offset, nil
}

func ParsePcapFile(data []byte, linktype int, callback func(*Frame80211, time.Time) error) error {
	hdr, offset, err := ParsePcapHeader(data)
	if err != nil {
		return err
	}

	_ = hdr

	for offset < len(data) {
		rec, packet, newOffset, err := ReadPcapRecord(data, offset)
		if err != nil {
			break
		}
		offset = newOffset

		ts := time.Unix(rec.Seconds, rec.Microseconds*1000)

		var frame *Frame80211
		if linktype == LINKTYPE_IEEE802_11_RADIOTAP {
			rtInfo, rtLen := ParseRadiotap(packet)
			if rtInfo != nil && rtLen > 0 && rtLen < len(packet) {
				frame, err = ParseFrame80211(packet[rtLen:])
				if frame != nil {
					frame.Radiotap = rtInfo
				}
			}
		} else {
			frame, err = ParseFrame80211(packet)
		}
		if err != nil || frame == nil {
			continue
		}

		if err := callback(frame, ts); err != nil {
			return err
		}
	}

	return nil
}

func WritePcapHeader(f *os.File, network uint32) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], PCAP_MAGIC)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[8:], 0)
	binary.LittleEndian.PutUint32(hdr[12:], 0)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], network)
	_, err := f.Write(hdr)
	return err
}

func WritePcapRecord(f *os.File, packet []byte, ts time.Time) error {
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(packet)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(packet)))
	if _, err := f.Write(rec); err != nil {
		return err
	}
	_, err := f.Write(packet)
	return err
}

func WritePcapFrame(f *os.File, frame *Frame80211, ts time.Time, linktype uint32) error {
	var packet []byte

	if linktype == LINKTYPE_IEEE802_11_RADIOTAP {
		rtap := BuildRadiotapHeader(frame)
		packet = append(rtap, frame.Raw...)
	} else {
		packet = frame.Raw
	}

	return WritePcapRecord(f, packet, ts)
}

func BuildRadiotapHeader(frame *Frame80211) []byte {
	buf := make([]byte, 36)
	
	buf[0] = 0
	buf[1] = 0
	binary.LittleEndian.PutUint16(buf[2:], 36)
	
	present := uint32(0)
	present |= 1 << RADIOTAP_FLAGS
	present |= 1 << RADIOTAP_CHANNEL
	present |= 1 << RADIOTAP_DBM_ANTSIGNAL
	
	binary.LittleEndian.PutUint32(buf[4:], present)
	
	buf[8] = 0x00
	
	offset := 12
	if frame.Radiotap != nil {
		freq := uint16(frame.Radiotap.Freq)
		if freq == 0 {
			freq = uint16(FreqFromChannel(frame.Radiotap.Channel))
		}
		binary.LittleEndian.PutUint16(buf[offset:], freq)
		binary.LittleEndian.PutUint16(buf[offset+2:], RADIOTAP_CHAN_2GHZ|RADIOTAP_CHAN_OFDM)
		offset += 4
		
		buf[offset] = byte(frame.Radiotap.AntSignal)
		offset++
	}
	
	return buf[:offset]
}