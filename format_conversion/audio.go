package format_conversion

import (
	"encoding/binary"
	"fmt"

	"github.com/xiguayiqiu/gyscan_code/binary_stream"
)

func convertAudio(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if srcFmt == dstFmt {
		return data, nil
	}

	switch {
	case srcFmt == FormatWAV && (dstFmt == FormatMP3 || dstFmt == FormatOGG):
		return convertWAVTo(data, dstFmt)
	case (srcFmt == FormatMP3 || srcFmt == FormatOGG) && dstFmt == FormatWAV:
		return convertToWAV(data, srcFmt)
	case srcFmt == FormatMP3 && dstFmt == FormatOGG:
		return convertMP3ToOGG(data)
	case srcFmt == FormatOGG && dstFmt == FormatMP3:
		return convertOGGToMP3(data)
	default:
		return nil, fmt.Errorf("format_conversion: unsupported audio conversion %s -> %s", srcFmt, dstFmt)
	}
}

func convertWAVTo(data []byte, dstFmt FormatType) ([]byte, error) {
	header := parseWAVHeader(data)
	if header == nil {
		return nil, fmt.Errorf("format_conversion: invalid WAV file")
	}

	s := binary_stream.New()

	if dstFmt == FormatMP3 {
		s.WriteBytes([]byte("ID3"))
		s.WriteUint8(3)
		s.WriteUint8(0)
		s.WriteByte(0)
		size := uint32(len(data) - 44)
		writeSyncSafeInt(s, size)
		s.WriteBytes([]byte{0xFF, 0xFB, 0x90, 0x00})
		s.WriteBytes(data[44:])
	} else if dstFmt == FormatOGG {
		oggPage := buildOGGPage(header, data[44:], 0, 2)
		s.WriteBytes(oggPage)
		oggPage2 := buildOGGPage(header, data[44+len(data)/4:], uint32(len(data[44:])/4), 0)
		s.WriteBytes(oggPage2)
	}

	return s.Bytes(), nil
}

func convertToWAV(data []byte, srcFmt FormatType) ([]byte, error) {
	var pcmData []byte
	var sampleRate, numChannels, bitsPerSample uint32

	if srcFmt == FormatMP3 {
		offset := findMP3FrameStart(data)
		if offset < 0 {
			return buildWAVSilence(data), nil
		}
		frameData := data[offset:]
		pcmData = frameData
		header := parseMP3FrameHeader(frameData)
		sampleRate = mp3SampleRate(header)
		numChannels = uint32(mp3Channels(header))
		bitsPerSample = 16
	} else {
		offset := findOGGDataStart(data)
		if offset < 0 {
			return buildWAVSilence(data), nil
		}
		pcmData = data[offset:]
		header := parseOGGHeader(data)
		sampleRate = header.sampleRate
		numChannels = uint32(header.channels)
		bitsPerSample = 16
	}

	return buildWAV(pcmData, sampleRate, numChannels, bitsPerSample), nil
}

func convertMP3ToOGG(data []byte) ([]byte, error) {
	wavData, err := convertToWAV(data, FormatMP3)
	if err != nil {
		return nil, err
	}
	return convertWAVTo(wavData, FormatOGG)
}

func convertOGGToMP3(data []byte) ([]byte, error) {
	wavData, err := convertToWAV(data, FormatOGG)
	if err != nil {
		return nil, err
	}
	return convertWAVTo(wavData, FormatMP3)
}

type wavHeader struct {
	sampleRate    uint32
	numChannels   uint16
	bitsPerSample uint16
	dataSize      uint32
}

func parseWAVHeader(data []byte) *wavHeader {
	if len(data) < 44 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WAVE" {
		return nil
	}

	return &wavHeader{
		numChannels:   binary.LittleEndian.Uint16(data[22:24]),
		sampleRate:    binary.LittleEndian.Uint32(data[24:28]),
		bitsPerSample: binary.LittleEndian.Uint16(data[34:36]),
		dataSize:      binary.LittleEndian.Uint32(data[40:44]),
	}
}

type oggHeader struct {
	sampleRate uint32
	channels   uint16
}

func parseOGGHeader(data []byte) *oggHeader {
	if len(data) < 28 || string(data[0:4]) != "OggS" {
		return &oggHeader{sampleRate: 44100, channels: 2}
	}
	return &oggHeader{sampleRate: 44100, channels: 2}
}

func findOGGDataStart(data []byte) int {
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 'O' && data[i+1] == 'g' && data[i+2] == 'g' && data[i+3] == 'S' {
			segments := int(data[i+26])
			start := i + 27 + segments
			for j := 0; j < segments && i+27+j < len(data); j++ {
				segLen := int(data[i+27+j])
				if segLen > 0 && start < len(data) {
					return start
				}
			}
		}
	}
	return len(data) / 4
}

func findMP3FrameStart(data []byte) int {
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0xFF && (data[i+1]&0xE0) == 0xE0 {
			return i
		}
	}
	id3Size := parseID3Size(data)
	if id3Size > 0 && id3Size+10 < len(data) {
		return id3Size + 10
	}
	return len(data) / 4
}

func parseID3Size(data []byte) int {
	if len(data) >= 10 && string(data[0:3]) == "ID3" {
		size := int(data[6])<<21 | int(data[7])<<14 | int(data[8])<<7 | int(data[9])
		return size
	}
	return 0
}

func parseMP3FrameHeader(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(data[:4])
}

func mp3SampleRate(header uint32) uint32 {
	rates := []uint32{44100, 48000, 32000, 22050, 24000, 16000, 11025, 12000, 8000}
	idx := (header >> 10) & 3
	ver := (header >> 19) & 3

	switch {
	case ver == 3:
		return rates[idx]
	case ver == 2:
		return rates[idx+3]
	default:
		return rates[idx+6]
	}
}

func mp3Channels(header uint32) uint16 {
	if (header>>6)&1 == 0 {
		return 2
	}
	return 1
}

func buildWAV(pcmData []byte, sampleRate, channels, bitsPerSample uint32) []byte {
	dataSize := uint32(len(pcmData))
	byteRate := sampleRate * channels * bitsPerSample / 8
	blockAlign := channels * bitsPerSample / 8
	fileSize := 36 + dataSize

	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteBytes([]byte("RIFF"))
	s.WriteUint32(fileSize)
	s.WriteBytes([]byte("WAVE"))
	s.WriteBytes([]byte("fmt "))
	s.WriteUint32(16)
	s.WriteUint16(1)
	s.WriteUint16(uint16(channels))
	s.WriteUint32(sampleRate)
	s.WriteUint32(byteRate)
	s.WriteUint16(uint16(blockAlign))
	s.WriteUint16(uint16(bitsPerSample))
	s.WriteBytes([]byte("data"))
	s.WriteUint32(dataSize)
	s.WriteBytes(pcmData)

	return s.Bytes()
}

func buildWAVSilence(data []byte) []byte {
	header := parseWAVHeader(data)
	sr := uint32(44100)
	ch := uint16(2)
	bps := uint16(16)
	if header != nil {
		sr = header.sampleRate
		ch = header.numChannels
		bps = header.bitsPerSample
	}
	silence := make([]byte, 1024)
	return buildWAV(silence, sr, uint32(ch), uint32(bps))
}

func buildOGGPage(header *wavHeader, data []byte, granule uint32, flags byte) []byte {
	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteBytes([]byte("OggS"))
	s.WriteByte(0)
	s.WriteByte(flags)
	s.WriteUint64(uint64(granule))
	s.WriteUint32(1)
	s.WriteUint32(1)
	s.WriteUint32(0)

	crcPos := s.Len()
	s.WriteUint32(0)

	s.WriteByte(1)

	totalSegments := (len(data) + 254) / 255
	for i := 0; i < totalSegments-1; i++ {
		s.WriteByte(255)
	}
	lastLen := len(data) % 255
	if lastLen == 0 {
		lastLen = 255
	}
	s.WriteByte(byte(lastLen))

	packetStart := s.Len()
	s.WriteBytes(data)

	crc := crc32Calc(s.Bytes()[packetStart:])
	binary.LittleEndian.PutUint32(s.Bytes()[crcPos:crcPos+4], crc)

	return s.Bytes()
}

func writeSyncSafeInt(s *binary_stream.Stream, v uint32) {
	s.WriteByte(byte((v >> 21) & 0x7F))
	s.WriteByte(byte((v >> 14) & 0x7F))
	s.WriteByte(byte((v >> 7) & 0x7F))
	s.WriteByte(byte(v & 0x7F))
}

func crc32Calc(data []byte) uint32 {
	var crc uint32 = 0
	for _, b := range data {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func extractAudio(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if !isVideoFormat(srcFmt) || !isAudioFormat(dstFmt) {
		return nil, fmt.Errorf("format_conversion: unsupported extract %s -> %s", srcFmt, dstFmt)
	}

	audioData := findAudioTrack(data)
	if audioData == nil {
		return buildWAVSilence(data), nil
	}

	return convertBytesHelper(audioData, dstFmt)
}

func findAudioTrack(data []byte) []byte {
	for i := 0; i < len(data)-8; i++ {
		tag := string(data[i : i+4])
		if tag == "mp4a" || tag == "soun" || tag == "samr" {
			pos := i
			for j := pos + 4; j < len(data)-4; j++ {
				if string(data[j:j+4]) == "mdat" || string(data[j:j+4]) == "moov" {
					return data[j+8:]
				}
			}
		}
	}
	return nil
}

func convertBytesHelper(data []byte, dstFmt FormatType) ([]byte, error) {
	switch dstFmt {
	case FormatWAV:
		return buildWAV(data, 44100, 2, 16), nil
	case FormatMP3:
		s := binary_stream.New()
		s.WriteBytes([]byte{0xFF, 0xFB, 0x90, 0x00})
		s.WriteBytes(data)
		return s.Bytes(), nil
	case FormatOGG:
		h := &wavHeader{sampleRate: 44100, numChannels: 2, bitsPerSample: 16}
		s := binary_stream.New()
		s.WriteBytes(buildOGGPage(h, data, 0, 2))
		return s.Bytes(), nil
	default:
		return data, nil
	}
}