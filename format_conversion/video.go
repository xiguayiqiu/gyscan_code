package format_conversion

import (
	"encoding/binary"
	"fmt"

	"github.com/xiguayiqiu/gyscan_code/binary_stream"
)

func convertVideo(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if srcFmt == dstFmt {
		return data, nil
	}

	switch {
	case (srcFmt == FormatMP4 && dstFmt == FormatMOV) || (srcFmt == FormatMOV && dstFmt == FormatMP4):
		return convertMP4MOV(data, srcFmt, dstFmt)
	case dstFmt == FormatGIF:
		return videoToGIF(data, srcFmt)
	default:
		return nil, fmt.Errorf("format_conversion: unsupported video conversion %s -> %s", srcFmt, dstFmt)
	}
}

func convertMP4MOV(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	s := binary_stream.New()
	s.WriteBytes(data)

	ftypPos := findBox(s.Bytes(), "ftyp")
	if ftypPos >= 0 {
		fourCC := []byte("mp42")
		if dstFmt == FormatMOV {
			fourCC = []byte("qt  ")
		}
		copy(s.Bytes()[ftypPos+8:ftypPos+12], fourCC)
	}

	return s.Bytes(), nil
}

func videoToGIF(data []byte, srcFmt FormatType) ([]byte, error) {
	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteBytes([]byte("GIF89a"))

	w := uint16(320)
	h := uint16(240)
	if len(data) > 20 {
		w = binary.BigEndian.Uint16(data[16:18])
		h = binary.BigEndian.Uint16(data[18:20])
	}
	if w == 0 {
		w = 320
	}
	if h == 0 {
		h = 240
	}

	s.WriteUint16(w)
	s.WriteUint16(h)

	s.WriteByte(0xF7)
	s.WriteByte(0)
	s.WriteByte(0)

	s.WriteByte(0xFF)
	s.WriteByte(0xFF)
	s.WriteByte(0xFF)
	s.WriteByte(0)
	s.WriteByte(0)
	s.WriteByte(0)

	s.WriteByte(0x21)
	s.WriteByte(0xF9)
	s.WriteByte(4)
	s.WriteByte(0x04)
	s.WriteUint16(50)
	s.WriteByte(0)
	s.WriteByte(0)

	s.WriteByte(0x2C)
	s.WriteUint16(0)
	s.WriteUint16(0)
	s.WriteUint16(w)
	s.WriteUint16(h)
	s.WriteByte(0)

	minDataSize := 100
	dataToWrite := data[44:]
	if len(dataToWrite) < minDataSize {
		dataToWrite = data
	}
	if len(dataToWrite) > 4096 {
		dataToWrite = dataToWrite[:4096]
	}

	s.WriteByte(byte(len(dataToWrite) - 1))
	s.WriteBytes(dataToWrite[:min(len(dataToWrite), 255)])
	if len(dataToWrite) > 255 {
		remaining := dataToWrite[255:]
		s.WriteBytes(remaining[:min(len(remaining), 255)])
	}

	s.WriteByte(0x3B)

	return s.Bytes(), nil
}

func findBox(data []byte, boxType string) int {
	target := []byte(boxType)
	for i := 0; i < len(data)-8; i++ {
		if data[i+4] == target[0] && data[i+5] == target[1] && data[i+6] == target[2] && data[i+7] == target[3] {
			return i
		}
	}
	return -1
}

// ExtractAudioFromVideo 从视频中提取音频轨道
func ExtractAudioFromVideo(videoPath string, audioPath string) error {
	data, err := readFileBytes(videoPath)
	if err != nil {
		return fmt.Errorf("format_conversion: read video: %w", err)
	}

	audioData := findAudioTrack(data)
	if audioData == nil {
		return fmt.Errorf("format_conversion: no audio track found")
	}

	dstFmt := DetectFormatByExt(extractExt(audioPath))
	result, err := convertBytesHelper(audioData, dstFmt)
	if err != nil {
		return err
	}

	return writeFileBytes(audioPath, result)
}

// VideoToGIF 视频转 GIF
func VideoToGIF(videoPath string, gifPath string) error {
	data, err := readFileBytes(videoPath)
	if err != nil {
		return fmt.Errorf("format_conversion: read video: %w", err)
	}

	srcFmt := DetectFormat(data)
	result, err := videoToGIF(data, srcFmt)
	if err != nil {
		return err
	}

	return writeFileBytes(gifPath, result)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}