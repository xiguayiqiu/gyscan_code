package format_conversion

import (
	"bytes"
	"fmt"
)

type FormatType int

const (
	FormatUnknown FormatType = iota
	FormatPNG
	FormatJPG
	FormatBMP
	FormatICO
	FormatWEBP
	FormatWAV
	FormatMP3
	FormatOGG
	FormatMP4
	FormatMOV
	FormatGIF
)

var formatNames = map[FormatType]string{
	FormatPNG:  "PNG",
	FormatJPG:  "JPG",
	FormatBMP:  "BMP",
	FormatICO:  "ICO",
	FormatWEBP: "WEBP",
	FormatWAV:  "WAV",
	FormatMP3:  "MP3",
	FormatOGG:  "OGG",
	FormatMP4:  "MP4",
	FormatMOV:  "MOV",
	FormatGIF:  "GIF",
}

var formatExtensions = map[FormatType][]string{
	FormatPNG:  {".png"},
	FormatJPG:  {".jpg", ".jpeg"},
	FormatBMP:  {".bmp"},
	FormatICO:  {".ico"},
	FormatWEBP: {".webp"},
	FormatWAV:  {".wav", ".wave"},
	FormatMP3:  {".mp3"},
	FormatOGG:  {".ogg", ".oga"},
	FormatMP4:  {".mp4"},
	FormatMOV:  {".mov"},
	FormatGIF:  {".gif"},
}

func (f FormatType) String() string {
	if name, ok := formatNames[f]; ok {
		return name
	}
	return "UNKNOWN"
}

// DetectFormat 通过文件头魔数检测格式
func DetectFormat(data []byte) FormatType {
	if len(data) < 4 {
		return FormatUnknown
	}

	switch {
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}):
		return FormatPNG
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return FormatJPG
	case bytes.HasPrefix(data, []byte{0x42, 0x4D}):
		return FormatBMP
	case bytes.HasPrefix(data, []byte{0x00, 0x00, 0x01, 0x00}):
		return FormatICO
	case bytes.HasPrefix(data, []byte("RIFF")) && len(data) >= 12 &&
		bytes.HasPrefix(data[8:], []byte("WEBP")):
		return FormatWEBP
	case bytes.HasPrefix(data, []byte("RIFF")) && len(data) >= 12 &&
		bytes.HasPrefix(data[8:], []byte("WAVE")):
		return FormatWAV
	case bytes.HasPrefix(data, []byte{0xFF, 0xFB}) ||
		bytes.HasPrefix(data, []byte("ID3")):
		return FormatMP3
	case bytes.HasPrefix(data, []byte("OggS")):
		return FormatOGG
	case len(data) >= 8 && data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70:
		return FormatMP4
	case bytes.HasPrefix(data, []byte{0x00, 0x00, 0x00}) && len(data) >= 8 &&
		isMOVBrand(data[4:8]):
		return FormatMOV
	case bytes.HasPrefix(data, []byte("GIF8")):
		return FormatGIF
	}
	return FormatUnknown
}

func isMOVBrand(b []byte) bool {
	brands := [][]byte{
		[]byte("moov"), []byte("mdat"), []byte("ftyp"),
		[]byte("free"), []byte("skip"), []byte("wide"),
	}
	for _, brand := range brands {
		if bytes.Equal(b, brand) {
			return true
		}
	}
	return false
}

// DetectFormatByExt 通过文件扩展名检测格式
func DetectFormatByExt(ext string) FormatType {
	for ft, exts := range formatExtensions {
		for _, e := range exts {
			if e == ext {
				return ft
			}
		}
	}
	return FormatUnknown
}

// ConvertResult 转换结果
type ConvertResult struct {
	Data       []byte
	FormatType FormatType
	Error      error
}

// ConvertFile 文件格式转换入口
func ConvertFile(srcPath string, dstPath string) error {
	srcFormat := DetectFormatByExt(extractExt(srcPath))
	dstFormat := DetectFormatByExt(extractExt(dstPath))
	if srcFormat == FormatUnknown || dstFormat == FormatUnknown {
		return fmt.Errorf("format_conversion: unsupported format conversion: %s -> %s", extractExt(srcPath), extractExt(dstPath))
	}
	return ConvertFileByType(srcPath, dstPath, srcFormat, dstFormat)
}

// ConvertFileByType 按指定类型转换文件
func ConvertFileByType(srcPath, dstPath string, srcFmt, dstFmt FormatType) error {
	srcData, err := readFileBytes(srcPath)
	if err != nil {
		return fmt.Errorf("format_conversion: %w", err)
	}
	result, err := ConvertBytes(srcData, srcFmt, dstFmt)
	if err != nil {
		return err
	}
	return writeFileBytes(dstPath, result)
}

// ConvertBytes 字节级格式转换
func ConvertBytes(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	detected := DetectFormat(data)
	if detected != FormatUnknown && detected != srcFmt {
		srcFmt = detected
	}

	switch {
	case isImageFormat(srcFmt) && isImageFormat(dstFmt):
		return convertImage(data, srcFmt, dstFmt)
	case isAudioFormat(srcFmt) && isAudioFormat(dstFmt):
		return convertAudio(data, srcFmt, dstFmt)
	case isVideoFormat(srcFmt) && isVideoFormat(dstFmt):
		return convertVideo(data, srcFmt, dstFmt)
	case isVideoFormat(srcFmt) && isAudioFormat(dstFmt):
		return extractAudio(data, srcFmt, dstFmt)
	default:
		return nil, fmt.Errorf("format_conversion: unsupported conversion %s -> %s", srcFmt, dstFmt)
	}
}

func isImageFormat(f FormatType) bool {
	switch f {
	case FormatPNG, FormatJPG, FormatBMP, FormatICO, FormatWEBP, FormatGIF:
		return true
	}
	return false
}

func isAudioFormat(f FormatType) bool {
	switch f {
	case FormatWAV, FormatMP3, FormatOGG:
		return true
	}
	return false
}

func isVideoFormat(f FormatType) bool {
	switch f {
	case FormatMP4, FormatMOV:
		return true
	}
	return false
}

func extractExt(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	return ""
}