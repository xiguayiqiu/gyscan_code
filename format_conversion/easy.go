package format_conversion

import (
	"fmt"
	"os"
)

// ImageConvert 图片格式转换便捷函数
func ImageConvert(srcPath, dstPath string) error {
	return ConvertFile(srcPath, dstPath)
}

// AudioConvert 音频格式转换便捷函数
func AudioConvert(srcPath, dstPath string) error {
	return ConvertFile(srcPath, dstPath)
}

// VideoConvert 视频格式转换便捷函数
func VideoConvert(srcPath, dstPath string) error {
	return ConvertFile(srcPath, dstPath)
}

// DocumentConvert 文档格式转换便捷函数
func DocumentConvert(srcPath, dstPath string) error {
	return ConvertFile(srcPath, dstPath)
}

// IsPandocAvailable 检查 pandoc 是否已安装
func IsPandocAvailable() bool {
	return isPandocAvailable()
}

// Convert 通用格式转换
func Convert(srcPath, dstPath string) error {
	return ConvertFile(srcPath, dstPath)
}

// BatchConvert 批量转换同目录下相同扩展名的文件
func BatchConvert(dir, srcExt, dstExt string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("format_conversion: read dir %s: %w", dir, err)
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if extractExt(name) == srcExt {
			srcPath := dir + "/" + name
			base := name[:len(name)-len(srcExt)]
			dstPath := dir + "/" + base + dstExt
			if err := ConvertFile(srcPath, dstPath); err != nil {
				return fmt.Errorf("format_conversion: convert %s: %w", name, err)
			}
			count++
		}
	}

	fmt.Printf("format_conversion: batch converted %d files %s -> %s\n", count, srcExt, dstExt)
	return nil
}

// GetFormat 获取文件格式类型
func GetFormat(path string) FormatType {
	data, err := os.ReadFile(path)
	if err != nil {
		return DetectFormatByExt(extractExt(path))
	}
	return DetectFormat(data)
}

// GetFormatName 获取文件格式名称
func GetFormatName(path string) string {
	return GetFormat(path).String()
}

// SupportedFormats 返回所有支持的格式列表
func SupportedFormats() []string {
	return []string{
		"PNG", "JPG/JPEG", "BMP", "ICO", "WEBP", "GIF",
		"WAV", "MP3", "OGG",
		"MP4", "MOV",
		"Markdown", "DOC", "DOCX", "ODT", "HTML", "RTF", "PDF", "TXT",
	}
}

// SupportedConversions 返回支持的转换列表
func SupportedConversions() []string {
	return []string{
		"PNG ↔ BMP",
		"PNG → JPG",
		"JPG → PNG",
		"PNG/JPG → ICO",
		"PNG/JPG → WEBP",
		"WAV → MP3/OGG",
		"MP3/OGG → WAV",
		"MP3 ↔ OGG",
		"MP4 ↔ MOV",
		"MP4/MOV → GIF",
		"Video → Audio",
"Markdown ↔ DOCX/ODT/HTML/RTF/TXT",
		"Markdown → PDF (需要 wkhtmltopdf/weasyprint 等 PDF 引擎)",
		"DOC → DOCX/ODT/HTML/RTF/TXT",
		"DOCX ↔ ODT/HTML/RTF/TXT",
		"HTML ↔ TXT/RTF",
		"PDF → TXT",
	}
}