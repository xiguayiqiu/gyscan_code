package format_conversion

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	ffmpeg "github.com/u2takey/ffmpeg-go"
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
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil, fmt.Errorf("format_conversion: ffmpeg not found.\nInstall: sudo apt install ffmpeg  (Linux)\n        brew install ffmpeg      (macOS)\n        winget install ffmpeg    (Windows)")
	}

	tmpDir, err := os.MkdirTemp("", "formatconv_*")
	if err != nil {
		return nil, fmt.Errorf("format_conversion: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	ext := formatExtensions[srcFmt][0]
	srcPath := filepath.Join(tmpDir, "input"+ext)
	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		return nil, fmt.Errorf("format_conversion: write temp file: %w", err)
	}

	dstPath := filepath.Join(tmpDir, "output.gif")

	err = ffmpeg.Input(srcPath).
		Output(dstPath, ffmpeg.KwArgs{
			"vf":     "fps=10,scale=320:-1:flags=lanczos",
			"loop":   "0",
		}).
		OverWriteOutput().
		Run()
	if err != nil {
		return nil, fmt.Errorf("format_conversion: ffmpeg conversion failed: %w", err)
	}

	result, err := os.ReadFile(dstPath)
	if err != nil {
		return nil, fmt.Errorf("format_conversion: read output gif: %w", err)
	}

	return result, nil
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
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return fmt.Errorf("format_conversion: ffmpeg not found.\nInstall: sudo apt install ffmpeg  (Linux)\n        brew install ffmpeg      (macOS)\n        winget install ffmpeg    (Windows)")
	}

	return ffmpeg.Input(videoPath).
		Output(audioPath, ffmpeg.KwArgs{"vn": ""}).
		OverWriteOutput().
		Run()
}

// VideoToGIF 视频转 GIF
func VideoToGIF(videoPath string, gifPath string) error {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return fmt.Errorf("format_conversion: ffmpeg not found.\nInstall: sudo apt install ffmpeg  (Linux)\n        brew install ffmpeg      (macOS)\n        winget install ffmpeg    (Windows)")
	}

	return ffmpeg.Input(videoPath).
		Output(gifPath, ffmpeg.KwArgs{
			"vf":   "fps=10,scale=320:-1:flags=lanczos",
			"loop": "0",
		}).
		OverWriteOutput().
		Run()
}