package format_conversion

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	ffmpeg "github.com/u2takey/ffmpeg-go"
)

func convertAudio(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if srcFmt == dstFmt {
		return data, nil
	}

	return convertWithFFmpeg(data, srcFmt, dstFmt, nil)
}

func extractAudio(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if !isVideoFormat(srcFmt) || !isAudioFormat(dstFmt) {
		return nil, fmt.Errorf("format_conversion: unsupported extract %s -> %s", srcFmt, dstFmt)
	}

	return convertWithFFmpeg(data, srcFmt, dstFmt, ffmpeg.KwArgs{"vn": ""})
}

func convertWithFFmpeg(data []byte, srcFmt, dstFmt FormatType, extraKwArgs ffmpeg.KwArgs) ([]byte, error) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil, fmt.Errorf("format_conversion: ffmpeg not found, conversion requires ffmpeg.\nInstall: sudo apt install ffmpeg  (Linux)\n        brew install ffmpeg      (macOS)\n        winget install ffmpeg    (Windows)")
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

	outExt := formatExtensions[dstFmt][0]
	dstPath := filepath.Join(tmpDir, "output"+outExt)

	outputKwArgs := ffmpeg.KwArgs{}
	if extraKwArgs != nil {
		for k, v := range extraKwArgs {
			outputKwArgs[k] = v
		}
	}

	if err := ffmpeg.Input(srcPath).Output(dstPath, outputKwArgs).OverWriteOutput().Run(); err != nil {
		return nil, fmt.Errorf("format_conversion: ffmpeg conversion failed: %w", err)
	}

	result, err := os.ReadFile(dstPath)
	if err != nil {
		return nil, fmt.Errorf("format_conversion: read output: %w", err)
	}

	return result, nil
}