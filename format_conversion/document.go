package format_conversion

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func convertDocument(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if srcFmt == dstFmt {
		return data, nil
	}

	if !isPandocAvailable() {
		return nil, fmt.Errorf("format_conversion: pandoc is not installed, please install pandoc first")
	}

	tmpDir, err := os.MkdirTemp("", "docconv_*")
	if err != nil {
		return nil, fmt.Errorf("format_conversion: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	srcExt := getFormatExtension(srcFmt)
	dstExt := getFormatExtension(dstFmt)

	srcPath := filepath.Join(tmpDir, "src"+srcExt)
	dstPath := filepath.Join(tmpDir, "dst"+dstExt)

	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		return nil, fmt.Errorf("format_conversion: write temp file: %w", err)
	}

	srcFormat := getPandocInputFormat(srcFmt)
	dstFormat, err := getPandocOutputFormat(dstFmt)
	if err != nil {
		return nil, err
	}

	args := []string{"-f", srcFormat, "-t", dstFormat, "-o", dstPath, srcPath}
	if dstFmt == FormatPDF {
		engine := findPandocPDFEngine()
		if engine == "" {
			return nil, fmt.Errorf("format_conversion: PDF conversion requires a PDF engine (pdflatex/xelatex/wkhtmltopdf/weasyprint), but none found.\nInstall one: sudo apt install wkhtmltopdf  OR  pip install weasyprint")
		}
		args = append([]string{"--pdf-engine=" + engine}, args...)
	}

	cmd := exec.Command("pandoc", args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("format_conversion: pandoc conversion failed: %w", err)
	}

	result, err := os.ReadFile(dstPath)
	if err != nil {
		return nil, fmt.Errorf("format_conversion: read result file: %w", err)
	}

	return result, nil
}

func convertDocumentStream(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if srcFmt == dstFmt {
		return data, nil
	}

	if !isPandocAvailable() {
		return nil, fmt.Errorf("format_conversion: pandoc is not installed, please install pandoc first")
	}

	srcFormat := getPandocInputFormat(srcFmt)
	dstFormat, err := getPandocOutputFormat(dstFmt)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30)
	defer cancel()

	args := []string{"-f", srcFormat, "-t", dstFormat}
	if dstFmt == FormatPDF {
		engine := findPandocPDFEngine()
		if engine == "" {
			return nil, fmt.Errorf("format_conversion: PDF conversion requires a PDF engine (pdflatex/xelatex/wkhtmltopdf/weasyprint), but none found.\nInstall one: sudo apt install wkhtmltopdf  OR  pip install weasyprint")
		}
		args = append([]string{"--pdf-engine=" + engine}, args...)
	}

	cmd := exec.CommandContext(ctx, "pandoc", args...)
	cmd.Stdin = bytes.NewReader(data)

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("format_conversion: pandoc conversion failed: %w", err)
	}

	return out.Bytes(), nil
}

func isPandocAvailable() bool {
	cmd := exec.Command("pandoc", "--version")
	return cmd.Run() == nil
}

func getFormatExtension(f FormatType) string {
	exts, ok := formatExtensions[f]
	if !ok || len(exts) == 0 {
		return ".txt"
	}
	return exts[0]
}

func getPandocInputFormat(f FormatType) string {
	switch f {
	case FormatMarkdown:
		return "markdown"
	case FormatDOC:
		return "doc"
	case FormatDOCX:
		return "docx"
	case FormatODT:
		return "odt"
	case FormatHTML:
		return "html"
	case FormatRTF:
		return "rtf"
	case FormatPDF:
		return "pdf"
	case FormatTXT:
		return "plain"
	default:
		return "markdown"
	}
}

func getPandocOutputFormat(f FormatType) (string, error) {
	switch f {
	case FormatMarkdown:
		return "markdown", nil
	case FormatDOC:
		return "", fmt.Errorf("format_conversion: pandoc cannot output to .doc, use .docx instead")
	case FormatDOCX:
		return "docx", nil
	case FormatODT:
		return "odt", nil
	case FormatHTML:
		return "html", nil
	case FormatRTF:
		return "rtf", nil
	case FormatPDF:
		return "pdf", nil
	case FormatTXT:
		return "plain", nil
	default:
		return "", fmt.Errorf("format_conversion: unsupported output format %s", f)
	}
}

func findPandocPDFEngine() string {
	engines := []string{"wkhtmltopdf", "weasyprint", "pdflatex", "xelatex", "lualatex"}
	for _, engine := range engines {
		if _, err := exec.LookPath(engine); err == nil {
			return engine
		}
	}
	return ""
}
