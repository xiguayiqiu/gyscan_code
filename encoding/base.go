package encoding

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func Base16Encode(data []byte) string {
	return hex.EncodeToString(data)
}

func Base16Decode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func Base32Encode(data []byte) string {
	return base32.StdEncoding.EncodeToString(data)
}

func Base32Decode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	switch len(s) % 8 {
	case 2:
		s += "======"
	case 4:
		s += "===="
	case 5:
		s += "==="
	case 7:
		s += "="
	}
	return base32.StdEncoding.DecodeString(s)
}

func Base32HexEncode(data []byte) string {
	return base32.HexEncoding.EncodeToString(data)
}

func Base32HexDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	switch len(s) % 8 {
	case 2:
		s += "======"
	case 4:
		s += "===="
	case 5:
		s += "==="
	case 7:
		s += "="
	}
	return base32.HexEncoding.DecodeString(s)
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func Base64URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func Base64URLDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

func Base85Encode(data []byte) string {
	encode := make([]byte, 0, len(data)*5/4+4)
	for i := 0; i < len(data); i += 4 {
		var chunk uint32
		n := 0
		for j := 0; j < 4; j++ {
			if i+j < len(data) {
				chunk |= uint32(data[i+j]) << (24 - j*8)
				n++
			}
		}
		if n == 0 {
			break
		}
		tmp := make([]byte, 5)
		for j := 4; j >= 0; j-- {
			tmp[j] = byte(chunk%85) + 33
			chunk /= 85
		}
		encode = append(encode, tmp[:n+1]...)
	}
	return string(encode)
}

func Base85Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	result := make([]byte, 0, len(s)*4/5)
	for i := 0; i < len(s); i += 5 {
		var chunk uint32
		n := 0
		for j := 0; j < 5 && i+j < len(s); j++ {
			if s[i+j] < 33 || s[i+j] > 117 {
				return nil, fmt.Errorf("encoding: invalid base85 character %q at position %d", s[i+j], i+j)
			}
			chunk = chunk*85 + uint32(s[i+j]-33)
			n++
		}
		if n == 0 {
			break
		}
		pad := 5 - n
		for j := 0; j < pad; j++ {
			chunk = chunk*85 + 84
		}
		tmp := make([]byte, 4)
		for j := 3; j >= 0; j-- {
			tmp[j] = byte(chunk & 0xFF)
			chunk >>= 8
		}
		result = append(result, tmp[:n-1]...)
	}
	return result, nil
}