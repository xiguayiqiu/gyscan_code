package ano

import (
	"encoding/binary"
	"fmt"
)

const (
	TLS_CHANGE_CIPHER_SPEC uint8 = 20
	TLS_ALERT              uint8 = 21
	TLS_HANDSHAKE          uint8 = 22
	TLS_APPLICATION_DATA   uint8 = 23
)

const (
	TLS_VERSION_1_0 uint16 = 0x0301
	TLS_VERSION_1_1 uint16 = 0x0302
	TLS_VERSION_1_2 uint16 = 0x0303
	TLS_VERSION_1_3 uint16 = 0x0304
)

var TLSVersionNames = map[uint16]string{
	TLS_VERSION_1_0: "TLS 1.0",
	TLS_VERSION_1_1: "TLS 1.1",
	TLS_VERSION_1_2: "TLS 1.2",
	TLS_VERSION_1_3: "TLS 1.3",
}

const (
	TLS_HANDSHAKE_HELLO_REQUEST    uint8 = 0
	TLS_HANDSHAKE_CLIENT_HELLO     uint8 = 1
	TLS_HANDSHAKE_SERVER_HELLO     uint8 = 2
	TLS_HANDSHAKE_CERTIFICATE      uint8 = 11
	TLS_HANDSHAKE_SERVER_KEY_EXCH  uint8 = 12
	TLS_HANDSHAKE_CERT_REQUEST     uint8 = 13
	TLS_HANDSHAKE_SERVER_HELLO_DONE uint8 = 14
	TLS_HANDSHAKE_CERT_VERIFY      uint8 = 15
	TLS_HANDSHAKE_CLIENT_KEY_EXCH  uint8 = 16
	TLS_HANDSHAKE_FINISHED         uint8 = 20
)

var TLSContentTypeNames = map[uint8]string{
	TLS_CHANGE_CIPHER_SPEC: "Change Cipher Spec",
	TLS_ALERT:              "Alert",
	TLS_HANDSHAKE:          "Handshake",
	TLS_APPLICATION_DATA:   "Application Data",
}

var TLSHandshakeTypeNames = map[uint8]string{
	TLS_HANDSHAKE_HELLO_REQUEST:     "Hello Request",
	TLS_HANDSHAKE_CLIENT_HELLO:      "Client Hello",
	TLS_HANDSHAKE_SERVER_HELLO:      "Server Hello",
	TLS_HANDSHAKE_CERTIFICATE:       "Certificate",
	TLS_HANDSHAKE_SERVER_KEY_EXCH:   "Server Key Exchange",
	TLS_HANDSHAKE_CERT_REQUEST:      "Certificate Request",
	TLS_HANDSHAKE_SERVER_HELLO_DONE: "Server Hello Done",
	TLS_HANDSHAKE_CERT_VERIFY:       "Certificate Verify",
	TLS_HANDSHAKE_CLIENT_KEY_EXCH:   "Client Key Exchange",
	TLS_HANDSHAKE_FINISHED:          "Finished",
}

const (
	TLS_EXT_SERVER_NAME           uint16 = 0
	TLS_EXT_MAX_FRAGMENT_LENGTH   uint16 = 1
	TLS_EXT_STATUS_REQUEST        uint16 = 5
	TLS_EXT_SUPPORTED_GROUPS      uint16 = 10
	TLS_EXT_EC_POINT_FORMATS      uint16 = 11
	TLS_EXT_SIGNATURE_ALGORITHMS  uint16 = 13
	TLS_EXT_ALPN                  uint16 = 16
	TLS_EXT_SUPPORTED_VERSIONS    uint16 = 43
	TLS_EXT_KEY_SHARE             uint16 = 51
)

var TLSExtensionNames = map[uint16]string{
	TLS_EXT_SERVER_NAME:           "server_name (SNI)",
	TLS_EXT_MAX_FRAGMENT_LENGTH:   "max_fragment_length",
	TLS_EXT_STATUS_REQUEST:        "status_request",
	TLS_EXT_SUPPORTED_GROUPS:      "supported_groups",
	TLS_EXT_EC_POINT_FORMATS:      "ec_point_formats",
	TLS_EXT_SIGNATURE_ALGORITHMS:  "signature_algorithms",
	TLS_EXT_ALPN:                  "application_layer_protocol_negotiation (ALPN)",
	TLS_EXT_SUPPORTED_VERSIONS:    "supported_versions",
	TLS_EXT_KEY_SHARE:             "key_share",
}

type TLSExtension struct {
	Type   uint16
	Length uint16
	Data   []byte
}

type TLSRecord struct {
	ContentType     uint8
	Version         uint16
	Length          uint16
	Fragment        []byte
	HandshakeType   uint8
	ClientVersion   uint16
	ClientRandom    [32]byte
	SessionID       []byte
	CipherSuites    []uint16
	CompMethods     []uint8
	Extensions      []TLSExtension
	ServerName      string
	ServerVersion   uint16
	ServerRandom    [32]byte
	CipherSuite     uint16
	AlertLevel      uint8
	AlertDesc       uint8
}

func NewTLSRecord() *TLSRecord {
	return &TLSRecord{
		ContentType: TLS_HANDSHAKE,
		Version:     TLS_VERSION_1_2,
	}
}

func NewTLSClientHello(sni string) *TLSRecord {
	var random [32]byte
	for i := range random {
		random[i] = byte(RandInt(0, 255))
	}
	t := &TLSRecord{
		ContentType:   TLS_HANDSHAKE,
		Version:       TLS_VERSION_1_2,
		HandshakeType: TLS_HANDSHAKE_CLIENT_HELLO,
		ClientVersion: TLS_VERSION_1_2,
		ClientRandom:  random,
		CompMethods:   []uint8{0},
	}
	copy(t.ClientRandom[:], random[:])

	if sni != "" {
		t.ServerName = sni
		ext := buildSNIExtension(sni)
		t.Extensions = append(t.Extensions, ext)
	}
	if len(t.CipherSuites) == 0 {
		t.CipherSuites = []uint16{
			0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
			0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
		}
	}
	t.recalcLength()
	return t
}

func buildSNIExtension(sni string) TLSExtension {
	nameBytes := make([]byte, 3+len(sni))
	nameBytes[0] = 0
	binary.BigEndian.PutUint16(nameBytes[1:3], uint16(len(sni)))
	copy(nameBytes[3:], sni)

	listLen := len(nameBytes)
	listBytes := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(listBytes[0:2], uint16(listLen))
	copy(listBytes[2:], nameBytes)

	return TLSExtension{
		Type:   TLS_EXT_SERVER_NAME,
		Length: uint16(len(listBytes)),
		Data:   listBytes,
	}
}

func (t *TLSRecord) recalcLength() {
	if t.HandshakeType != 0 {
		bodyLen := 4 + 28 + 1 + len(t.SessionID) + 2 + len(t.CipherSuites)*2 + 1 + len(t.CompMethods)
		if len(t.Extensions) > 0 {
			extLen := 0
			for _, e := range t.Extensions {
				extLen += 4 + len(e.Data)
			}
			bodyLen += 2 + extLen
		}
		t.Length = uint16(bodyLen)
	}
}

func (t *TLSRecord) Tag() string { return "TLS" }

func (t *TLSRecord) Len() int { return 5 + int(t.Length) }

func (t *TLSRecord) Copy() Layer {
	n := &TLSRecord{
		ContentType:   t.ContentType,
		Version:       t.Version,
		Length:        t.Length,
		HandshakeType: t.HandshakeType,
		ClientVersion: t.ClientVersion,
		ServerVersion: t.ServerVersion,
		ServerName:    t.ServerName,
		CipherSuite:   t.CipherSuite,
		AlertLevel:    t.AlertLevel,
		AlertDesc:     t.AlertDesc,
	}
	n.Fragment = make([]byte, len(t.Fragment))
	copy(n.Fragment, t.Fragment)
	copy(n.ClientRandom[:], t.ClientRandom[:])
	copy(n.ServerRandom[:], t.ServerRandom[:])
	n.SessionID = make([]byte, len(t.SessionID))
	copy(n.SessionID, t.SessionID)
	n.CipherSuites = make([]uint16, len(t.CipherSuites))
	copy(n.CipherSuites, t.CipherSuites)
	n.CompMethods = make([]uint8, len(t.CompMethods))
	copy(n.CompMethods, t.CompMethods)
	n.Extensions = make([]TLSExtension, len(t.Extensions))
	for i, e := range t.Extensions {
		n.Extensions[i].Type = e.Type
		n.Extensions[i].Length = e.Length
		n.Extensions[i].Data = make([]byte, len(e.Data))
		copy(n.Extensions[i].Data, e.Data)
	}
	return n
}

func (t *TLSRecord) Serialize() []byte {
	hdr := make([]byte, 5)
	hdr[0] = t.ContentType
	binary.BigEndian.PutUint16(hdr[1:3], t.Version)
	binary.BigEndian.PutUint16(hdr[3:5], t.Length)

	var body []byte
	switch t.ContentType {
	case TLS_HANDSHAKE:
		body = t.serializeHandshake()
	case TLS_ALERT:
		body = []byte{t.AlertLevel, t.AlertDesc}
	case TLS_CHANGE_CIPHER_SPEC:
		body = []byte{1}
	default:
		body = t.Fragment
	}
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(body)))
	return append(hdr, body...)
}

func (t *TLSRecord) serializeHandshake() []byte {
	bodyLen := 2 + 32 + 1 + len(t.SessionID) + 2 + len(t.CipherSuites)*2 + 1 + len(t.CompMethods)
	if len(t.Extensions) > 0 {
		extData := t.serializeExtensions()
		bodyLen += 2 + len(extData)
	}

	hsBody := make([]byte, bodyLen)
	binary.BigEndian.PutUint16(hsBody[0:2], t.ClientVersion)
	copy(hsBody[2:34], t.ClientRandom[:])
	hsBody[34] = byte(len(t.SessionID))
	copy(hsBody[35:], t.SessionID)
	off := 35 + len(t.SessionID)
	binary.BigEndian.PutUint16(hsBody[off:off+2], uint16(len(t.CipherSuites)*2))
	off += 2
	for _, cs := range t.CipherSuites {
		binary.BigEndian.PutUint16(hsBody[off:off+2], cs)
		off += 2
	}
	hsBody[off] = byte(len(t.CompMethods))
	off++
	for _, cm := range t.CompMethods {
		hsBody[off] = cm
		off++
	}

	var extData []byte
	if len(t.Extensions) > 0 {
		extData = t.serializeExtensions()
		binary.BigEndian.PutUint16(hsBody[off:off+2], uint16(len(extData)))
		off += 2
		copy(hsBody[off:], extData)
		off += len(extData)
	}

	hsMsg := make([]byte, 4+off)
	hsMsg[0] = t.HandshakeType
	hsMsg[1] = byte(len(hsBody) >> 16)
	hsMsg[2] = byte(len(hsBody) >> 8)
	hsMsg[3] = byte(len(hsBody))
	copy(hsMsg[4:], hsBody)

	t.Length = uint16(len(hsMsg))
	return hsMsg
}

func (t *TLSRecord) serializeExtensions() []byte {
	var b []byte
	for _, e := range t.Extensions {
		b = binary.BigEndian.AppendUint16(b, e.Type)
		b = binary.BigEndian.AppendUint16(b, uint16(len(e.Data)))
		b = append(b, e.Data...)
	}
	return b
}

func (t *TLSRecord) Deserialize(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return data, fmt.Errorf("tls: need 5 bytes, got %d", len(data))
	}
	t.ContentType = data[0]
	t.Version = binary.BigEndian.Uint16(data[1:3])
	t.Length = binary.BigEndian.Uint16(data[3:5])

	recordEnd := 5 + int(t.Length)
	if recordEnd > len(data) {
		return data, fmt.Errorf("tls: record length %d exceeds available %d", t.Length, len(data)-5)
	}

	t.Fragment = make([]byte, t.Length)
	copy(t.Fragment, data[5:recordEnd])

	switch t.ContentType {
	case TLS_HANDSHAKE:
		t.parseHandshake(t.Fragment)
	case TLS_ALERT:
		if len(t.Fragment) >= 2 {
			t.AlertLevel = t.Fragment[0]
			t.AlertDesc = t.Fragment[1]
		}
	}

	return data[recordEnd:], nil
}

func (t *TLSRecord) parseHandshake(data []byte) {
	if len(data) < 4 {
		return
	}
	t.HandshakeType = data[0]
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	body := data[4:]
	if len(body) < hsLen {
		body = body[:len(body)]
	} else {
		body = body[:hsLen]
	}

	if (t.HandshakeType == TLS_HANDSHAKE_CLIENT_HELLO || t.HandshakeType == TLS_HANDSHAKE_SERVER_HELLO) && len(body) >= 38 {
		t.ClientVersion = binary.BigEndian.Uint16(body[0:2])
		copy(t.ClientRandom[:], body[2:34])
		sidLen := int(body[34])
		off := 35
		if sidLen > 0 && off+sidLen <= len(body) {
			t.SessionID = make([]byte, sidLen)
			copy(t.SessionID, body[off:off+sidLen])
		}
		off += sidLen

		if t.HandshakeType == TLS_HANDSHAKE_CLIENT_HELLO && off+2 <= len(body) {
			csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			for i := 0; i < csLen/2 && off+2 <= len(body); i++ {
				t.CipherSuites = append(t.CipherSuites, binary.BigEndian.Uint16(body[off:off+2]))
				off += 2
			}

			if off < len(body) {
				cmLen := int(body[off])
				off++
				if off+cmLen <= len(body) {
					for i := 0; i < cmLen; i++ {
						t.CompMethods = append(t.CompMethods, body[off+i])
					}
					off += cmLen
				}
			}

			if off+2 <= len(body) {
				extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
				off += 2
				endOff := off + extLen
				if endOff > len(body) {
					endOff = len(body)
				}
				t.parseExtensions(body[off:endOff])
			}
		} else if t.HandshakeType == TLS_HANDSHAKE_SERVER_HELLO && off+2 <= len(body) {
			t.CipherSuite = binary.BigEndian.Uint16(body[off : off+2])
		}
	}
}

func (t *TLSRecord) parseExtensions(data []byte) {
	off := 0
	for off+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[off : off+2])
		extLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if extLen > 0 && off+extLen <= len(data) {
			ext := TLSExtension{Type: extType, Length: uint16(extLen)}
			ext.Data = make([]byte, extLen)
			copy(ext.Data, data[off:off+extLen])
			t.Extensions = append(t.Extensions, ext)

			if extType == TLS_EXT_SERVER_NAME {
				t.ServerName = parseSNI(ext.Data)
			}
			off += extLen
		} else {
			break
		}
	}
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return ""
	}
	data = data[2 : 2+listLen]
	off := 0
	for off+3 <= len(data) {
		if data[off] != 0 {
			off++
			continue
		}
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if off+nameLen <= len(data) {
			return string(data[off : off+nameLen])
		}
		break
	}
	return ""
}

func (t *TLSRecord) Next(data []byte) Layer { return nil }

func IsTLS(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	ct := data[0]
	ver := binary.BigEndian.Uint16(data[1:3])
	if ct < TLS_CHANGE_CIPHER_SPEC || ct > TLS_APPLICATION_DATA {
		return false
	}
	return ver >= TLS_VERSION_1_0 && ver <= TLS_VERSION_1_3
}

func (t *TLSRecord) SetSNI(sni string) *TLSRecord {
	t.ServerName = sni
	ext := buildSNIExtension(sni)
	t.Extensions = append(t.Extensions, ext)
	t.recalcLength()
	return t
}

func (t *TLSRecord) SetVersion(v uint16) *TLSRecord {
	t.Version = v
	t.ClientVersion = v
	return t
}

func (t *TLSRecord) SetCipherSuites(cs []uint16) *TLSRecord {
	t.CipherSuites = cs
	t.recalcLength()
	return t
}