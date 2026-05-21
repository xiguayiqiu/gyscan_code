package wifie

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
)

func RC4Init(key []byte) *RC4State {
	s := &RC4State{}
	for i := 0; i < 256; i++ {
		s.S[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s.S[i]) + int(key[i%len(key)])) % 256
		s.S[i], s.S[j] = s.S[j], s.S[i]
	}
	return s
}

func RC4Crypt(s *RC4State, data []byte) {
	for k := 0; k < len(data); k++ {
		s.I++
		s.J += s.S[s.I]
		s.S[s.I], s.S[s.J] = s.S[s.J], s.S[s.I]
		data[k] ^= s.S[uint8((uint16(s.S[s.I])+uint16(s.S[s.J]))%256)]
	}
}

func WEPDecrypt(key []byte, packet []byte) ([]byte, error) {
	if len(packet) < 8 {
		return nil, nil
	}

	wepKey := make([]byte, 3+len(key))
	copy(wepKey[0:3], packet[0:3])
	copy(wepKey[3:], key)

	s := RC4Init(wepKey)

	dataLen := len(packet) - 8
	if dataLen < 0 {
		return nil, nil
	}

	data := make([]byte, dataLen)
	copy(data, packet[4:4+dataLen])
	RC4Crypt(s, data)

	return data, nil
}

func WEPDecryptGroup(key []byte, packet []byte) ([]byte, error) {
	if len(packet) < 12 {
		return nil, nil
	}

	iv := packet[0:3]
	keyIdx := packet[3]
	_ = keyIdx

	wepKey := make([]byte, 3+len(key))
	copy(wepKey[0:3], iv)
	copy(wepKey[3:], key)

	s := RC4Init(wepKey)

	payloadLen := len(packet) - 8
	if payloadLen < 0 {
		return nil, nil
	}

	data := make([]byte, len(packet))
	copy(data, packet)
	RC4Crypt(s, data[4:4+payloadLen])

	return data[4 : 4+payloadLen-4], nil
}

func CalcPMK(passphrase []byte, essid []byte) [32]byte {
	var pmk [32]byte
	pbkdf2SHA1(passphrase, essid, 4096, pmk[:])
	return pmk
}

func pbkdf2SHA1(password []byte, salt []byte, iter int, dk []byte) {
	h := sha1.New
	hlen := h().Size()
	blockSize := 64

	key := password
	if len(key) > blockSize {
		sum := sha1.Sum(key)
		key = sum[:]
	}

	saltLen := len(salt)
	saltBlock := make([]byte, saltLen+4)
	copy(saltBlock, salt)

	T := make([]byte, hlen)
	U := make([]byte, hlen)
	U2 := make([]byte, hlen)

	mac := hmac.New(h, key)

	blockCount := (len(dk) + hlen - 1) / hlen

	for block := 1; block <= blockCount; block++ {
		saltBlock[saltLen] = byte(block >> 24)
		saltBlock[saltLen+1] = byte(block >> 16)
		saltBlock[saltLen+2] = byte(block >> 8)
		saltBlock[saltLen+3] = byte(block)

		mac.Reset()
		mac.Write(saltBlock)
		mac.Sum(T[:0])
		copy(U, T)

		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(U[:hlen])
			mac.Sum(U2[:0])
			for j := 0; j < hlen; j++ {
				T[j] ^= U2[j]
			}
			U, U2 = U2, U
		}

		offset := (block - 1) * hlen
		cp := hlen
		if len(dk)-offset < hlen {
			cp = len(dk) - offset
		}
		copy(dk[offset:], T[:cp])
	}
}

func SHA1PRF(key []byte, label string, data []byte, outputLen int) []byte {
	numBytes := (outputLen + sha1.Size - 1) / sha1.Size
	output := make([]byte, numBytes*sha1.Size)

	for i := 0; i < numBytes; i++ {
		mac := hmac.New(sha1.New, key)
		mac.Write([]byte(label))
		mac.Write([]byte{0})
		mac.Write(data)
		mac.Write([]byte{byte(i)})
		copy(output[i*sha1.Size:], mac.Sum(nil))
	}

	return output[:outputLen]
}

func CalcPTK(pmk []byte, bssid, stamac string, anonce, snonce []byte, keyVer uint8) []byte {
	data := buildPTKData(bssid, stamac, anonce, snonce)

	if keyVer < 3 {
		return SHA1PRF(pmk, "Pairwise key expansion", data, 64)
	}

	return SHA256PRF(pmk, "Pairwise key expansion", data, 48)
}

func buildPTKData(bssid, stamac string, anonce, snonce []byte) []byte {
	data := make([]byte, 6+6+32+32)
	copy(data[0:6], minMACBytes(bssid, stamac))
	copy(data[6:12], maxMACBytes(bssid, stamac))
	copy(data[12:44], minBytes(anonce, snonce))
	copy(data[44:76], maxBytes(anonce, snonce))
	return data
}

func PreComputePTKData(bssid, stamac string, anonce, snonce []byte) []byte {
	return buildPTKData(bssid, stamac, anonce, snonce)
}

func CalcPTKWithData(pmk []byte, pkeData []byte, keyVer uint8) []byte {
	if keyVer < 3 {
		return SHA1PRF(pmk, "Pairwise key expansion", pkeData, 64)
	}
	return SHA256PRF(pmk, "Pairwise key expansion", pkeData, 48)
}

func SHA256PRF(key []byte, label string, data []byte, outputLen int) []byte {
	numBytes := (outputLen*8 + sha256.Size*8 - 1) / (sha256.Size * 8)
	output := make([]byte, numBytes*sha256.Size)

	for i := 0; i < numBytes; i++ {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(label))
		mac.Write([]byte{0})
		mac.Write(data)
		mac.Write([]byte{byte(i)})
		copy(output[i*sha256.Size:], mac.Sum(nil))
	}

	return output[:outputLen]
}

func CalcPMKID(pmk []byte, bssid, stamac string) []byte {
	data := make([]byte, 20)
	copy(data[0:8], []byte("PMK Name"))
	copy(data[8:14], parseMACBytes(bssid))
	copy(data[14:20], parseMACBytes(stamac))

	mac := hmac.New(sha1.New, pmk)
	mac.Write(data)
	return mac.Sum(nil)
}

func CalcEAPOLMIC(eapol []byte, ptk []byte, keyVer uint8) ([]byte, error) {
	if keyVer == 1 {
		mac := hmac.New(md5.New, ptk[:16])
		mac.Write(eapol)
		return mac.Sum(nil), nil
	} else if keyVer == 2 {
		mac := hmac.New(sha1.New, ptk[:16])
		mac.Write(eapol)
		return mac.Sum(nil)[:16], nil
	} else if keyVer == 3 {
		return calcOMAC1AES(ptk[:16], eapol), nil
	}
	return nil, nil
}

func calcOMAC1AES(key []byte, data []byte) []byte {
	block, _ := aes.NewCipher(key)
	omac := make([]byte, 16)

	var L [16]byte
	block.Encrypt(L[:], L[:])

	var subkey1 [16]byte
	gfMul(L[:], subkey1[:])

	var tmp [16]byte
	var last [16]byte
	remaining := data

	for len(remaining) > 16 {
		for i := 0; i < 16; i++ {
			tmp[i] = omac[i] ^ remaining[i]
		}
		block.Encrypt(omac[:], tmp[:])
		remaining = remaining[16:]
	}

	if len(remaining) == 16 {
		for i := 0; i < 16; i++ {
			last[i] = subkey1[i] ^ remaining[i] ^ omac[i]
		}
	} else {
		var subkey2 [16]byte
		gfMul(subkey1[:], subkey2[:])
		copy(tmp[:], remaining)
		tmp[len(remaining)] = 0x80
		for i := len(remaining) + 1; i < 16; i++ {
			tmp[i] = 0
		}
		for i := 0; i < 16; i++ {
			last[i] = subkey2[i] ^ tmp[i] ^ omac[i]
		}
	}

	block.Encrypt(omac[:], last[:])
	return omac
}

func gfMul(x []byte, out []byte) {
	copy(out, x)
	overflow := byte(0)
	for i := 15; i >= 0; i-- {
		carry := out[i] >> 7
		out[i] = (out[i] << 1) | overflow
		overflow = carry
	}
	if x[15]&0x80 != 0 {
		out[0] ^= 0x87
	}
}

func minMAC(a, b string) string {
	if a < b {
		return a
	}
	return b
}

func maxMAC(a, b string) string {
	if a < b {
		return b
	}
	return a
}

func minMACBytes(a, b string) []byte {
	if a < b {
		return parseMACBytes(a)
	}
	return parseMACBytes(b)
}

func maxMACBytes(a, b string) []byte {
	if a < b {
		return parseMACBytes(b)
	}
	return parseMACBytes(a)
}

func minBytes(a, b []byte) []byte {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return a
		}
		if a[i] > b[i] {
			return b
		}
	}
	return a
}

func maxBytes(a, b []byte) []byte {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] > b[i] {
			return a
		}
		if a[i] < b[i] {
			return b
		}
	}
	return a
}

func TryWPAKey(passphrase []byte, essid []byte, bssid, stamac string, anonce, snonce []byte, eapolData []byte, eapolSize int, cmpmic []byte, keyVer uint8) bool {
	pmk := CalcPMK(passphrase, essid)
	ptk := CalcPTK(pmk[:], bssid, stamac, anonce, snonce, keyVer)

	mic, err := CalcEAPOLMIC(eapolData[:eapolSize], ptk, keyVer)
	if err != nil {
		return false
	}

	for i := 0; i < 16 && i < len(mic) && i < len(cmpmic); i++ {
		if mic[i] != cmpmic[i] {
			return false
		}
	}
	return true
}

func TryPMKID(pmk, pmkid []byte, bssid, stamac string) bool {
	calc := CalcPMKID(pmk, bssid, stamac)
	for i := 0; i < 16 && i < len(calc) && i < len(pmkid); i++ {
		if calc[i] != pmkid[i] {
			return false
		}
	}
	return true
}

func CalcCRC32(buf []byte) uint32 {
	var crc uint32 = 0xFFFFFFFF
	table := crc32Table()
	for _, b := range buf {
		crc = table[byte(crc)^b] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}

func crc32Table() [256]uint32 {
	var table [256]uint32
	for i := uint32(0); i < 256; i++ {
		c := i
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	return table
}

func BuildWEPPacket(payload []byte, key []byte, iv [3]byte, keyIdx byte, addICV bool) []byte {
	wepKey := make([]byte, 3+len(key))
	copy(wepKey[0:3], iv[:])
	copy(wepKey[3:], key)

	packet := make([]byte, 4+len(payload)+4+4)
	copy(packet[0:3], iv[:])
	packet[3] = keyIdx

	dataPart := packet[4 : 4+len(payload)+4]
	copy(dataPart, payload)

	if addICV {
		crc := CalcCRC32(payload)
		binary.LittleEndian.PutUint32(packet[4+len(payload):], crc)
	}

	s := RC4Init(wepKey)

	dataToEncrypt := packet[4 : 4+len(payload)+4]
	RC4Crypt(s, dataToEncrypt)

	return packet[:4+len(payload)+4]
}

func ExtractWEPIV(packet []byte) (iv [3]byte, keyIdx byte) {
	if len(packet) < 4 {
		return
	}
	copy(iv[:], packet[0:3])
	keyIdx = packet[3]
	return
}