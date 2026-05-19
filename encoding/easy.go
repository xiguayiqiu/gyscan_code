package encoding

func EncodeBase16(data []byte) string {
	return Base16Encode(data)
}

func DecodeBase16(s string) ([]byte, error) {
	return Base16Decode(s)
}

func EncodeBase32(data []byte) string {
	return Base32Encode(data)
}

func DecodeBase32(s string) ([]byte, error) {
	return Base32Decode(s)
}

func EncodeBase64(data []byte) string {
	return Base64Encode(data)
}

func DecodeBase64(s string) ([]byte, error) {
	return Base64Decode(s)
}

func EncodeBase85(data []byte) string {
	return Base85Encode(data)
}

func DecodeBase85(s string) ([]byte, error) {
	return Base85Decode(s)
}

func EncodeURL(s string) string {
	return URLEncode(s)
}

func DecodeURL(s string) (string, error) {
	return URLDecode(s)
}

func EncodeHex(data []byte) string {
	return HexEncode(data)
}

func DecodeHex(s string) ([]byte, error) {
	return HexDecode(s)
}

func EncodeHTML(s string) string {
	return HTMLEntityEncode(s)
}

func DecodeHTML(s string) string {
	return HTMLEntityDecode(s)
}

func EncodeCaesar(s string, shift int) string {
	return CaesarEncode(s, shift)
}

func DecodeCaesar(s string, shift int) string {
	return CaesarDecode(s, shift)
}

func EncodeVigenere(s string, key string) string {
	return VigenereEncode(s, key)
}

func DecodeVigenere(s string, key string) string {
	return VigenereDecode(s, key)
}

func EncodeRailFence(s string, rails int) string {
	return RailFenceEncode(s, rails)
}

func DecodeRailFence(s string, rails int) string {
	return RailFenceDecode(s, rails)
}

func EncodeJother(s string) string {
	return JotherEncode(s)
}

func DecodeJother(s string) string {
	return JotherDecode(s)
}

func EncodeJSFuck(s string) string {
	return JSFuckEncode(s)
}

func DecodeJSFuck(s string) string {
	return JSFuckDecode(s)
}