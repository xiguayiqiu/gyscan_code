package payload

func XSSStrings() []string {
	items := XSSPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func XSSHTMLStrings() []string {
	items := XSSHTMLPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func XSSAttributeStrings() []string {
	items := XSSAttributePayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func XSSSVGStrings() []string {
	items := XSSSVGPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func XSSPolyglotStrings() []string {
	items := XSSPolyglotPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func XSSWAFBypassStrings() []string {
	items := XSSWAFBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func WAFBypassStrings(waf WAFType) []string {
	items := WAFBypassPayloads(waf)
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func WAFBypassAllStrings() []string {
	items := WAFBypassAllPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func FingerprintCanvasStrings() []string {
	items := FingerprintCanvasPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func FingerprintWebGLStrings() []string {
	items := FingerprintWebGLPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func FingerprintFontStrings() []string {
	items := FingerprintFontPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func FingerprintWebRTCStrings() []string {
	items := FingerprintWebRTCPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func FingerprintAllStrings() []string {
	items := FingerprintAllPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirUserAgentBypassStrings() []string {
	items := DirUserAgentBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirHeaderBypassStrings() []string {
	items := DirHeaderBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirEncodingBypassStrings() []string {
	items := DirEncodingBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirCaseBypassStrings() []string {
	items := DirCaseBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirRateLimitBypassStrings() []string {
	items := DirRateLimitBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirPathObfuscationBypassStrings() []string {
	items := DirPathObfuscationBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func DirAllBypassStrings() []string {
	items := DirAllBypassPayloads()
	result := make([]string, len(items))
	for i, p := range items {
		result[i] = p.Raw
	}
	return result
}

func PasswordCount() int {
	return len(PwPayload())
}

func XSSCount() int {
	return len(XSSPayloads())
}

func WAFBypassCount(waf WAFType) int {
	return len(WAFBypassPayloads(waf))
}

func WAFBypassAllCount() int {
	return len(WAFBypassAllPayloads())
}

func FingerprintCount() int {
	return len(FingerprintAllPayloads())
}

func DirBypassCount() int {
	return len(DirAllBypassPayloads())
}

func TotalCount() int {
	return XSSCount() + WAFBypassAllCount() + FingerprintCount() + DirBypassCount() + PasswordCount()
}