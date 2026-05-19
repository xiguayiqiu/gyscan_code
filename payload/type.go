package payload

type XSSContext int

const (
	XSSHTML XSSContext = iota
	XSSAttribute
	XSSScript
	XSSCSS
	XSSURL
	XSSComment
	XSSSVG
	XSSTagName
)

func (x XSSContext) String() string {
	switch x {
	case XSSHTML:
		return "html"
	case XSSAttribute:
		return "attribute"
	case XSSScript:
		return "script"
	case XSSCSS:
		return "css"
	case XSSURL:
		return "url"
	case XSSComment:
		return "comment"
	case XSSSVG:
		return "svg"
	case XSSTagName:
		return "tagname"
	default:
		return "unknown"
	}
}

type WAFType int

const (
	WAFCloudflare WAFType = iota
	WAFAWS
	WAFModSecurity
	WAFIncapsula
	WAFF5
	WAFBarracuda
	WAFSucuri
	WAFAkamai
	WAFGeneric
)

func (w WAFType) String() string {
	switch w {
	case WAFCloudflare:
		return "cloudflare"
	case WAFAWS:
		return "aws"
	case WAFModSecurity:
		return "modsecurity"
	case WAFIncapsula:
		return "incapsula"
	case WAFF5:
		return "f5"
	case WAFBarracuda:
		return "barracuda"
	case WAFSucuri:
		return "sucuri"
	case WAFAkamai:
		return "akamai"
	case WAFGeneric:
		return "generic"
	default:
		return "unknown"
	}
}

type FingerprintType int

const (
	FingerprintCanvas FingerprintType = iota
	FingerprintWebGL
	FingerprintAudio
	FingerprintFont
	FingerprintWebRTC
	FingerprintBattery
	FingerprintPlugin
	FingerprintScreen
	FingerprintTimezone
	FingerprintLanguage
	FingerprintUserAgent
	FingerprintHardware
	FingerprintMedia
)

func (f FingerprintType) String() string {
	switch f {
	case FingerprintCanvas:
		return "canvas"
	case FingerprintWebGL:
		return "webgl"
	case FingerprintAudio:
		return "audio"
	case FingerprintFont:
		return "font"
	case FingerprintWebRTC:
		return "webrtc"
	case FingerprintBattery:
		return "battery"
	case FingerprintPlugin:
		return "plugin"
	case FingerprintScreen:
		return "screen"
	case FingerprintTimezone:
		return "timezone"
	case FingerprintLanguage:
		return "language"
	case FingerprintUserAgent:
		return "useragent"
	case FingerprintHardware:
		return "hardware"
	case FingerprintMedia:
		return "media"
	default:
		return "unknown"
	}
}

type DirScanBypassType int

const (
	DirBypassUserAgent DirScanBypassType = iota
	DirBypassHeader
	DirBypassEncoding
	DirBypassCase
	DirBypassRateLimit
	DirBypassPathObfuscation
	DirBypassMethod
	DirBypassReferer
	DirBypassCookie
	DirBypassParam
)

func (d DirScanBypassType) String() string {
	switch d {
	case DirBypassUserAgent:
		return "useragent"
	case DirBypassHeader:
		return "header"
	case DirBypassEncoding:
		return "encoding"
	case DirBypassCase:
		return "case"
	case DirBypassRateLimit:
		return "ratelimit"
	case DirBypassPathObfuscation:
		return "path_obfuscation"
	case DirBypassMethod:
		return "method"
	case DirBypassReferer:
		return "referer"
	case DirBypassCookie:
		return "cookie"
	case DirBypassParam:
		return "param"
	default:
		return "unknown"
	}
}

type Payload struct {
	Raw         string
	Description string
	Context     XSSContext
	WAF         WAFType
	FPType      FingerprintType
	BypassType  DirScanBypassType
}