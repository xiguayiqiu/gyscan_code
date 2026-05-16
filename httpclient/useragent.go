package httpclient

import (
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
)

// DeviceType 设备类型
type DeviceType int

const (
	DeviceDesktop DeviceType = iota // 桌面设备
	DeviceMobile                   // 移动设备
	DeviceTablet                   // 平板设备
	DeviceBot                      // 爬虫
	DeviceAPI                      // API客户端
)

// OS 操作系统类型
type OS int

const (
	OSWindows OS = iota // Windows
	OSMacOS             // macOS
	OSLinux              // Linux
	OSAndroid            // Android
	OSIOS                // iOS
	OSUnknown            // 未知系统
)

// Browser 浏览器类型
type Browser int

const (
	BrowserChrome Browser = iota // Chrome
	BrowserFirefox             // Firefox
	BrowserSafari               // Safari
	BrowserEdge                 // Edge
	BrowserOpera                // Opera
	BrowserBrave                // Brave
	BrowserIE                   // Internet Explorer
	BrowserBot                  // 爬虫浏览器
	BrowserAPIClient            // API客户端
	BrowserUnknown              // 未知浏览器
)

// UAInfo 用户代理信息
type UAInfo struct {
	Browser    Browser    // 浏览器类型
	BrowserStr string     // 浏览器名称
	Version    string     // 浏览器版本
	OS         OS         // 操作系统类型
	OSStr      string     // 操作系统名称
	Platform   string     // 平台
	Device     string     // 设备
	DeviceType DeviceType // 设备类型
	IsMobile   bool       // 是否为移动端
	IsBot      bool       // 是否为爬虫
}

// Parse 解析 User-Agent 字符串
func Parse(ua string) *UAInfo {
	info := &UAInfo{DeviceType: DeviceDesktop}

	uaLower := strings.ToLower(ua)

	if strings.Contains(uaLower, "bot") || strings.Contains(uaLower, "crawler") || strings.Contains(uaLower, "spider") {
		info.DeviceType = DeviceBot
		info.IsBot = true
		info.Browser = BrowserBot
		info.BrowserStr = "Bot"
		return info
	}

	if matched, _ := regexp.MatchString(`(curl|wget|python|requests|java|go-http|axios|node-fetch|perl|lwp)`, uaLower); matched {
		info.DeviceType = DeviceAPI
		info.Browser = BrowserAPIClient
		info.BrowserStr = "APIClient"
		return info
	}

	if strings.Contains(uaLower, "android") {
		info.DeviceType = DeviceMobile
		info.IsMobile = true
		info.OS = OSAndroid
		info.OSStr = "Android"
		if strings.Contains(uaLower, "mobile") || strings.Contains(uaLower, "android") {
			if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "edg") {
				info.Browser = BrowserChrome
				info.BrowserStr = "Chrome Mobile"
			} else if strings.Contains(uaLower, "firefox") {
				info.Browser = BrowserFirefox
				info.BrowserStr = "Firefox Mobile"
			}
		}
		info.Device = extractDevice(ua, "Android")
		info.Version = extractVersion(ua, "Android")
		return info
	}

	if strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad") || strings.Contains(uaLower, "ipod") {
		info.OS = OSIOS
		info.OSStr = "iOS"
		info.Platform = "iOS"
		if strings.Contains(uaLower, "ipad") {
			info.DeviceType = DeviceTablet
			info.Device = "iPad"
		} else if strings.Contains(uaLower, "iphone") {
			info.DeviceType = DeviceMobile
			info.IsMobile = true
			info.Device = "iPhone"
		} else {
			info.DeviceType = DeviceMobile
			info.Device = "iPod"
		}
		if strings.Contains(uaLower, "version") {
			info.Browser = BrowserSafari
			info.BrowserStr = "Safari Mobile"
		} else if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "edg") {
			info.Browser = BrowserChrome
			info.BrowserStr = "Chrome Mobile iOS"
		}
		info.Version = extractVersion(ua, "OS")
		return info
	}

	if strings.Contains(uaLower, "windows nt 10") {
		info.OS = OSWindows
		info.OSStr = "Windows 10/11"
		info.Platform = "Windows"
	} else if strings.Contains(uaLower, "windows nt 6.3") || strings.Contains(uaLower, "windows nt 6.2") || strings.Contains(uaLower, "windows nt 6.1") {
		info.OS = OSWindows
		info.OSStr = "Windows 7/8.1"
		info.Platform = "Windows"
	} else if strings.Contains(uaLower, "mac os x") {
		info.OS = OSMacOS
		info.OSStr = extractMacOSVersion(ua)
		info.Platform = "Macintosh"
	} else if strings.Contains(uaLower, "linux") {
		info.OS = OSLinux
		info.OSStr = "Linux"
		info.Platform = "Linux"
	}

	if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "edg") && !strings.Contains(uaLower, "chromium") {
		info.Browser = BrowserChrome
		info.BrowserStr = "Chrome"
		info.Version = extractVersion(ua, "Chrome")
	} else if strings.Contains(uaLower, "firefox") {
		info.Browser = BrowserFirefox
		info.BrowserStr = "Firefox"
		info.Version = extractVersion(ua, "Firefox")
	} else if strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome") {
		info.Browser = BrowserSafari
		info.BrowserStr = "Safari"
		info.Version = extractVersion(ua, "Version")
	} else if strings.Contains(uaLower, "edg") {
		info.Browser = BrowserEdge
		info.BrowserStr = "Edge"
		info.Version = extractVersion(ua, "Edg")
	} else if strings.Contains(uaLower, "opera") || strings.Contains(uaLower, "opr") {
		info.Browser = BrowserOpera
		info.BrowserStr = "Opera"
		info.Version = extractVersion(ua, "OPR")
	} else if strings.Contains(uaLower, "brave") {
		info.Browser = BrowserBrave
		info.BrowserStr = "Brave"
		info.Version = extractVersion(ua, "Brave")
	} else if strings.Contains(uaLower, "trident") || strings.Contains(uaLower, "msie") {
		info.Browser = BrowserIE
		info.BrowserStr = "Internet Explorer"
		info.Version = extractVersion(ua, "MSIE")
	}

	return info
}

// extractVersion 从 User-Agent 中提取版本号
func extractVersion(ua, name string) string {
	regex := regexp.MustCompile(name + `/(\d+[\.\d]*)`)
	matches := regex.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	regex = regexp.MustCompile(`(\d+[\.\d]*)`)
	matches = regex.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractDevice 从 User-Agent 中提取设备信息
func extractDevice(ua, defaultName string) string {
	if strings.Contains(ua, "Pixel") {
		return "Google Pixel"
	}
	if strings.Contains(ua, "Samsung") {
		return "Samsung"
	}
	if strings.Contains(ua, "Huawei") {
		return "Huawei"
	}
	if strings.Contains(ua, "Xiaomi") {
		return "Xiaomi"
	}
	if strings.Contains(ua, "OnePlus") {
		return "OnePlus"
	}
	if strings.Contains(ua, "OPPO") {
		return "OPPO"
	}
	if strings.Contains(ua, "vivo") {
		return "vivo"
	}
	return defaultName
}

// extractMacOSVersion 从 User-Agent 中提取 macOS 版本
func extractMacOSVersion(ua string) string {
	regex := regexp.MustCompile(`Mac OS X (\d+[_\.\d]*)`)
	matches := regex.FindStringSubmatch(ua)
	if len(matches) > 1 {
		version := strings.ReplaceAll(matches[1], "_", ".")
		return "macOS " + version
	}
	return "macOS"
}

// desktopUAs 桌面端 User-Agent 列表
var desktopUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Brave/1.66.80",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Brave/1.65.76",
}

// mobileUAs 移动端 User-Agent 列表
var mobileUAs = []string{
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.8 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-A546V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; Xiaomi 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; HUAWEI P50) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12L; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; SM-G780G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; OnePlus 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 11; Redmi Note 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 11; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Google Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.0.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.0.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/125.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; 23021RAAEG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; M2004jny) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2204) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}

// botUAs 爬虫 User-Agent 列表
var botUAs = []string{
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"Mozilla/5.0 (compatible; Baiduuspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (compatible; DuckDuckBot/1.0; +https://duckduckgo.com/duckduckbot)",
	"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
	"Mozilla/5.0 (compatible; SeznamBot/4.0; +http://napoveda.seznam.cz/en/seznambot-intro/)",
	"Mozilla/5.0 (compatible; MojeekBot/1.0; +https://www.mojeek.com/bot.html)",
	"Mozilla/5.0 (compatible; Twitterbot/1.0)",
	"Mozilla/5.0 (compatible; FacebookBot/1.0; +https://developers.facebook.com/docs/sharing/webmaster)",
	"Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)",
}

// apiClientUAs API 客户端 User-Agent 列表
var apiClientUAs = []string{
	"python-requests/2.31.0",
	"python-requests/2.32.0",
	"python-requests/2.30.0",
	"curl/8.5.0",
	"curl/8.4.0",
	"curl/8.3.0",
	"Wget/1.21.4",
	"Wget/1.21.3",
	"Java/17.0.9",
	"Java/21.0.1",
	"Go-http-client/2.0",
	"axios/1.6.0",
	"node-fetch/1.0",
	"PostmanRuntime/7.32.0",
	"Insomnia/2023.5.0",
}

// RandomDesktop 随机获取桌面端 User-Agent
func RandomDesktop() string {
	return desktopUAs[rand.IntN(len(desktopUAs))]
}

// RandomMobile 随机获取移动端 User-Agent
func RandomMobile() string {
	return mobileUAs[rand.IntN(len(mobileUAs))]
}

// RandomBot 随机获取爬虫 User-Agent
func RandomBot() string {
	return botUAs[rand.IntN(len(botUAs))]
}

// RandomAPIClient 随机获取 API 客户端 User-Agent
func RandomAPIClient() string {
	return apiClientUAs[rand.IntN(len(apiClientUAs))]
}

// Random 随机获取任意类型 User-Agent
func Random() string {
	all := append(append(append([]string{}, desktopUAs...), mobileUAs...), botUAs...)
	return all[rand.IntN(len(all))]
}

// RandomUserAgent 随机获取任意类型 User-Agent（别名）
func RandomUserAgent() string {
	return Random()
}

// AllDesktop 获取所有桌面端 User-Agent
func AllDesktop() []string {
	result := make([]string, len(desktopUAs))
	copy(result, desktopUAs)
	return result
}

// AllMobile 获取所有移动端 User-Agent
func AllMobile() []string {
	result := make([]string, len(mobileUAs))
	copy(result, mobileUAs)
	return result
}

// AllBot 获取所有爬虫 User-Agent
func AllBot() []string {
	result := make([]string, len(botUAs))
	copy(result, botUAs)
	return result
}

// AllAPIClient 获取所有 API 客户端 User-Agent
func AllAPIClient() []string {
	result := make([]string, len(apiClientUAs))
	copy(result, apiClientUAs)
	return result
}

// RandomByBrowser 根据浏览器类型随机获取 User-Agent
func RandomByBrowser(browser string) string {
	browser = strings.ToLower(browser)
	var pool []string

	switch browser {
	case "chrome":
		pool = filterUAs(desktopUAs, "Chrome")
	case "firefox":
		pool = filterUAs(desktopUAs, "Firefox")
	case "safari":
		pool = filterUAs(desktopUAs, "Safari")
	case "edge", "chromium":
		pool = filterUAs(desktopUAs, "Edg")
	case "opera":
		pool = filterUAs(desktopUAs, "OPR")
	case "brave":
		pool = filterUAs(desktopUAs, "Brave")
	default:
		return Random()
	}

	if len(pool) == 0 {
		return Random()
	}
	return pool[rand.IntN(len(pool))]
}

// RandomByOS 根据操作系统随机获取 User-Agent
func RandomByOS(os string) string {
	os = strings.ToLower(os)
	var pool []string

	switch os {
	case "windows":
		pool = filterUAs(desktopUAs, "Windows")
	case "macos", "mac", "osx":
		pool = filterUAs(desktopUAs, "Mac OS X")
	case "linux", "ubuntu", "fedora", "centos", "debian":
		pool = filterUAs(desktopUAs, "X11")
	case "ios", "iphone", "ipad":
		pool = filterUAs(mobileUAs, "iPhone")
	case "android":
		pool = filterUAs(mobileUAs, "Android")
	default:
		return Random()
	}

	if len(pool) == 0 {
		return Random()
	}
	return pool[rand.IntN(len(pool))]
}

// RandomByDevice 根据设备类型随机获取 User-Agent
func RandomByDevice(device string) string {
	device = strings.ToLower(device)
	var pool []string

	switch device {
	case "iphone", "ios":
		pool = filterUAs(mobileUAs, "iPhone")
	case "ipad", "tablet":
		pool = filterUAs(mobileUAs, "iPad")
	case "android", "phone", "mobile":
		pool = filterUAs(mobileUAs, "Linux; Android")
	case "desktop", "pc":
		pool = desktopUAs
	default:
		return Random()
	}

	if len(pool) == 0 {
		return Random()
	}
	return pool[rand.IntN(len(pool))]
}

// filterUAs 过滤 User-Agent 列表
func filterUAs(pool []string, keyword string) []string {
	var result []string
	for _, ua := range pool {
		if strings.Contains(ua, keyword) {
			result = append(result, ua)
		}
	}
	return result
}

// Chrome 获取 Chrome 浏览器 User-Agent
func Chrome(versions ...int) string {
	versionMap := map[int]string{
		126: "126.0.0.0",
		125: "125.0.0.0",
		124: "124.0.0.0",
		123: "123.0.0.0",
		122: "122.0.0.0",
		121: "121.0.0.0",
		120: "120.0.0.0",
	}

	v := 125
	if len(versions) > 0 {
		v = versions[0]
	}

	ver, ok := versionMap[v]
	if !ok {
		ver = "125.0.0.0"
	}

	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + " Safari/537.36"
}

// Firefox 获取 Firefox 浏览器 User-Agent
func Firefox(version int, os string) string {
	versionMap := map[int]string{
		126: "126.0",
		125: "125.0",
		124: "124.0",
		123: "123.0",
		122: "122.0",
		121: "121.0",
		120: "120.0",
	}

	v := 126
	if version > 0 {
		v = version
	}

	ver, ok := versionMap[v]
	if !ok {
		ver = "126.0"
	}

	osMap := map[string]string{
		"windows": "Windows NT 10.0; Win64; x64;",
		"mac":     "Macintosh; Intel Mac OS X 14.5;",
		"linux":   "X11; Linux x86_64;",
		"macos":   "Macintosh; Intel Mac OS X 14.5;",
	}

	osStr := osMap["windows"]
	if o, ok := osMap[os]; ok {
		osStr = o
	}

	return "Mozilla/5.0 (" + osStr + " rv:" + ver + ") Gecko/20100101 Firefox/" + ver
}

// Safari 获取 Safari 浏览器 User-Agent
func Safari(version int) string {
	v := 17
	if version > 0 {
		v = version
	}
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + strconv.Itoa(v) + ".4.1 Safari/605.1.15"
}

// Edge 获取 Edge 浏览器 User-Agent
func Edge(version int) string {
	versionMap := map[int]string{
		126: "126.0.0.0",
		125: "125.0.0.0",
		124: "124.0.0.0",
		123: "123.0.0.0",
		122: "122.0.0.0",
	}

	v := 125
	if version > 0 {
		v = version
	}

	ver, ok := versionMap[v]
	if !ok {
		ver = "125.0.0.0"
	}

	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + " Safari/537.36 Edg/" + ver
}

// Opera 获取 Opera 浏览器 User-Agent
func Opera(version int) string {
	v := 111
	if version > 0 {
		v = version
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/" + strconv.Itoa(v) + ".0.0"
}

// iPhone 获取 iPhone 设备 User-Agent
func iPhone(osVersion int) string {
	v := 17
	if osVersion > 0 {
		v = osVersion
	}
	return "Mozilla/5.0 (iPhone; CPU iPhone OS " + strconv.Itoa(v) + "_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + strconv.Itoa(v) + ".4 Mobile/15E148 Safari/604.1"
}

// iPad 获取 iPad 设备 User-Agent
func iPad(osVersion int) string {
	v := 17
	if osVersion > 0 {
		v = osVersion
	}
	return "Mozilla/5.0 (iPad; CPU OS " + strconv.Itoa(v) + "_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + strconv.Itoa(v) + ".4 Mobile/15E148 Safari/604.1"
}

// AndroidChrome 获取 Android Chrome 浏览器 User-Agent
func AndroidChrome(device string, androidVersion int, chromeVersion int) string {
	av := 14
	if androidVersion > 0 {
		av = androidVersion
	}
	cv := "125.0.0.0"
	if chromeVersion > 0 {
		cv = strconv.Itoa(chromeVersion) + ".0.0.0"
	}
	d := device
	if d == "" {
		d = "Pixel 8 Pro"
	}
	return "Mozilla/5.0 (Linux; Android " + strconv.Itoa(av) + "; " + d + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + cv + " Mobile Safari/537.36"
}

// WindowsChrome 获取 Windows Chrome 浏览器 User-Agent
func WindowsChrome(version int) string {
	return Chrome(version)
}

// WindowsFirefox 获取 Windows Firefox 浏览器 User-Agent
func WindowsFirefox(version int) string {
	return Firefox(version, "windows")
}

// MacChrome 获取 macOS Chrome 浏览器 User-Agent
func MacChrome(version int) string {
	v := 125
	if version > 0 {
		v = version
	}
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(v) + ".0.0.0 Safari/537.36"
}

// MacFirefox 获取 macOS Firefox 浏览器 User-Agent
func MacFirefox(version int) string {
	return Firefox(version, "mac")
}

// LinuxChrome 获取 Linux Chrome 浏览器 User-Agent
func LinuxChrome(version int) string {
	v := 125
	if version > 0 {
		v = version
	}
	return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(v) + ".0.0.0 Safari/537.36"
}

// LinuxFirefox 获取 Linux Firefox 浏览器 User-Agent
func LinuxFirefox(version int) string {
	return Firefox(version, "linux")
}

// UAList User-Agent 列表构建器
type UAList struct {
	UAs      []string
	browser  string
	os       string
	device   string
	count    int
}

// NewUAList 创建新的 User-Agent 列表构建器
func NewUAList() *UAList {
	return &UAList{}
}

// FilterBrowser 按浏览器过滤
func (l *UAList) FilterBrowser(browser string) *UAList {
	l.browser = strings.ToLower(browser)
	return l
}

// FilterOS 按操作系统过滤
func (l *UAList) FilterOS(os string) *UAList {
	l.os = strings.ToLower(os)
	return l
}

// FilterDevice 按设备过滤
func (l *UAList) FilterDevice(device string) *UAList {
	l.device = strings.ToLower(device)
	return l
}

// Limit 限制数量
func (l *UAList) Limit(n int) *UAList {
	l.count = n
	return l
}

// All 获取所有符合条件的 User-Agent
func (l *UAList) All() []string {
	pool := l.buildPool()
	if l.count > 0 && len(pool) > l.count {
		pool = pool[:l.count]
	}
	return pool
}

// Random 随机获取一个符合条件的 User-Agent
func (l *UAList) Random() string {
	pool := l.buildPool()
	if len(pool) == 0 {
		return Random()
	}
	return pool[rand.IntN(len(pool))]
}

// buildPool 构建 User-Agent 池
func (l *UAList) buildPool() []string {
	var pool []string

	if l.device == "mobile" || l.device == "phone" || l.device == "iphone" {
		pool = mobileUAs
	} else if l.device == "tablet" || l.device == "ipad" {
		pool = filterUAs(mobileUAs, "iPad")
	} else if l.device == "bot" {
		pool = botUAs
	} else if l.device == "api" || l.device == "curl" || l.device == "python" {
		pool = apiClientUAs
	} else {
		pool = append(append([]string{}, desktopUAs...), mobileUAs...)
	}

	if l.browser != "" {
		pool = l.filterByBrowser(pool)
	}
	if l.os != "" {
		pool = l.filterByOS(pool)
	}

	return pool
}

// filterByBrowser 按浏览器过滤
func (l *UAList) filterByBrowser(pool []string) []string {
	switch l.browser {
	case "chrome":
		return filterUAs(pool, "Chrome")
	case "firefox":
		return filterUAs(pool, "Firefox")
	case "safari":
		return filterUAs(pool, "Safari")
	case "edge":
		return filterUAs(pool, "Edg")
	case "opera":
		return filterUAs(pool, "OPR")
	}
	return pool
}

// filterByOS 按操作系统过滤
func (l *UAList) filterByOS(pool []string) []string {
	switch l.os {
	case "windows":
		return filterUAs(pool, "Windows")
	case "macos", "mac", "osx":
		return filterUAs(pool, "Mac OS X")
	case "linux":
		return filterUAs(pool, "X11")
	case "ios", "iphone", "ipad":
		return filterUAs(pool, "iPhone")
	case "android":
		return filterUAs(pool, "Android")
	}
	return pool
}
