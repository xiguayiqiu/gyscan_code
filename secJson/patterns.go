package secjson

import (
	"regexp"
	"strings"
)

type sensPattern struct {
	re       *regexp.Regexp
	typeName string
	category Category
	severity Severity
	message  string
}

type sensField struct {
	re       *regexp.Regexp
	typeName string
	category Category
	severity Severity
	message  string
}

var sensitivePatterns = []sensPattern{
	{
		re:       regexp.MustCompile(`^[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]$`),
		typeName: "id_card_cn",
		category: CategoryIdentity,
		severity: SeverityCritical,
		message:  "中国大陆身份证号，属于强监管个人身份标识",
	},
	{
		re:       regexp.MustCompile(`^[1-9]\d{5}\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]$`),
		typeName: "id_card_cn_18",
		category: CategoryIdentity,
		severity: SeverityCritical,
		message:  "中国大陆18位身份证号",
	},
	{
		re:       regexp.MustCompile(`^\d{15}$`),
		typeName: "id_card_cn_15",
		category: CategoryIdentity,
		severity: SeverityHigh,
		message:  "中国大陆15位旧版身份证号",
	},
	{
		re:       regexp.MustCompile(`^1[3-9]\d{9}$`),
		typeName: "phone_cn",
		category: CategoryPrivacy,
		severity: SeverityHigh,
		message:  "中国大陆手机号码",
	},
	{
		re:       regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		typeName: "email",
		category: CategoryPrivacy,
		severity: SeverityMedium,
		message:  "电子邮箱地址，可用于精准定位和钓鱼",
	},
	{
		re:       regexp.MustCompile(`^(?:sk|pk|api[_-]?key|secret|token|access[_-]?key)[-_]?[a-zA-Z0-9]{20,}`),
		typeName: "api_key",
		category: CategoryCredential,
		severity: SeverityCritical,
		message:  "API密钥或访问令牌，泄露可导致未授权访问",
	},
	{
		re:       regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`),
		typeName: "base64_sensitive",
		category: CategoryCredential,
		severity: SeverityMedium,
		message:  "长Base64编码串，可能包含令牌或加密数据",
	},
	{
		re:       regexp.MustCompile(`^(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+$`),
		typeName: "auth_header",
		category: CategoryCredential,
		severity: SeverityCritical,
		message:  "HTTP认证头，包含可直接使用的凭证",
	},
	{
		re:       regexp.MustCompile(`^[A-Za-z0-9+/]{32,}={0,2}$`),
		typeName: "jwt_or_token",
		category: CategoryCredential,
		severity: SeverityHigh,
		message:  "疑似JWT Token或会话令牌",
	},
	{
		re:       regexp.MustCompile(`^eyJ[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+$`),
		typeName: "jwt_token",
		category: CategoryCredential,
		severity: SeverityCritical,
		message:  "JWT（JSON Web Token），包含用户身份和权限信息",
	},
	{
		re:       regexp.MustCompile(`^\d{13,19}$`),
		typeName: "bank_card_potential",
		category: CategoryFinance,
		severity: SeverityHigh,
		message:  "疑似银行卡号（13-19位数字），需Luhn算法验证",
	},
	{
		re:       regexp.MustCompile(`^(?:\d[ -]*?){13,16}$`),
		typeName: "credit_card",
		category: CategoryFinance,
		severity: SeverityCritical,
		message:  "信用卡号，受PCI-DSS规范保护",
	},
	{
		re:       regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
		typeName: "uuid",
		category: CategoryInternal,
		severity: SeverityLow,
		message:  "UUID标识符，可能关联内部系统对象",
	},
	{
		re:       regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`),
		typeName: "ip_address",
		category: CategoryPrivacy,
		severity: SeverityLow,
		message:  "IPv4地址，在GDPR下属于个人数据",
	},
	{
		re:       regexp.MustCompile(`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`),
		typeName: "ipv6_address",
		category: CategoryPrivacy,
		severity: SeverityLow,
		message:  "IPv6地址，在GDPR下属于个人数据",
	},
}

var sensitiveFields = []sensField{
	{regexp.MustCompile(`^(?:id_card|card_id|idcard|identity_card)$`), "id_card_field", CategoryIdentity, SeverityCritical, "身份证号字段"},
	{regexp.MustCompile(`^(?:phone|mobile|tel|telephone|cell)$`), "phone_field", CategoryPrivacy, SeverityHigh, "手机/电话号码字段"},
	{regexp.MustCompile(`^(?:email|mail|e_mail)$`), "email_field", CategoryPrivacy, SeverityMedium, "邮箱字段"},
	{regexp.MustCompile(`^(?:password|passwd|pwd|secret|pass)$`), "password_field", CategoryCredential, SeverityCritical, "密码/密钥字段"},
	{regexp.MustCompile(`^(?:token|jwt|access_token|refresh_token|api_key|apikey|auth)$`), "token_field", CategoryCredential, SeverityCritical, "令牌/凭证字段"},
	{regexp.MustCompile(`^(?:ssn|social_security|sin)$`), "ssn_field", CategoryIdentity, SeverityCritical, "社保号/社会安全号"},
	{regexp.MustCompile(`^(?:passport|visa)$`), "passport_field", CategoryIdentity, SeverityHigh, "护照/签证字段"},
	{regexp.MustCompile(`^(?:credit_card|card_number|bank_card|bankcard|debit_card)$`), "bank_card_field", CategoryFinance, SeverityCritical, "银行卡号字段"},
	{regexp.MustCompile(`^(?:cvv|cvc|cvv2|cid)$`), "cvv_field", CategoryFinance, SeverityCritical, "CVV/CVC安全码字段"},
	{regexp.MustCompile(`^(?:iban|swift|routing|account_number)$`), "account_field", CategoryFinance, SeverityHigh, "银行账户相关字段"},
	{regexp.MustCompile(`^(?:pin|pay_password|transaction_password|payment_code)$`), "pin_field", CategoryFinance, SeverityCritical, "支付密码字段"},
	{regexp.MustCompile(`^(?:face|fingerprint|biometric|face_id|touch_id)$`), "bio_field", CategoryBiometric, SeverityCritical, "生物特征字段"},
	{regexp.MustCompile(`^(?:api_key|secret_key|private_key|encryption_key|master_key)$`), "key_field", CategoryCredential, SeverityCritical, "密钥字段"},
	{regexp.MustCompile(`^(?:salary|income|balance|amount)$`), "finance_field", CategoryFinance, SeverityMedium, "财务信息字段"},
	{regexp.MustCompile(`^(?:address|location|gps|latitude|longitude)$`), "address_field", CategoryPrivacy, SeverityMedium, "地址/位置字段"},
	{regexp.MustCompile(`^(?:birthday|birth_date|age|gender)$`), "privacy_field", CategoryPrivacy, SeverityMedium, "个人隐私字段"},
	{regexp.MustCompile(`^(?:ip_address|client_ip|remote_addr|user_ip)$`), "ip_field", CategoryPrivacy, SeverityLow, "IP地址字段"},
	{regexp.MustCompile(`^(?:mother|father|spouse|child|family)$`), "family_field", CategoryPrivacy, SeverityMedium, "家庭成员信息"},
}

func LuhnCheck(cardNumber string) bool {
	sum := 0
	isSecond := false

	for i := len(cardNumber) - 1; i >= 0; i-- {
		d := int(cardNumber[i] - '0')
		if isSecond {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		isSecond = !isSecond
	}
	return sum%10 == 0
}

func IsValidBankCard(cardNumber string) bool {
	if len(cardNumber) < 13 || len(cardNumber) > 19 {
		return false
	}
	n := cardNumber
	if strings.ContainsAny(n, " -") {
		n = strings.Map(func(r rune) rune {
			if r == ' ' || r == '-' {
				return -1
			}
			return r
		}, n)
	}
	for _, c := range n {
		if c < '0' || c > '9' {
			return false
		}
	}
	return LuhnCheck(n)
}