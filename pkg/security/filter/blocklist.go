package filter

// ThreatCategory defines the classification of a blocked resource.
type ThreatCategory string

const (
	CategoryMalware  ThreatCategory = "MALWARE"
	CategoryPhishing ThreatCategory = "PHISHING"
	CategoryMiner    ThreatCategory = "CRYPTO_MINER"
	CategoryAdware   ThreatCategory = "AD_TRACKER"
	CategoryCustom   ThreatCategory = "CUSTOM_BLOCK"
)

// DefaultThreatFeeds contains known high-risk domains for default protection.
var (
	DefaultMalwareDomains = []string{
		"c2-panel.su",
		"dark-trojan-bot.net",
		"evil-payloads.org",
		"stealer-logs.cc",
		"cobaltstrike-beacon.biz",
		"rat-connector.xyz",
	}

	DefaultPhishingDomains = []string{
		"login-security-update-verify.com",
		"secure-banking-auth-portal.com",
		"sberbank-login-online.cc",
		"tinkoff-bonus-claim.ru.com",
		"gosuslugi-verif.site",
		"telegram-auth-qr.online",
	}

	DefaultMinerDomains = []string{
		"coinhive.com",
		"crypto-loot.com",
		"coin-have.com",
		"minr.pw",
		"xmr-pool.net",
		"minexmr.com",
		"supportxmr.com",
	}

	DefaultAdTrackerDomains = []string{
		"adservice.google.com",
		"pagead2.googlesyndication.com",
		"telemetry.microsoft.com",
		"app-measurement.com",
		"analytics.facebook.com",
		"metrics.icloud.com",
	}
)
