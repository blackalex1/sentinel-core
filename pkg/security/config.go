package security

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PortAction defines the reaction when a connection to a sensitive port is detected.
type PortAction string

const (
	PortActionAlert PortAction = "alert"
	PortActionBlock PortAction = "block"
	PortActionKill  PortAction = "kill"
)

// SecurityConfig holds all configurable parameters for Sentinel-Core security subsystems.
type SecurityConfig struct {
	Enabled     bool              `json:"enabled"`
	PortGuard   PortGuardConfig   `json:"port_guard"`
	RateLimiter RateLimiterConfig `json:"rate_limiter"`
	KillSwitch  KillSwitchConfig  `json:"kill_switch"`
	Integrity   IntegrityConfig   `json:"integrity"`
	Filter      FilterConfig      `json:"filter"`
	Whitelist   WhitelistConfig   `json:"whitelist"`
}

// PortGuardConfig defines rules for protecting sensitive system/network ports.
type PortGuardConfig struct {
	Enabled            bool       `json:"enabled"`
	SensitivePorts     []int      `json:"sensitive_ports"`
	Action             PortAction `json:"action"`
	ScanThreshold      int        `json:"scan_threshold"`       // Max unique port probes before flagged as scan
	ScanWindowSeconds  int        `json:"scan_window_seconds"` // Time window for scan detection
	AutoBanScanner     bool       `json:"auto_ban_scanner"`
}

// RateLimiterConfig defines token-bucket traffic and request rate limiting.
type RateLimiterConfig struct {
	Enabled                bool    `json:"enabled"`
	RequestsPerSecond      float64 `json:"requests_per_second"`
	Burst                  int     `json:"burst"`
	BanThresholdViolations int     `json:"ban_threshold_violations"`
	BanDurationSeconds     int     `json:"ban_duration_seconds"`
}

// KillSwitchConfig defines fail-safe network isolation and leak prevention.
type KillSwitchConfig struct {
	Enabled        bool     `json:"enabled"`
	BlockIPv6      bool     `json:"block_ipv6"`
	AllowLocalLAN  bool     `json:"allow_local_lan"`
	StrictDNS      bool     `json:"strict_dns"`
	AllowedSubnets []string `json:"allowed_subnets"`
}

// IntegrityConfig defines cryptographic validation and config sanitization.
type IntegrityConfig struct {
	SanitizeConfigs    bool `json:"sanitize_configs"`
	BlockCloudMetadata bool `json:"block_cloud_metadata"` // Blocks 169.254.169.254 AWS/GCP/Azure metadata
	VerifySignatures   bool `json:"verify_signatures"`
	ZeroizeOnDrop      bool `json:"zeroize_on_drop"`      // Securely wipe keys from memory after use
}

// FilterConfig defines Threat Intelligence and domain/IP content filtering.
type FilterConfig struct {
	Enabled              bool     `json:"enabled"`
	BlockMalware         bool     `json:"block_malware"`
	BlockPhishing        bool     `json:"block_phishing"`
	BlockMiners          bool     `json:"block_miners"`
	BlockAds             bool     `json:"block_ads"`
	CustomBlockedDomains []string `json:"custom_blocked_domains"`
	CustomAllowedDomains []string `json:"custom_allowed_domains"`
	CustomBlockedIPs     []string `json:"custom_blocked_ips"`
}

// WhitelistConfig defines protected processes and IP ranges for self-protection.
type WhitelistConfig struct {
	Processes []string `json:"processes"`
	IPs       []string `json:"ips"`
}

// DefaultSecurityConfig returns production-ready secure default parameters.
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Enabled: true,
		PortGuard: PortGuardConfig{
			Enabled: true,
			SensitivePorts: []int{
				22,    // SSH
				3389,  // RDP
				8006,  // Proxmox VE Web API
				5432,  // PostgreSQL
				3306,  // MySQL / MariaDB
				27017, // MongoDB
				6379,  // Redis
				2375,  // Docker daemon unencrypted
				2376,  // Docker daemon TLS
			},
			Action:            PortActionBlock,
			ScanThreshold:     5,
			ScanWindowSeconds: 10,
			AutoBanScanner:    true,
		},
		RateLimiter: RateLimiterConfig{
			Enabled:                true,
			RequestsPerSecond:      50.0,
			Burst:                  100,
			BanThresholdViolations: 20,
			BanDurationSeconds:     300, // 5 minutes
		},
		KillSwitch: KillSwitchConfig{
			Enabled:       true,
			BlockIPv6:     true,
			AllowLocalLAN: true,
			StrictDNS:     true,
			AllowedSubnets: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"127.0.0.0/8",
			},
		},
		Integrity: IntegrityConfig{
			SanitizeConfigs:    true,
			BlockCloudMetadata: true,
			VerifySignatures:   false,
			ZeroizeOnDrop:      true,
		},
		Filter: FilterConfig{
			Enabled:              true,
			BlockMalware:         true,
			BlockPhishing:        true,
			BlockMiners:          true,
			BlockAds:             false,
			CustomBlockedDomains: make([]string, 0),
			CustomAllowedDomains: make([]string, 0),
			CustomBlockedIPs:     make([]string, 0),
		},
		Whitelist: WhitelistConfig{
			Processes: []string{
				"sentinel-core",
				"sentinel-core.exe",
				"sing-box",
				"sing-box.exe",
				"xray",
				"xray.exe",
				"hysteria",
				"hysteria.exe",
				"ansible",
				"ansible-playbook",
				"pveproxy",
				"sshd",
				"dockerd",
			},
			IPs: []string{
				"127.0.0.1",
				"::1",
			},
		},
	}
}

// Validate ensures that all provided configuration values are valid.
func (c *SecurityConfig) Validate() error {
	if c.RateLimiter.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate_limiter.requests_per_second must be > 0, got %f", c.RateLimiter.RequestsPerSecond)
	}
	if c.RateLimiter.Burst <= 0 {
		return fmt.Errorf("rate_limiter.burst must be > 0, got %d", c.RateLimiter.Burst)
	}
	if c.PortGuard.ScanThreshold <= 0 {
		return fmt.Errorf("port_guard.scan_threshold must be > 0, got %d", c.PortGuard.ScanThreshold)
	}
	switch c.PortGuard.Action {
	case PortActionAlert, PortActionBlock, PortActionKill:
	case "":
		c.PortGuard.Action = PortActionBlock
	default:
		return fmt.Errorf("invalid port_guard.action: %s (must be alert, block, or kill)", c.PortGuard.Action)
	}
	return nil
}

// ToJSON serializes the config to a formatted JSON string.
func (c *SecurityConfig) ToJSON() (string, error) {
	bytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// FromJSON parses a JSON string into the SecurityConfig, filling missing fields with defaults.
func FromJSON(jsonStr string) (*SecurityConfig, error) {
	cfg := DefaultSecurityConfig()
	if strings.TrimSpace(jsonStr) == "" {
		return &cfg, nil
	}
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse security config JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SecurityFieldSchema represents metadata for the UI Settings Tab in Panel / Desktop / Mobile.
type SecurityFieldSchema struct {
	Key          string                 `json:"key"`
	Type         string                 `json:"type"` // boolean, number, string, select, tags
	Label        string                 `json:"label"`
	Description  string                 `json:"description"`
	DefaultValue interface{}            `json:"default_value"`
	Options      []string               `json:"options,omitempty"`
	Category     string                 `json:"category"`
	Validation   map[string]interface{} `json:"validation,omitempty"`
}

// GenerateSecuritySchema returns a dynamic schema describing the UI fields for panel and client apps.
func GenerateSecuritySchema(lang string) []SecurityFieldSchema {
	isRU := strings.ToLower(lang) == "ru"

	if isRU {
		return []SecurityFieldSchema{
			// Категория: Защита портов (Port Guard & IPS)
			{
				Key:          "port_guard.enabled",
				Type:         "boolean",
				Label:        "Активная защита портов (IPS)",
				Description:  "Мониторинг и блокировка попыток несанкционированного доступа к чувствительным портам",
				DefaultValue: true,
				Category:     "port_guard",
			},
			{
				Key:          "port_guard.sensitive_ports",
				Type:         "tags",
				Label:        "Чувствительные порты",
				Description:  "Список защищаемых портов (SSH 22, RDP 3389, Proxmox 8006, СУБД 5432/3306 и др.)",
				DefaultValue: []int{22, 3389, 8006, 5432, 3306, 27017, 6379, 2375, 2376},
				Category:     "port_guard",
			},
			{
				Key:          "port_guard.action",
				Type:         "select",
				Label:        "Действие при нарушении",
				Description:  "Реакция системы при обращении к защищенному порту",
				DefaultValue: "block",
				Options:      []string{"alert", "block", "kill"},
				Category:     "port_guard",
			},
			{
				Key:          "port_guard.scan_threshold",
				Type:         "number",
				Label:        "Порог обнаружения сканирования",
				Description:  "Количество попыток подключения к закрытым портам до признания источника сканером",
				DefaultValue: 5,
				Category:     "port_guard",
			},
			{
				Key:          "port_guard.auto_ban_scanner",
				Type:         "boolean",
				Label:        "Авто-бан сканеров портов",
				Description:  "Автоматически блокировать IP-адрес при обнаружении порт-сканирования (nmap/masscan)",
				DefaultValue: true,
				Category:     "port_guard",
			},

			// Категория: Ограничение соединений (Rate Limiting)
			{
				Key:          "rate_limiter.enabled",
				Type:         "boolean",
				Label:        "Защита от флуда и DDoS (Rate Limiter)",
				Description:  "Ограничение интенсивности входящих и исходящих соединений",
				DefaultValue: true,
				Category:     "rate_limiter",
			},
			{
				Key:          "rate_limiter.requests_per_second",
				Type:         "number",
				Label:        "Макс. запросов в секунду (RPS)",
				Description:  "Базовая скорость пропускания новых соединений от одного клиента",
				DefaultValue: 50.0,
				Category:     "rate_limiter",
			},
			{
				Key:          "rate_limiter.burst",
				Type:         "number",
				Label:        "Пиковый лимит (Burst)",
				Description:  "Максимально допустимый мгновенный всплеск соединений",
				DefaultValue: 100,
				Category:     "rate_limiter",
			},
			{
				Key:          "rate_limiter.ban_duration_seconds",
				Type:         "number",
				Label:        "Длительность временного бана (сек)",
				Description:  "Время изоляции нарушителя в секундах (по умолчанию 300 сек = 5 мин)",
				DefaultValue: 300,
				Category:     "rate_limiter",
			},

			// Категория: Защита от утечек (KillSwitch)
			{
				Key:          "kill_switch.enabled",
				Type:         "boolean",
				Label:        "Kill-Switch (Аварийная изоляция)",
				Description:  "Блокировать весь нетуннелированный интернет-трафик при разрыве VPN-сессии",
				DefaultValue: true,
				Category:     "kill_switch",
			},
			{
				Key:          "kill_switch.strict_dns",
				Type:         "boolean",
				Label:        "Защита от утечек DNS",
				Description:  "Принудительно направлять DNS-запросы только через зашифрованные DNS-серверы ядра",
				DefaultValue: true,
				Category:     "kill_switch",
			},
			{
				Key:          "kill_switch.block_ipv6",
				Type:         "boolean",
				Label:        "Блокировка утечек IPv6",
				Description:  "Блокировать IPv6-трафик, если серверная нода работает только по IPv4",
				DefaultValue: true,
				Category:     "kill_switch",
			},
			{
				Key:          "kill_switch.allow_local_lan",
				Type:         "boolean",
				Label:        "Разрешить локальную сеть (LAN Bypass)",
				Description:  "Сохранять доступ к роутеру и локальным устройствам (192.168.x.x, 10.x.x.x)",
				DefaultValue: true,
				Category:     "kill_switch",
			},

			// Категория: Фильтрация угроз (Threat Filter)
			{
				Key:          "filter.enabled",
				Type:         "boolean",
				Label:        "Фильтрация угроз (Threat Shield)",
				Description:  "Автоматическая блокировка вредоносных, фишинговых и мошеннических ресурсов",
				DefaultValue: true,
				Category:     "filter",
			},
			{
				Key:          "filter.block_malware",
				Type:         "boolean",
				Label:        "Блокировать вредоносное ПО",
				Description:  "Блокировка C2-серверов ботнетов, вирусов и эксплойтов",
				DefaultValue: true,
				Category:     "filter",
			},
			{
				Key:          "filter.block_phishing",
				Type:         "boolean",
				Label:        "Блокировать фишинг",
				Description:  "Защита от поддельных страниц банков и сервисов",
				DefaultValue: true,
				Category:     "filter",
			},
			{
				Key:          "filter.block_miners",
				Type:         "boolean",
				Label:        "Блокировать скрытый майнинг",
				Description:  "Блокировка браузерного криптомайнинга и пулов",
				DefaultValue: true,
				Category:     "filter",
			},
			{
				Key:          "filter.block_ads",
				Type:         "boolean",
				Label:        "Блокировать рекламу и трекеры",
				Description:  "Фильтрация баннерных сетей и систем слежки",
				DefaultValue: false,
				Category:     "filter",
			},

			// Категория: Целостность (Integrity)
			{
				Key:          "integrity.block_cloud_metadata",
				Type:         "boolean",
				Label:        "Блокировка Cloud Metadata (SSRF)",
				Description:  "Запрет доступа к 169.254.169.254 (защита от кражи IAM-токенов в облаках)",
				DefaultValue: true,
				Category:     "integrity",
			},
			{
				Key:          "integrity.sanitize_configs",
				Type:         "boolean",
				Label:        "Санитизация конфигураций",
				Description:  "Проверка входящих конфигов на отсутствие небезопасных параметров и скриптов",
				DefaultValue: true,
				Category:     "integrity",
			},
		}
	}

	// English localization
	return []SecurityFieldSchema{
		{
			Key:          "port_guard.enabled",
			Type:         "boolean",
			Label:        "Active Port Guard (IPS)",
			Description:  "Monitor and block unauthorized access attempts to sensitive ports",
			DefaultValue: true,
			Category:     "port_guard",
		},
		{
			Key:          "port_guard.sensitive_ports",
			Type:         "tags",
			Label:        "Sensitive Ports",
			Description:  "List of monitored ports (SSH 22, RDP 3389, Proxmox 8006, DBs 5432/3306, etc.)",
			DefaultValue: []int{22, 3389, 8006, 5432, 3306, 27017, 6379, 2375, 2376},
			Category:     "port_guard",
		},
		{
			Key:          "port_guard.action",
			Type:         "select",
			Label:        "Action on Violation",
			Description:  "Response action upon connection to a protected port",
			DefaultValue: "block",
			Options:      []string{"alert", "block", "kill"},
			Category:     "port_guard",
		},
		{
			Key:          "port_guard.scan_threshold",
			Type:         "number",
			Label:        "Port Scan Threshold",
			Description:  "Number of unique probes before source is identified as scanner",
			DefaultValue: 5,
			Category:     "port_guard",
		},
		{
			Key:          "port_guard.auto_ban_scanner",
			Type:         "boolean",
			Label:        "Auto-Ban Port Scanners",
			Description:  "Automatically ban IP address on port scan detection",
			DefaultValue: true,
			Category:     "port_guard",
		},
		{
			Key:          "rate_limiter.enabled",
			Type:         "boolean",
			Label:        "Rate Limiter & Anti-Flood",
			Description:  "Limit connection frequency to prevent flooding and abuse",
			DefaultValue: true,
			Category:     "rate_limiter",
		},
		{
			Key:          "rate_limiter.requests_per_second",
			Type:         "number",
			Label:        "Max Requests Per Second (RPS)",
			Description:  "Token-bucket baseline rate per client/IP",
			DefaultValue: 50.0,
			Category:     "rate_limiter",
		},
		{
			Key:          "rate_limiter.burst",
			Type:         "number",
			Label:        "Burst Capacity",
			Description:  "Maximum allowed instantaneous burst capacity",
			DefaultValue: 100,
			Category:     "rate_limiter",
		},
		{
			Key:          "rate_limiter.ban_duration_seconds",
			Type:         "number",
			Label:        "Ban Duration (Seconds)",
			Description:  "Temporary ban isolation time (default 300s = 5m)",
			DefaultValue: 300,
			Category:     "rate_limiter",
		},
		{
			Key:          "kill_switch.enabled",
			Type:         "boolean",
			Label:        "Kill-Switch Protection",
			Description:  "Block all non-tunneled internet traffic if VPN disconnects",
			DefaultValue: true,
			Category:     "kill_switch",
		},
		{
			Key:          "kill_switch.strict_dns",
			Type:         "boolean",
			Label:        "DNS Leak Protection",
			Description:  "Enforce routing of DNS exclusively via core encrypted resolvers",
			DefaultValue: true,
			Category:     "kill_switch",
		},
		{
			Key:          "kill_switch.block_ipv6",
			Type:         "boolean",
			Label:        "Block IPv6 Leaks",
			Description:  "Block IPv6 traffic when proxy node is IPv4-only",
			DefaultValue: true,
			Category:     "kill_switch",
		},
		{
			Key:          "kill_switch.allow_local_lan",
			Type:         "boolean",
			Label:        "Allow Local LAN Bypass",
			Description:  "Keep local router and LAN devices reachable (192.168.x.x, 10.x.x.x)",
			DefaultValue: true,
			Category:     "kill_switch",
		},
		{
			Key:          "filter.enabled",
			Type:         "boolean",
			Label:        "Threat Shield Filter",
			Description:  "Automatically filter out malicious, phishing, and mining domains",
			DefaultValue: true,
			Category:     "filter",
		},
		{
			Key:          "filter.block_malware",
			Type:         "boolean",
			Label:        "Block Malware & Botnets",
			Description:  "Block known malware command & control hosts",
			DefaultValue: true,
			Category:     "filter",
		},
		{
			Key:          "filter.block_phishing",
			Type:         "boolean",
			Label:        "Block Phishing Sites",
			Description:  "Protect against fraudulent credential harvesting portals",
			DefaultValue: true,
			Category:     "filter",
		},
		{
			Key:          "filter.block_miners",
			Type:         "boolean",
			Label:        "Block Crypto Miners",
			Description:  "Block unauthorized browser and script mining pools",
			DefaultValue: true,
			Category:     "filter",
		},
		{
			Key:          "filter.block_ads",
			Type:         "boolean",
			Label:        "Block Ads & Trackers",
			Description:  "Filter out telemetry, analytics, and advertising networks",
			DefaultValue: false,
			Category:     "filter",
		},
		{
			Key:          "integrity.block_cloud_metadata",
			Type:         "boolean",
			Label:        "Block Cloud Metadata (SSRF)",
			Description:  "Prevent requests to 169.254.169.254 (cloud IAM token protection)",
			DefaultValue: true,
			Category:     "integrity",
		},
		{
			Key:          "integrity.sanitize_configs",
			Type:         "boolean",
			Label:        "Sanitize Configurations",
			Description:  "Audit incoming proxy configs for dangerous or invalid parameters",
			DefaultValue: true,
			Category:     "integrity",
		},
	}
}
