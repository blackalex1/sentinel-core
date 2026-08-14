package matrix

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// ProtocolCapability defines allowed configurations for a specific protocol in the UI
type ProtocolCapability struct {
	Protocol            string              `json:"protocol"`            // "vless", "hysteria2", "trojan", etc.
	DisplayName         string              `json:"displayName"`         // "VLESS", "Hysteria 2", "Trojan", etc.
	Description         string              `json:"description,omitempty"`
	DefaultPort         int                 `json:"defaultPort"`         // 443
	SupportedEngines    []string            `json:"supportedEngines"`    // ["xray-core", "sing-box"]
	SupportedTransports []string            `json:"supportedTransports"` // ["tcp", "ws", "grpc", "xhttp"]
	SupportedSecurity   []string            `json:"supportedSecurity"`   // ["reality", "tls", "none"]
	SupportedFlows      map[string][]string `json:"supportedFlows,omitempty"` // {"reality": ["xtls-rprx-vision"], "tls": ["xtls-rprx-vision", "none"]}
	SupportedCiphers    []string            `json:"supportedCiphers,omitempty"`
	Features            []string            `json:"features,omitempty"` // ["port_hopping", "salamander_obfs", "post_quantum"]
}

// EngineOption represents a core engine selectable in the dropdown
type EngineOption struct {
	ID          string   `json:"id"`          // "xray-core", "sing-box", "hysteria2"
	Name        string   `json:"name"`        // "Xray-core", "sing-box", "Hysteria 2"
	Description string   `json:"description"`
	Protocols   []string `json:"protocols"`   // ["vless", "trojan", ...]
}

// SniffingOption represents a sniffing protocol toggle in the modal
type SniffingOption struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default"`
}

// ConfigurationSchema is the master capability matrix sent to Sentinel-Panel frontend
type ConfigurationSchema struct {
	Language        string                        `json:"language"`
	Engines         []EngineOption                `json:"engines"`
	Protocols       map[string]ProtocolCapability `json:"protocols"`
	SniffingOptions []SniffingOption              `json:"sniffingOptions"`
}

// GetConfigurationSchema returns the dynamic schema localized for the requested language ("ru" / "en")
func GetConfigurationSchema(lang string) *ConfigurationSchema {
	langLower := strings.ToLower(lang)
	if langLower == "" {
		langLower = string(i18n.GetLocale())
	}
	if langLower != "en" && langLower != "ru" {
		langLower = "ru"
	}

	if langLower == "en" {
		return &ConfigurationSchema{
			Language: "en",
			Engines: []EngineOption{
				{
					ID:          "xray-core",
					Name:        "Xray-core",
					Description: "Reference engine for VLESS Reality, Post-Quantum X25519Kyber768, and XTLS Vision",
					Protocols:   []string{ast.ProtoVLESS, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoVMess, ast.ProtoWireGuard, ast.ProtoHysteria2},
				},
				{
					ID:          "sing-box",
					Name:        "sing-box",
					Description: "All-in-one universal core: Native Hysteria 2, TUIC v5, ShadowTLS, Wintun, and Smart Routing",
					Protocols:   []string{ast.ProtoVLESS, ast.ProtoHysteria2, ast.ProtoTUIC, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoShadowTLS, ast.ProtoWireGuard, ast.ProtoVMess},
				},
				{
					ID:          "hysteria2",
					Name:        "Hysteria 2 (Official)",
					Description: "Official Hysteria 2 server with HTTP Webhook Auth Backend and Port Hopping",
					Protocols:   []string{ast.ProtoHysteria2},
				},
			},
			Protocols: map[string]ProtocolCapability{
				ast.ProtoVLESS: {
					Protocol:            ast.ProtoVLESS,
					DisplayName:         "VLESS",
					Description:         "Modern high-speed protocol with XTLS Vision and Reality camouflage",
					DefaultPort:         443,
					SupportedEngines:    []string{"xray-core", "sing-box"},
					SupportedTransports: []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade"},
					SupportedSecurity:   []string{"reality", "tls", "none"},
					SupportedFlows: map[string][]string{
						"reality": {"xtls-rprx-vision", "none"},
						"tls":     {"xtls-rprx-vision", "none"},
						"none":    {"none"},
					},
					Features: []string{"post_quantum", "reality_short_ids", "spider_x"},
				},
				ast.ProtoHysteria2: {
					Protocol:            ast.ProtoHysteria2,
					DisplayName:         "Hysteria 2",
					Description:         "UDP/QUIC protocol with Brutal BBR congestion control and Port Hopping",
					DefaultPort:         443,
					SupportedEngines:    []string{"sing-box", "hysteria2", "xray-core"},
					SupportedTransports: []string{"quic"},
					SupportedSecurity:   []string{"tls"},
					Features:            []string{"port_hopping", "salamander_obfs", "bandwidth_up_down", "webhook_auth"},
				},
				ast.ProtoTrojan: {
					Protocol:            ast.ProtoTrojan,
					DisplayName:         "Trojan",
					Description:         "HTTPS camouflage protocol mimicking legitimate web traffic",
					DefaultPort:         443,
					SupportedEngines:    []string{"xray-core", "sing-box"},
					SupportedTransports: []string{"tcp", "ws", "grpc"},
					SupportedSecurity:   []string{"tls"},
				},
				ast.ProtoShadowsocks: {
					Protocol:         ast.ProtoShadowsocks,
					DisplayName:      "Shadowsocks",
					Description:      "AEAD and 2022-Blake3 encrypted proxy protocol",
					DefaultPort:      8388,
					SupportedEngines:  []string{"xray-core", "sing-box"},
					SupportedSecurity: []string{"none"},
					SupportedCiphers: []string{
						"2022-blake3-aes-128-gcm",
						"2022-blake3-aes-256-gcm",
						"2022-blake3-chacha20-poly1305",
						"aes-128-gcm",
						"aes-256-gcm",
						"chacha20-ietf-poly1305",
					},
				},
				ast.ProtoTUIC: {
					Protocol:            ast.ProtoTUIC,
					DisplayName:         "TUIC v5",
					Description:         "0-RTT QUIC proxy with native BBR congestion control",
					DefaultPort:         8443,
					SupportedEngines:    []string{"sing-box"},
					SupportedTransports: []string{"quic"},
					SupportedSecurity:   []string{"tls"},
					Features:            []string{"congestion_control_bbr", "zero_rtt"},
				},
				ast.ProtoShadowTLS: {
					Protocol:          ast.ProtoShadowTLS,
					DisplayName:       "ShadowTLS",
					Description:       "Real TLS handshake imitation with third-party domain validation",
					DefaultPort:       443,
					SupportedEngines:   []string{"sing-box"},
					SupportedSecurity: []string{"shadowtls"},
					Features:          []string{"shadowtls_v3", "handshake_mimic"},
				},
				ast.ProtoWireGuard: {
					Protocol:         ast.ProtoWireGuard,
					DisplayName:      "WireGuard",
					Description:      "Modern kernel-level cryptographic VPN protocol",
					DefaultPort:      51820,
					SupportedEngines:  []string{"xray-core", "sing-box"},
					SupportedSecurity: []string{"none"},
					Features:          []string{"reserved_bytes", "preshared_key"},
				},
			},
			SniffingOptions: []SniffingOption{
				{ID: "tls", DisplayName: "TLS (SNI inspection)", Description: "Extracts domain names from TLS ClientHello packets", Default: true},
				{ID: "http", DisplayName: "HTTP (Host header)", Description: "Extracts domain names from plain HTTP Host headers", Default: true},
				{ID: "quic", DisplayName: "QUIC (Initial SNI)", Description: "Extracts domain names from QUIC initial handshakes", Default: true},
				{ID: "fakedns", DisplayName: "FakeDNS (Domain restoration)", Description: "Restores original domains from FakeDNS IP pool", Default: true},
			},
		}
	}

	// Default: Russian
	return &ConfigurationSchema{
		Language: "ru",
		Engines: []EngineOption{
			{
				ID:          "xray-core",
				Name:        "Xray-core",
				Description: "Эталонное ядро для VLESS Reality, Post-Quantum X25519Kyber768 и XTLS Vision",
				Protocols:   []string{ast.ProtoVLESS, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoVMess, ast.ProtoWireGuard, ast.ProtoHysteria2},
			},
			{
				ID:          "sing-box",
				Name:        "sing-box",
				Description: "Универсальный комбайн: нативная Hysteria 2, TUIC v5, ShadowTLS, Wintun и Smart Routing",
				Protocols:   []string{ast.ProtoVLESS, ast.ProtoHysteria2, ast.ProtoTUIC, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoShadowTLS, ast.ProtoWireGuard, ast.ProtoVMess},
			},
			{
				ID:          "hysteria2",
				Name:        "Hysteria 2 (Official)",
				Description: "Официальный сервер Hysteria 2 с HTTP Webhook Auth Backend и Port Hopping",
				Protocols:   []string{ast.ProtoHysteria2},
			},
		},
		Protocols: map[string]ProtocolCapability{
			ast.ProtoVLESS: {
				Protocol:            ast.ProtoVLESS,
				DisplayName:         "VLESS",
				Description:         "Современный легковесный протокол с XTLS Vision и маскировкой Reality",
				DefaultPort:         443,
				SupportedEngines:    []string{"xray-core", "sing-box"},
				SupportedTransports: []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade"},
				SupportedSecurity:   []string{"reality", "tls", "none"},
				SupportedFlows: map[string][]string{
					"reality": {"xtls-rprx-vision", "none"},
					"tls":     {"xtls-rprx-vision", "none"},
					"none":    {"none"},
				},
				Features: []string{"post_quantum", "reality_short_ids", "spider_x"},
			},
			ast.ProtoHysteria2: {
				Protocol:            ast.ProtoHysteria2,
				DisplayName:         "Hysteria 2",
				Description:         "UDP/QUIC протокол с Brutal BBR контролем перегрузок и Port Hopping",
				DefaultPort:         443,
				SupportedEngines:    []string{"sing-box", "hysteria2", "xray-core"},
				SupportedTransports: []string{"quic"},
				SupportedSecurity:   []string{"tls"},
				Features:            []string{"port_hopping", "salamander_obfs", "bandwidth_up_down", "webhook_auth"},
			},
			ast.ProtoTrojan: {
				Protocol:            ast.ProtoTrojan,
				DisplayName:         "Trojan",
				Description:         "Маскировка под валидный HTTPS сайт с проверкой TLS сертификата",
				DefaultPort:         443,
				SupportedEngines:    []string{"xray-core", "sing-box"},
				SupportedTransports: []string{"tcp", "ws", "grpc"},
				SupportedSecurity:   []string{"tls"},
			},
			ast.ProtoShadowsocks: {
				Protocol:         ast.ProtoShadowsocks,
				DisplayName:      "Shadowsocks",
				Description:      "Шифрованный прокси-протокол AEAD и Shadowsocks-2022 Blake3",
				DefaultPort:      8388,
				SupportedEngines:  []string{"xray-core", "sing-box"},
				SupportedSecurity: []string{"none"},
				SupportedCiphers: []string{
					"2022-blake3-aes-128-gcm",
					"2022-blake3-aes-256-gcm",
					"2022-blake3-chacha20-poly1305",
					"aes-128-gcm",
					"aes-256-gcm",
					"chacha20-ietf-poly1305",
				},
			},
			ast.ProtoTUIC: {
				Protocol:            ast.ProtoTUIC,
				DisplayName:         "TUIC v5",
				Description:         "0-RTT QUIC протокол с нативным BBR для нестабильных сетей",
				DefaultPort:         8443,
				SupportedEngines:    []string{"sing-box"},
				SupportedTransports: []string{"quic"},
				SupportedSecurity:   []string{"tls"},
				Features:            []string{"congestion_control_bbr", "zero_rtt"},
			},
			ast.ProtoShadowTLS: {
				Protocol:          ast.ProtoShadowTLS,
				DisplayName:       "ShadowTLS",
				Description:       "Имитация рукопожатия TLS с внешним доверенным сайтом-маскировкой",
				DefaultPort:       443,
				SupportedEngines:   []string{"sing-box"},
				SupportedSecurity: []string{"shadowtls"},
				Features:          []string{"shadowtls_v3", "handshake_mimic"},
			},
			ast.ProtoWireGuard: {
				Protocol:         ast.ProtoWireGuard,
				DisplayName:      "WireGuard",
				Description:      "Быстрый криптографический VPN на уровне ядра с защитой от блокировок",
				DefaultPort:      51820,
				SupportedEngines:  []string{"xray-core", "sing-box"},
				SupportedSecurity: []string{"none"},
				Features:          []string{"reserved_bytes", "preshared_key"},
			},
		},
		SniffingOptions: []SniffingOption{
			{ID: "tls", DisplayName: "TLS (Анализ SNI)", Description: "Извлечение имени домена из TLS ClientHello пакетов", Default: true},
			{ID: "http", DisplayName: "HTTP (Заголовок Host)", Description: "Извлечение имени домена из HTTP заголовка Host", Default: true},
			{ID: "quic", DisplayName: "QUIC (Анализ SNI)", Description: "Извлечение имени домена из начального QUIC пакета", Default: true},
			{ID: "fakedns", DisplayName: "FakeDNS (Восстановление домена)", Description: "Восстановление доменного имени из пула FakeDNS", Default: true},
		},
	}
}
