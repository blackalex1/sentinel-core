package fields

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// BuildBasicTab returns the standard Basic settings tab
func BuildBasicTab(lang string, proto string, defaultPort int) types.TabDefinition {
	loc := i18n.Locale(lang)
	
	basicFields := []types.FormField{
		{
			ID:          "remark",
			TargetField: "remark",
			Type:        "text",
			Label:       i18n.T(loc, "UI_FIELD_REMARK"),
			Placeholder: proto,
			GridColumn:  "col-12",
		},
		{
			ID:          "port",
			TargetField: "port",
			Type:        "port_generator",
			Label:       i18n.T(loc, "UI_FIELD_PORT"),
			Default:     defaultPort,
			GridColumn:  "col-4",
		},
		{
			ID:          "protocol",
			TargetField: "protocol",
			Type:        "select",
			Label:       i18n.T(loc, "UI_FIELD_PROTOCOL"),
			Default:     proto,
			GridColumn:  "col-4",
		},
		{
			ID:          "core",
			TargetField: "core",
			Type:        "select",
			Label:       i18n.T(loc, "UI_FIELD_CORE"),
			GridColumn:  "col-4",
		},
		{
			ID:          "total",
			TargetField: "total",
			Type:        "number",
			Label:       i18n.T(loc, "UI_FIELD_TOTAL_TRAFFIC"),
			Default:     0,
			GridColumn:  "col-4",
		},
		{
			ID:          "expiryTime",
			TargetField: "expiryTime",
			Type:        "number",
			Label:       i18n.T(loc, "UI_FIELD_EXPIRY_DATE"),
			Default:     0,
			GridColumn:  "col-4",
		},
		{
			ID:          "enable",
			TargetField: "enable",
			Type:        "checkbox",
			Label:       i18n.T(loc, "UI_FIELD_ENABLE"),
			Default:     true,
			GridColumn:  "col-4",
		},
		{
			ID:          "externalHost",
			TargetField: "externalHost",
			Type:        "text",
			Label:       i18n.T(loc, "UI_FIELD_EXTERNAL_HOST"),
			GridColumn:  "col-12",
		},
		{
			ID:          "clients",
			TargetField: "settings.clients",
			Type:        "clients_manager",
			Label:       i18n.T(loc, "UI_FIELD_CLIENTS"),
			GridColumn:  "col-12",
		},
	}

	return types.TabDefinition{
		ID:    "basic",
		Title: i18n.T(loc, "UI_TAB_BASIC"),
		Icon:  "fa-sliders",
		Groups: []types.FieldGroup{
			{
				ID:     "basic_group",
				Fields: basicFields,
			},
		},
	}
}

// BuildSniffingTab returns the universal Sniffing settings tab
func BuildSniffingTab(lang string) types.TabDefinition {
	loc := i18n.Locale(lang)
	return types.TabDefinition{
		ID:    "sniffing",
		Title: i18n.T(loc, "UI_TAB_SNIFFING"),
		Icon:  "fa-magnifying-glass",
		Groups: []types.FieldGroup{
			{
				ID: "sniffing_group",
				Fields: []types.FormField{
					{
						ID:          "sniffing_enabled",
						TargetField: "sniffing.enabled",
						Type:        "checkbox",
						Label:       i18n.T(loc, "UI_FIELD_SNIFFING_ENABLE"),
						Default:     true,
						GridColumn:  "col-12",
					},
					{
						ID:          "destOverride",
						TargetField: "sniffing.destOverride",
						Type:        "select_multi",
						Label:       i18n.T(loc, "UI_FIELD_SNIFFING_PROTOCOLS"),
						Default:     []string{"tls", "http", "quic", "fakedns"},
						Options: []types.SelectOption{
							{Value: "tls", Label: "TLS (SNI)"},
							{Value: "http", Label: "HTTP (Host)"},
							{Value: "quic", Label: "QUIC (SNI)"},
							{Value: "fakedns", Label: "FakeDNS"},
						},
						ShowIf:     map[string]interface{}{"sniffing.enabled": true},
						GridColumn: "col-12",
					},
					{
						ID:          "routeOnly",
						TargetField: "sniffing.routeOnly",
						Type:        "checkbox",
						Label:       i18n.T(loc, "UI_FIELD_SNIFFING_ROUTEONLY"),
						Default:     false,
						ShowIf:      map[string]interface{}{"sniffing.enabled": true},
						GridColumn:  "col-12",
					},
				},
			},
		},
	}
}

// BuildAdvancedTab returns the Raw JSON editor tab
func BuildAdvancedTab(lang string) types.TabDefinition {
	loc := i18n.Locale(lang)
	return types.TabDefinition{
		ID:    "advanced",
		Title: i18n.T(loc, "UI_TAB_JSON"),
		Icon:  "fa-code",
		Groups: []types.FieldGroup{
			{
				ID: "json_group",
				Fields: []types.FormField{
					{
						ID:          "rawJson",
						TargetField: "rawJson",
						Type:        "json_editor",
						Label:       i18n.T(loc, "UI_FIELD_RAW_JSON"),
						GridColumn:  "col-12",
					},
				},
			},
		},
	}
}

// BuildVLESSTabDefinitions returns all tabs for VLESS protocol
func BuildVLESSTabDefinitions(lang string, isXray bool) []types.TabDefinition {
	loc := i18n.Locale(lang)
	tabs := []types.TabDefinition{
		BuildBasicTab(lang, ast.ProtoVLESS, 443),
	}

	if isXray {
		// Protocol Tab (Xray VLESS Encryption & Fallbacks)
		tabs = append(tabs, types.TabDefinition{
			ID:    "protocol",
			Title: i18n.T(loc, "UI_TAB_PROTOCOL"),
			Icon:  "fa-arrows-split-up-and-left",
			Groups: []types.FieldGroup{
				{
					ID:    "vless_encryption_group",
					Title: "VLESS Encryption / ML-KEM-768",
					Fields: []types.FormField{
						{
							ID:          "vless_decryption",
							TargetField: "settings.decryption",
							Type:        "keypair_generator",
							Label:       "VLESS Decryption (Расшифрование)",
							GridColumn:  "col-12",
						},
						{
							ID:          "vless_encryption",
							TargetField: "settings.encryption",
							Type:        "text",
							Label:       "VLESS Encryption (Шифрование)",
							GridColumn:  "col-12",
						},
					},
				},
				{
					ID:    "vless_fallbacks_group",
					Title: "Fallbacks (Перенаправление трафика)",
					Fields: []types.FormField{
						{
							ID:          "fallback_dest",
							TargetField: "settings.fallbacks.0.dest",
							Type:        "text",
							Label:       "Целевой адрес (Dest)",
							Placeholder: "80 или 127.0.0.1:8080",
							GridColumn:  "col-6",
						},
						{
							ID:          "fallback_path",
							TargetField: "settings.fallbacks.0.path",
							Type:        "text",
							Label:       "Путь (Path)",
							Placeholder: "/secret",
							GridColumn:  "col-6",
						},
						{
							ID:          "fallback_xver",
							TargetField: "settings.fallbacks.0.xver",
							Type:        "select",
							Label:       "PROXY Protocol (Xver)",
							Default:     "0",
							Options: []types.SelectOption{
								{Value: "0", Label: "Отключено (0)"},
								{Value: "1", Label: "Version 1 (1)"},
								{Value: "2", Label: "Version 2 (2)"},
							},
							GridColumn: "col-6",
						},
						{
							ID:          "fallback_alpn",
							TargetField: "settings.fallbacks.0.alpn",
							Type:        "text",
							Label:       "ALPN",
							Placeholder: "h2,http/1.1",
							GridColumn:  "col-6",
						},
					},
				},
			},
		})
	}

	// Stream Tab
	tabs = append(tabs, types.TabDefinition{
		ID:    "stream",
		Title: i18n.T(loc, "UI_TAB_STREAM"),
		Icon:  "fa-wave-square",
		Groups: []types.FieldGroup{
			{
				ID: "stream_network_group",
				Fields: []types.FormField{
					{
						ID:          "network",
						TargetField: "streamSettings.network",
						Type:        "select",
						Label:       "Транспорт (Network)",
						Default:     "tcp",
						Options: []types.SelectOption{
							{Value: "tcp", Label: "TCP"},
							{Value: "ws", Label: "WebSocket (WS)"},
							{Value: "grpc", Label: "gRPC"},
							{Value: "httpupgrade", Label: "HTTPUpgrade"},
							{Value: "xhttp", Label: "xHTTP (SplitHTTP)"},
							{Value: "h2", Label: "HTTP/2 (H2)"},
							{Value: "mkcp", Label: "mKCP"},
						},
						GridColumn: "col-12",
					},
					{
						ID:          "ws_path",
						TargetField: "streamSettings.wsSettings.path",
						Type:        "text",
						Label:       "WebSocket Path",
						Placeholder: "/ws",
						ShowIf:      map[string]interface{}{"streamSettings.network": "ws"},
						GridColumn:  "col-6",
					},
					{
						ID:          "ws_host",
						TargetField: "streamSettings.wsSettings.headers.Host",
						Type:        "text",
						Label:       "WebSocket Host Header",
						ShowIf:      map[string]interface{}{"streamSettings.network": "ws"},
						GridColumn:  "col-6",
					},
					{
						ID:          "grpc_service_name",
						TargetField: "streamSettings.grpcSettings.serviceName",
						Type:        "text",
						Label:       "gRPC Service Name",
						ShowIf:      map[string]interface{}{"streamSettings.network": "grpc"},
						GridColumn:  "col-6",
					},
					{
						ID:          "grpc_multi_mode",
						TargetField: "streamSettings.grpcSettings.multiMode",
						Type:        "checkbox",
						Label:       "gRPC Multi Mode",
						ShowIf:      map[string]interface{}{"streamSettings.network": "grpc"},
						GridColumn:  "col-6",
					},
					{
						ID:          "xhttp_mode",
						TargetField: "streamSettings.xhttpSettings.mode",
						Type:        "select",
						Label:       "xHTTP Mode",
						Default:     "auto",
						Options: []types.SelectOption{
							{Value: "auto", Label: "auto"},
							{Value: "packet-up", Label: "packet-up"},
							{Value: "stream-up", Label: "stream-up"},
							{Value: "stream-one", Label: "stream-one"},
						},
						ShowIf:     map[string]interface{}{"streamSettings.network": "xhttp"},
						GridColumn: "col-6",
					},
					{
						ID:          "xhttp_path",
						TargetField: "streamSettings.xhttpSettings.path",
						Type:        "text",
						Label:       "xHTTP Path",
						Placeholder: "/",
						ShowIf:      map[string]interface{}{"streamSettings.network": "xhttp"},
						GridColumn:  "col-6",
					},
				},
			},
		},
	})

	// Security Tab
	tabs = append(tabs, types.TabDefinition{
		ID:    "security",
		Title: i18n.T(loc, "UI_TAB_SECURITY"),
		Icon:  "fa-shield-halved",
		Groups: []types.FieldGroup{
			{
				ID: "security_type_group",
				Fields: []types.FormField{
					{
						ID:          "security",
						TargetField: "streamSettings.security",
						Type:        "select",
						Label:       "Режим безопасности (Security)",
						Default:     "reality",
						Options: []types.SelectOption{
							{Value: "reality", Label: "Reality (Рекомендуется)"},
							{Value: "tls", Label: "TLS"},
							{Value: "none", Label: "Без шифрования (None)"},
						},
						GridColumn: "col-12",
					},
				},
			},
			{
				ID:     "reality_settings_group",
				Title:  "Параметры Reality",
				ShowIf: map[string]interface{}{"streamSettings.security": "reality"},
				Fields: []types.FormField{
					{
						ID:          "dest",
						TargetField: "streamSettings.realitySettings.dest",
						Type:        "text",
						Label:       "Целевой сайт (Dest)",
						Placeholder: "www.apple.com:443",
						GridColumn:  "col-6",
					},
					{
						ID:          "serverNames",
						TargetField: "streamSettings.realitySettings.serverNames",
						Type:        "text",
						Label:       "Доменные имена (ServerNames)",
						Placeholder: "www.apple.com",
						GridColumn:  "col-6",
					},
					{
						ID:          "privateKey",
						TargetField: "streamSettings.realitySettings.privateKey",
						Type:        "keypair_generator",
						Label:       "Приватный ключ (Private Key)",
						GridColumn:  "col-6",
					},
					{
						ID:          "publicKey",
						TargetField: "streamSettings.realitySettings.publicKey",
						Type:        "text",
						Label:       "Публичный ключ (Public Key)",
						GridColumn:  "col-6",
					},
					{
						ID:          "shortIds",
						TargetField: "streamSettings.realitySettings.shortIds",
						Type:        "text",
						Label:       "Короткие ID (ShortIds)",
						Placeholder: "8f9c2d1b",
						GridColumn:  "col-6",
					},
					{
						ID:          "spiderX",
						TargetField: "streamSettings.realitySettings.spiderX",
						Type:        "text",
						Label:       "SpiderX",
						Placeholder: "/",
						GridColumn:  "col-6",
					},
				},
			},
		},
	})

	// Sniffing and Advanced tabs
	tabs = append(tabs, BuildSniffingTab(lang))
	tabs = append(tabs, BuildAdvancedTab(lang))

	return tabs
}

// BuildHysteria2TabDefinitions returns all tabs for Hysteria 2
func BuildHysteria2TabDefinitions(lang string) []types.TabDefinition {
	loc := i18n.Locale(lang)
	return []types.TabDefinition{
		BuildBasicTab(lang, ast.ProtoHysteria2, 443),
		{
			ID:    "stream",
			Title: i18n.T(loc, "UI_TAB_STREAM"),
			Icon:  "fa-wave-square",
			Groups: []types.FieldGroup{
				{
					ID:    "hysteria_protection_group",
					Title: "Режим защиты Hysteria 2",
					Fields: []types.FormField{
						{
							ID:          "hysteria_mode",
							TargetField: "streamSettings.hysteria.mode",
							Type:        "select",
							Label:       "Режим защиты",
							Default:     "masq",
							Options: []types.SelectOption{
								{Value: "masq", Label: "Маскировка (Masquerade)"},
								{Value: "obfs", Label: "Обфускация (Obfuscation / Salamander)"},
							},
							GridColumn: "col-12",
						},
						{
							ID:          "obfs_password",
							TargetField: "streamSettings.hysteria.obfsPassword",
							Type:        "password_generator",
							Label:       "Пароль обфускации",
							ShowIf:      map[string]interface{}{"streamSettings.hysteria.mode": "obfs"},
							GridColumn:  "col-12",
						},
						{
							ID:          "masq_type",
							TargetField: "streamSettings.hysteria.masqType",
							Type:        "select",
							Label:       "Тип маскировки",
							Default:     "proxy",
							Options: []types.SelectOption{
								{Value: "proxy", Label: "Проксирование (HTTP Reverse Proxy)"},
								{Value: "file", Label: "Локальный каталог (Static Files)"},
								{Value: "status", Label: "HTTP Status Code"},
							},
							ShowIf:     map[string]interface{}{"streamSettings.hysteria.mode": "masq"},
							GridColumn: "col-6",
						},
						{
							ID:          "masq_value",
							TargetField: "streamSettings.hysteria.masqValue",
							Type:        "text",
							Label:       "URL / Значение маскировки",
							Placeholder: "https://google.com",
							ShowIf:      map[string]interface{}{"streamSettings.hysteria.mode": "masq"},
							GridColumn:  "col-6",
						},
						{
							ID:          "up_mbps",
							TargetField: "streamSettings.hysteria.upMbps",
							Type:        "number",
							Label:       "Лимит отдачи (Up Mbps)",
							Default:     100,
							GridColumn:  "col-6",
						},
						{
							ID:          "down_mbps",
							TargetField: "streamSettings.hysteria.downMbps",
							Type:        "number",
							Label:       "Лимит загрузки (Down Mbps)",
							Default:     100,
							GridColumn:  "col-6",
						},
						{
							ID:          "ignore_client_bandwidth",
							TargetField: "streamSettings.hysteria.ignoreClientBandwidth",
							Type:        "checkbox",
							Label:       "Игнорировать заявленную клиентом скорость",
							Default:     false,
							GridColumn:  "col-12",
						},
						{
							ID:          "sni",
							TargetField: "streamSettings.hysteria.sni",
							Type:        "text",
							Label:       "SNI (Домен сертификата)",
							Placeholder: "yourdomain.com",
							GridColumn:  "col-12",
						},
						{
							ID:          "cert_mode",
							TargetField: "streamSettings.hysteria.certMode",
							Type:        "select",
							Label:       "Сертификат TLS",
							Default:     "self",
							Options: []types.SelectOption{
								{Value: "self", Label: "Самоподписанный сертификат (Self-signed)"},
								{Value: "custom", Label: "Указать пути к файлам сертификата"},
							},
							GridColumn: "col-12",
						},
						{
							ID:          "cert_path",
							TargetField: "streamSettings.hysteria.certPath",
							Type:        "text",
							Label:       "Путь к сертификату (.crt / .pem)",
							Placeholder: "/etc/letsencrypt/live/domain/fullchain.pem",
							ShowIf:      map[string]interface{}{"streamSettings.hysteria.certMode": "custom"},
							GridColumn:  "col-6",
						},
						{
							ID:          "key_path",
							TargetField: "streamSettings.hysteria.keyPath",
							Type:        "text",
							Label:       "Путь к приватному ключу (.key)",
							Placeholder: "/etc/letsencrypt/live/domain/privkey.pem",
							ShowIf:      map[string]interface{}{"streamSettings.hysteria.certMode": "custom"},
							GridColumn:  "col-6",
						},
						{
							ID:          "hop",
							TargetField: "streamSettings.hysteria.hop",
							Type:        "text",
							Label:       "Port Hopping (Диапазон портов)",
							Placeholder: "20000-40000",
							GridColumn:  "col-12",
						},
					},
				},
			},
		},
		BuildSniffingTab(lang),
		BuildAdvancedTab(lang),
	}
}
