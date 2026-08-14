package i18n

// enTranslations contains all English localization strings
var enTranslations = map[string]string{
	// General Status & Errors
	"CORE_INITIALIZED":                   "Sentinel-Core successfully initialized (v%s)",
	"UNKNOWN_ERROR":                      "Unknown core error: %s",
	"INVALID_SYNTAX":                     "Configuration syntax error: %s",
	"UNSUPPORTED_PROTOCOL":               "Protocol '%s' is not supported by core '%s'",
	"ERR_SERVER_NODE_NIL":               "Server node profile cannot be nil",
	"ERR_UNSUPPORTED_PROTOCOL_SUGGEST":   "Core '%s' does not support protocol '%s'. Suggested action: switch core to Sing-box",
	"ERR_PQ_STRICT_MODE":                 "Post-quantum cryptography is enabled for node '%s', but core '%s' (%s) does not support it",
	"ERR_REALITY_UNSUPPORTED":            "Core '%s' does not support Reality security on protocol '%s'",
	"ERR_FLOW_VISION_STRICT":             "Core '%s' does not support XTLS Vision flow ('%s')",

	// Crypto & DB Vault
	"CRYPTO_KEY_TOO_SHORT":               "Database encryption key is too short (minimum 16 characters required)",
	"CRYPTO_TAMPER_DETECTED":             "WARNING: Data tampering or corruption detected in encrypted payload (AEAD tag mismatch)",
	"CRYPTO_DECRYPT_FAILED":              "Failed to decrypt node parameters. Incorrect master key or corrupted data",
	"CRYPTO_ENCRYPT_SUCCESS":             "Data successfully encrypted with AES-256-GCM AEAD",

	// URI Parser
	"PARSER_INVALID_URI":                 "Invalid proxy URI: '%s'",
	"PARSER_UNSUPPORTED_SCHEME":          "Unsupported protocol scheme: '%s'",
	"PARSER_MISSING_HOST":                "Server address is missing from the proxy link",
	"PARSER_MISSING_AUTH":                "Authorization credential (UUID/password) is missing from the proxy link",

	// Capability Matrix & Auto-Negotiation
	"PQ_DOWNGRADED_SINGBOX":              "Reality Post-Quantum TLS (Kyber768) automatically downgraded to standard X25519 for core %s",
	"PQ_STRICT_REJECT":                   "Core '%s' does not support Post-Quantum TLS in strict mode",
	"FLOW_VISION_STRIPPED":               "XTLS Flow '%s' disabled for core '%s'",
	"HY2_AUTO_SWITCH_SINGBOX":            "Native Hysteria 2 binary does not support routing rules or TUN mode. Automatically switched to Sing-box (with Hysteria2 protocol) to apply the routing table",
	"HY2_STRICT_REJECT":                  "Native Hysteria 2 binary does not support routing rules and system TUN mode",

	// Diagnostics & Health Checks
	"HEALTH_CHECK_PASSED":                "All core subsystems are operating normally",
	"HEALTH_CHECK_FAILED":                "Issues detected in core subsystems",
	"HEALTH_PORT_OCCUPIED":               "Port %d (%s) is already occupied by another application",
	"HEALTH_PORT_OCCUPIED_SIMPLE":        "Local port %d is occupied by another process",
	"HEALTH_PORT_FREE":                   "Port %d (%s) is available for listening",
	"HEALTH_DNS_OK":                      "DNS resolver is reachable (latency: %dms)",
	"HEALTH_DNS_TIMEOUT":                 "DNS server '%s' is unreachable (timeout)",
	"HEALTH_DNS_LOOKUP_ERROR":            "DNS lookup error for host '%s'",
	"HEALTH_VAULT_OK":                    "Cryptographic database vault verified and ready",
	"HEALTH_VAULT_INIT_FAIL":             "Crypto Vault initialization failed: %v",
	"HEALTH_VAULT_ENCRYPT_FAIL":          "AEAD test encryption failed",
	"HEALTH_VAULT_DECRYPT_FAIL":          "AEAD test decryption failed",

	// Routing Actions
	"ACTION_DIRECT":                      "Direct (DIRECT)",
	"ACTION_PROXY":                       "Proxy (PROXY)",
	"ACTION_BLOCK":                       "Block (BLOCKED)",
	"ACTION_CUSTOM_OUTBOUND":             "Route to node: %s",

	// Routing Category Presets
	"CATEGORY_ADS":                       "Ads and Trackers",
	"CATEGORY_RU_SERVICES":               "Russian Services & Banks",
	"CATEGORY_AI_SERVICES":               "AI & Neural Networks (OpenAI, Claude, Gemini)",
	"CATEGORY_STREAMING":                 "Streaming & Media (YouTube, Instagram, X)",
	"CATEGORY_LAN":                       "Local Area Network (LAN)",
	"CATEGORY_BITTORRENT":                "BitTorrent / P2P Protocol",
	"CATEGORY_IP_LOOKUP":                 "IP Lookup Services",

	// Routing Modes
	"ROUTING_MODE_SMART_NAME":            "Smart Rule",
	"ROUTING_MODE_SMART_DESC":            "Route traffic according to routing rule table",
	"ROUTING_MODE_GLOBAL_NAME":           "Global Proxy",
	"ROUTING_MODE_GLOBAL_DESC":           "All device network traffic is routed through the tunnel (except LAN)",
	"ROUTING_MODE_DIRECT_NAME":           "Direct All",
	"ROUTING_MODE_DIRECT_DESC":           "All network traffic goes direct without proxying",

	// UI Headers
	"UI_ROUTING_TABLE_TITLE":             "Routing Rules",
	"UI_ROUTING_TABLE_SUBTITLE":          "Rules are evaluated from top to bottom. You can adjust priority order using arrows.",
	"UI_COL_ORDER":                       "ORDER",
	"UI_COL_DESCRIPTION":                 "DESCRIPTION",
	"UI_COL_CONDITIONS":                  "CONDITIONS",
	"UI_COL_DESTINATION":                 "DESTINATION",
	"UI_COL_STATUS":                      "STATUS",
	"UI_COL_ACTIONS":                     "ACTIONS",
}
