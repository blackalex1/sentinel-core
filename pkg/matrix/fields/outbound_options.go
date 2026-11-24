package fields

import (
	"sort"

	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// OutboundVLESSFlowOptions returns selectable VLESS XTLS flow options.
func OutboundVLESSFlowOptions(lang string) []types.SelectOption {
	loc := i18n.Locale(lang)
	return []types.SelectOption{
		{Value: "", Label: i18n.T(loc, "UI_OPT_NO_FLOW")},
		{Value: "xtls-rprx-vision", Label: "xtls-rprx-vision", SupportedEngines: []string{"xray-core", "sing-box"}},
		{Value: "xtls-rprx-vision-udp443", Label: "xtls-rprx-vision-udp443", SupportedEngines: []string{"xray-core"}},
	}
}

// OutboundVLESSEncryptionOptions returns preset VLESS encryption options.
func OutboundVLESSEncryptionOptions(lang string) []types.SelectOption {
	loc := i18n.Locale(lang)
	return []types.SelectOption{
		{Value: "none", Label: "none (" + i18n.T(loc, "UI_OPT_NO_ENCRYPTION") + ")"},
	}
}

// OutboundFingerprintValues returns the canonical uTLS fingerprint list (no bogus browsers like opera).
func OutboundFingerprintValues() []string {
	return []string{
		"chrome",
		"firefox",
		"safari",
		"ios",
		"android",
		"edge",
		"360",
		"qq",
		"random",
		"randomized",
	}
}

// OutboundFingerprintOptions returns supported uTLS client fingerprint presets.
func OutboundFingerprintOptions() []types.SelectOption {
	labels := map[string]string{
		"chrome":     "Chrome",
		"firefox":    "Firefox",
		"safari":     "Safari",
		"ios":        "iOS",
		"android":    "Android",
		"edge":       "Edge",
		"360":        "360",
		"qq":         "QQ",
		"random":     "Random",
		"randomized": "Randomized",
	}
	vals := OutboundFingerprintValues()
	opts := make([]types.SelectOption, 0, len(vals))
	for _, v := range vals {
		opts = append(opts, types.SelectOption{
			Value:            v,
			Label:            labels[v],
			SupportedEngines: []string{"xray-core", "sing-box"},
		})
	}
	return opts
}

// OutboundALPNOptions returns standard ALPN protocol preset combinations.
func OutboundALPNOptions(lang string) []types.SelectOption {
	loc := i18n.Locale(lang)
	return []types.SelectOption{
		{Value: "", Label: i18n.T(loc, "UI_OPT_AUTO_DEFAULT")},
		{Value: "h2,http/1.1", Label: "h2, http/1.1"},
		{Value: "h2", Label: "h2 (HTTP/2)"},
		{Value: "http/1.1", Label: "http/1.1"},
		{Value: "h3", Label: "h3 (HTTP/3)"},
		{Value: "h3,h2,http/1.1", Label: "h3, h2, http/1.1"},
	}
}

// OutboundHysteriaALPNOptions returns ALPN presets tailored for QUIC / Hysteria 2.
func OutboundHysteriaALPNOptions(lang string) []types.SelectOption {
	loc := i18n.Locale(lang)
	return []types.SelectOption{
		{Value: "", Label: i18n.T(loc, "UI_OPT_AUTO_DEFAULT")},
		{Value: "h3", Label: "h3 (HTTP/3)"},
		{Value: "h3,h2", Label: "h3, h2"},
	}
}

// OutboundTCPHeaderTypeOptions returns TCP header obfuscation presets (Xray-core).
func OutboundTCPHeaderTypeOptions(lang string) []types.SelectOption {
	loc := i18n.Locale(lang)
	return []types.SelectOption{
		{Value: "", Label: i18n.T(loc, "UI_OPT_HEADER_NONE")},
		{Value: "http", Label: i18n.T(loc, "UI_OPT_HEADER_HTTP"), SupportedEngines: []string{"xray-core"}},
	}
}

// OutboundXHTTPModeOptions returns xHTTP/SplitHTTP stream modes supported by Xray-core.
func OutboundXHTTPModeOptions() []types.SelectOption {
	return []types.SelectOption{
		{Value: "auto", Label: "auto", SupportedEngines: []string{"xray-core"}},
		{Value: "packet-up", Label: "packet-up", SupportedEngines: []string{"xray-core"}},
		{Value: "stream-up", Label: "stream-up", SupportedEngines: []string{"xray-core"}},
		{Value: "stream-one", Label: "stream-one", SupportedEngines: []string{"xray-core"}},
	}
}

// OutboundTUICCongestionOptions returns congestion control algorithms for TUIC (sing-box).
func OutboundTUICCongestionOptions() []types.SelectOption {
	return []types.SelectOption{
		{Value: "bbr", Label: "BBR", SupportedEngines: []string{"sing-box"}},
		{Value: "cubic", Label: "CUBIC", SupportedEngines: []string{"sing-box"}},
		{Value: "new_reno", Label: "New Reno", SupportedEngines: []string{"sing-box"}},
	}
}

// OutboundTUICUDPRelayOptions returns UDP relay modes for TUIC (sing-box).
func OutboundTUICUDPRelayOptions() []types.SelectOption {
	return []types.SelectOption{
		{Value: "native", Label: "Native", SupportedEngines: []string{"sing-box"}},
		{Value: "quic", Label: "QUIC", SupportedEngines: []string{"sing-box"}},
	}
}

// OutboundShadowTLSVersionOptions returns supported ShadowTLS handshake versions (sing-box).
func OutboundShadowTLSVersionOptions() []types.SelectOption {
	return []types.SelectOption{
		{Value: "3", Label: "v3", SupportedEngines: []string{"sing-box"}},
		{Value: "2", Label: "v2", SupportedEngines: []string{"sing-box"}},
		{Value: "1", Label: "v1", SupportedEngines: []string{"sing-box"}},
	}
}

// OutboundNetworkOptions maps supported transport identifiers to display SelectOptions.
func OutboundNetworkOptions(transports []string) []types.SelectOption {
	return OutboundNetworkOptionsFor(transports, nil)
}

// OutboundNetworkOptionsFor maps supported transport identifiers with optional per-engine tags.
func OutboundNetworkOptionsFor(transports []string, engineTransports map[string][]string) []types.SelectOption {
	labels := map[string]string{
		"tcp":         "TCP",
		"ws":          "WebSocket (WS)",
		"grpc":        "gRPC",
		"httpupgrade": "HTTPUpgrade",
		"xhttp":       "XHTTP / Split-HTTP",
		"splithttp":   "SplitHTTP",
		"h2":          "HTTP/2 (H2)",
		"http":        "HTTP/2 (HTTP)",
		"quic":        "QUIC",
		"kcp":         "mKCP",
		"mkcp":        "mKCP",
	}
	opts := make([]types.SelectOption, 0, len(transports))
	for _, t := range transports {
		label, ok := labels[t]
		if !ok {
			label = t
		}
		var engines []string
		if len(engineTransports) > 0 {
			for eng, list := range engineTransports {
				for _, item := range list {
					if item == t {
						engines = append(engines, eng)
						break
					}
				}
			}
			sort.Strings(engines)
		}
		opts = append(opts, types.SelectOption{
			Value:            t,
			Label:            label,
			SupportedEngines: engines,
		})
	}
	return opts
}

// OutboundSecurityOptions builds security select options tagged with SupportedEngines.
func OutboundSecurityOptions(securities []string, engineSecurity map[string][]string, lang string) []types.SelectOption {
	loc := i18n.Locale(lang)
	labels := map[string]string{
		"reality":   "REALITY",
		"tls":       "TLS",
		"shadowtls": "ShadowTLS",
		"none":      "None (" + i18n.T(loc, "UI_OPT_NO_ENCRYPTION") + ")",
	}
	opts := make([]types.SelectOption, 0, len(securities))
	for _, s := range securities {
		label, ok := labels[s]
		if !ok {
			label = s
		}
		var engines []string
		if len(engineSecurity) > 0 {
			for eng, list := range engineSecurity {
				for _, item := range list {
					if item == s {
						engines = append(engines, eng)
						break
					}
				}
			}
			sort.Strings(engines)
		}
		opts = append(opts, types.SelectOption{
			Value:            s,
			Label:            label,
			SupportedEngines: engines,
		})
	}
	return opts
}
