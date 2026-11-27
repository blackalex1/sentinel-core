package adapter

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

// RawDBNode represents a generic database record for a proxy node.
type RawDBNode struct {
	ID         string                 `json:"id,omitempty"`
	Name       string                 `json:"name,omitempty"`
	Protocol   string                 `json:"protocol"`
	Address    string                 `json:"address"`
	Port       interface{}            `json:"port"` // Can be int or string in some DBs
	Transport  string                 `json:"transport,omitempty"`
	Security   string                 `json:"security,omitempty"`
	Parameters interface{}            `json:"parameters,omitempty"` // Can be map[string]interface{} OR encrypted string
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// IngestDBNode parses and converts a raw database record into a normalized ast.ServerProfile.
// If the parameters payload is encrypted with AEAD (enc:v1:aes-gcm:), it is automatically decrypted using vault.
func IngestDBNode(raw *RawDBNode, vault *crypto.Vault) (*ast.ServerProfile, error) {
	if raw == nil {
		return nil, fmt.Errorf("raw DB node cannot be nil")
	}

	profile := &ast.ServerProfile{
		ID:        raw.ID,
		Name:      raw.Name,
		Protocol:  strings.ToLower(strings.TrimSpace(raw.Protocol)),
		Address:   strings.TrimSpace(raw.Address),
		Transport: strings.ToLower(strings.TrimSpace(raw.Transport)),
		Security:  strings.ToLower(strings.TrimSpace(raw.Security)),
		Extra:     make(map[string]interface{}),
	}

	// 1. Parse Port
	switch p := raw.Port.(type) {
	case int:
		profile.Port = p
	case float64:
		profile.Port = int(p)
	case string:
		parsedPort, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid port string '%s': %w", p, err)
		}
		profile.Port = parsedPort
	default:
		return nil, fmt.Errorf("missing or invalid port format")
	}

	// 2. Resolve Parameters (Decryption if encrypted)
	var paramsMap map[string]interface{}

	if raw.Parameters != nil {
		switch paramVal := raw.Parameters.(type) {
		case string:
			paramStr := strings.TrimSpace(paramVal)
			if crypto.IsEncrypted(paramStr) {
				if vault == nil {
					return nil, fmt.Errorf("node '%s' has encrypted parameters, but no crypto vault / master secret was provided", profile.Name)
				}
				decrypted, err := vault.DecryptMap(paramStr)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt parameters for node '%s': %w", profile.Name, err)
				}
				paramsMap = decrypted
			} else if strings.HasPrefix(paramStr, "{") {
				// Raw JSON string in DB
				if err := json.Unmarshal([]byte(paramStr), &paramsMap); err != nil {
					return nil, fmt.Errorf("failed to parse JSON parameters for node '%s': %w", profile.Name, err)
				}
			}
		case map[string]interface{}:
			paramsMap = paramVal
		}
	}

	// 3. Map parameters to ServerProfile fields
	if paramsMap != nil {
		mapParametersToProfile(profile, paramsMap)
	}

	profile.Normalize()

	if err := profile.Validate(); err != nil {
		return nil, err
	}

	return profile, nil
}

// IngestFromJSON parses a JSON string containing a RawDBNode.
func IngestFromJSON(jsonStr string, vault *crypto.Vault) (*ast.ServerProfile, error) {
	var raw RawDBNode
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse RawDBNode JSON: %w", err)
	}
	return IngestDBNode(&raw, vault)
}

func paramString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func paramBool(m map[string]interface{}, keys ...string) bool {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		if b, ok := v.(bool); ok {
			return b
		}
		if s, ok := v.(string); ok {
			return s == "true" || s == "1"
		}
	}
	return false
}

func paramInt(m map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch val := v.(type) {
		case int:
			return val
		case float64:
			return int(val)
		case string:
			if parsed, err := strconv.Atoi(val); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func paramStringSlice(m map[string]interface{}, keys ...string) []string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch val := v.(type) {
		case []string:
			return val
		case []interface{}:
			var res []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					res = append(res, s)
				}
			}
			return res
		case string:
			if val != "" {
				return strings.Split(val, ",")
			}
		}
	}
	return nil
}

func mapParametersToProfile(p *ast.ServerProfile, m map[string]interface{}) {
	// Credentials
	if v := paramString(m, "uuid", "UUID"); v != "" {
		p.UUID = v
	}
	if v := paramString(m, "password", "pass", "pwd", "auth"); v != "" {
		p.Password = v
	}
	if v := paramString(m, "username", "user"); v != "" {
		p.Username = v
	}

	// TLS & Reality
	if v := paramString(m, "sni", "server_name", "serverName", "host"); v != "" {
		p.SNI = v
	}
	if v := paramString(m, "fingerprint", "fp"); v != "" {
		p.Fingerprint = v
	}
	if v := paramString(m, "public_key", "publicKey", "pbk"); v != "" {
		p.PublicKey = v
	}
	if v := paramString(m, "short_id", "shortId", "sid"); v != "" {
		p.ShortID = v
	}
	if v := paramString(m, "spider_x", "spiderX", "spx"); v != "" {
		p.SpiderX = v
	}
	if alpn := paramStringSlice(m, "alpn", "ALPN"); len(alpn) > 0 {
		p.ALPN = alpn
	}
	p.Insecure = paramBool(m, "insecure", "allowInsecure", "allow_insecure")
	p.PostQuantum = paramBool(m, "post_quantum", "postQuantum", "pq", "kyber")

	// Flow & Mux
	if v := paramString(m, "flow", "Flow"); v != "" {
		p.Flow = v
	}
	p.Mux = paramBool(m, "mux", "multiplex")

	// Transport
	if v := paramString(m, "path", "Path"); v != "" {
		p.Path = v
	}
	if v := paramString(m, "service_name", "serviceName", "grpc_service"); v != "" {
		p.ServiceName = v
	}

	// Shadowsocks / ShadowTLS
	if v := paramString(m, "cipher", "method"); v != "" {
		p.Cipher = v
	}
	p.ShadowTLSVersion = paramInt(m, "shadow_tls_version", "shadowTlsVersion")
	if v := paramString(m, "shadow_tls_password", "shadowTlsPassword"); v != "" {
		p.ShadowTLSPassword = v
	}
	if v := paramString(m, "shadow_tls_sni", "shadowTlsSni"); v != "" {
		p.ShadowTLSSNI = v
	}

	// Hysteria 2
	if v := paramString(m, "bandwidth_up", "bandwidthUp", "up_mbps"); v != "" {
		p.BandwidthUp = v
	}
	if v := paramString(m, "bandwidth_down", "bandwidthDown", "down_mbps"); v != "" {
		p.BandwidthDown = v
	}
	if v := paramString(m, "obfs_type", "obfsType"); v != "" {
		p.ObfsType = v
	}
	if v := paramString(m, "obfs_password", "obfsPassword", "obfs"); v != "" {
		p.ObfsPassword = v
	}
	if v := paramString(m, "port_hopping", "portHopping", "mport", "ports"); v != "" {
		p.PortHopping = v
	}

	// TUIC
	if v := paramString(m, "congestion_control", "congestionControl"); v != "" {
		p.CongestionControl = v
	}
	if v := paramString(m, "udp_relay_mode", "udpRelayMode"); v != "" {
		p.UDPRelayMode = v
	}
	p.ZeroRTTHandshake = paramBool(m, "zero_rtt_handshake", "zeroRttHandshake")

	// WireGuard
	if v := paramString(m, "private_key", "privateKey"); v != "" {
		p.PrivateKey = v
	}
	if v := paramString(m, "peer_public_key", "peerPublicKey"); v != "" {
		p.PeerPublicKey = v
	}
	if v := paramString(m, "preshared_key", "preSharedKey"); v != "" {
		p.PreSharedKey = v
	}
	p.MTU = paramInt(m, "mtu", "MTU")
	if localAddr := paramStringSlice(m, "local_address", "localAddress", "ip"); len(localAddr) > 0 {
		p.LocalAddress = localAddr
	}
}
