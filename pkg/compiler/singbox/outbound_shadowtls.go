package singbox

import (
	"strconv"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildShadowTLSOutbound compiles an ast.ServerProfile into a Sing-box ShadowTLS outbound object.
func buildShadowTLSOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	version := 3
	if node.ShadowTLSVersion > 0 {
		version = node.ShadowTLSVersion
	}

	out := map[string]interface{}{
		"type":        "shadowtls",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"version":     version,
		"password":    node.ShadowTLSPassword,
	}

	tlsMap := map[string]interface{}{
		"enabled":     true,
		"server_name": node.ShadowTLSSNI,
	}
	if node.Fingerprint != "" {
		tlsMap["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": node.Fingerprint,
		}
	}
	out["tls"] = tlsMap

	return out, nil
}

func compileRawShadowTLSOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	node := &ast.ServerProfile{
		Protocol:         ast.ProtoShadowTLS,
		Port:             443,
		ShadowTLSVersion: 3,
	}
	if sMap != nil {
		if s, ok := sMap["host"].(string); ok && s != "" {
			node.Address = s
		} else if s, ok := sMap["address"].(string); ok && s != "" {
			node.Address = s
		} else if s, ok := sMap["server"].(string); ok && s != "" {
			node.Address = s
		}
		if p, ok := sMap["port"].(float64); ok && p > 0 {
			node.Port = int(p)
		} else if p, ok := sMap["server_port"].(float64); ok && p > 0 {
			node.Port = int(p)
		}
		if v, ok := sMap["shadowTlsVersion"].(float64); ok && v > 0 {
			node.ShadowTLSVersion = int(v)
		} else if v, ok := sMap["version"].(float64); ok && v > 0 {
			node.ShadowTLSVersion = int(v)
		} else if vs, ok := sMap["shadowTlsVersion"].(string); ok && vs != "" {
			if parsed, err := strconv.Atoi(vs); err == nil && parsed > 0 {
				node.ShadowTLSVersion = parsed
			}
		}
		if pwd, ok := sMap["shadowTlsPassword"].(string); ok && pwd != "" {
			node.ShadowTLSPassword = pwd
		} else if pwd, ok := sMap["password"].(string); ok && pwd != "" {
			node.ShadowTLSPassword = pwd
		}
		if sni, ok := sMap["shadowTlsSni"].(string); ok && sni != "" {
			node.ShadowTLSSNI = sni
		} else if sni, ok := sMap["sni"].(string); ok && sni != "" {
			node.ShadowTLSSNI = sni
		}
		if fp, ok := sMap["fingerprint"].(string); ok && fp != "" {
			node.Fingerprint = fp
		}
	}
	if tsMap != nil {
		if tlsSet, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSet["serverName"].(string); ok && sn != "" && node.ShadowTLSSNI == "" {
				node.ShadowTLSSNI = sn
			}
			if fp, ok := tlsSet["fingerprint"].(string); ok && fp != "" && node.Fingerprint == "" {
				node.Fingerprint = fp
			}
		}
	}
	out, _ := buildShadowTLSOutbound(tag, node)
	return out
}
