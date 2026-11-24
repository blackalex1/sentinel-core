package xray

import (
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func isLoopbackHost(addr string) bool {
	trimmed := strings.TrimSpace(strings.Trim(addr, "[]"))
	return trimmed == "127.0.0.1" || trimmed == "::1" || strings.EqualFold(trimmed, "localhost")
}

func resolveHysteriaTargetPort(port int, portHopping string) int {
	if portHopping != "" && strings.Contains(portHopping, "-") {
		parts := strings.Split(portHopping, "-")
		if len(parts) == 2 {
			startP, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			endP, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && startP <= endP {
				if port < startP || port > endP {
					return startP
				}
			}
		}
	}
	return port
}

func supportsXrayUdpHop(coreVersion string) bool {
	v := strings.TrimSpace(strings.TrimPrefix(coreVersion, "v"))
	if v == "" {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 26 || (major == 26 && minor >= 10)
}

// buildXrayHysteria2Outbound compiles an ast.ServerProfile into an Xray Hysteria 2 outbound.
func buildXrayHysteria2Outbound(tag string, node *ast.ServerProfile, includeUdpHop bool) (map[string]interface{}, error) {
	auth := node.Password
	if auth == "" {
		auth = node.UUID
	}
	if auth == "" {
		auth = node.Username
	}
	if node.Username != "" && node.Password != "" && !strings.Contains(node.Password, ":") {
		auth = node.Username + ":" + node.Password
	}

	tlsSettings := map[string]interface{}{}
	sni := node.SNI
	if sni == "" {
		sni = node.Address
	}
	if sni != "" {
		tlsSettings["serverName"] = sni
	}
	if node.PinnedPeerCertSha256 != "" {
		tlsSettings["pinnedPeerCertSha256"] = node.PinnedPeerCertSha256
	} else if node.Insecure {
		tlsSettings["allowInsecure"] = true
	}
	if len(node.ALPN) > 0 {
		tlsSettings["alpn"] = node.ALPN
	}
	fp := node.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	tlsSettings["fingerprint"] = fp

	port := resolveHysteriaTargetPort(node.Port, node.PortHopping)

	hysteriaSettings := map[string]interface{}{
		"version": 2,
		"auth":    auth,
	}

	streamSettings := map[string]interface{}{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tlsSettings,
		"hysteriaSettings": hysteriaSettings,
	}

	var udpMasks []map[string]interface{}
	if node.ObfsPassword != "" && (node.ObfsType == "" || strings.EqualFold(node.ObfsType, "salamander")) {
		udpMasks = append(udpMasks, map[string]interface{}{
			"type": "salamander",
			"settings": map[string]interface{}{
				"password": node.ObfsPassword,
			},
		})
	}
	// Emit udphop only when the target Xray version supports it (26.10+), and never on loopback bridge sockets.
	if includeUdpHop && node.PortHopping != "" && !isLoopbackHost(node.Address) {
		udpMasks = append(udpMasks, map[string]interface{}{
			"type": "udphop",
			"settings": map[string]interface{}{
				"mode":     "intervalremote",
				"ports":    node.PortHopping,
				"interval": 30,
			},
		})
	}
	if len(udpMasks) > 0 {
		streamSettings["finalmask"] = map[string]interface{}{
			"udp": udpMasks,
		}
	}

	outbound := map[string]interface{}{
		"tag":      tag,
		"protocol": "hysteria",
		"settings": map[string]interface{}{
			"version": 2,
			"address": node.Address,
			"port":    port,
		},
		"streamSettings": streamSettings,
	}

	return outbound, nil
}
