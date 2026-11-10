package xray

import (
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayHysteria2Outbound compiles an ast.ServerProfile into an Xray Hysteria 2 outbound.
func buildXrayHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
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
	}
	if len(node.ALPN) > 0 {
		tlsSettings["alpn"] = node.ALPN
	}
	fp := node.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	tlsSettings["fingerprint"] = fp

	port := node.Port
	if node.PortHopping != "" && strings.Contains(node.PortHopping, "-") {
		parts := strings.Split(node.PortHopping, "-")
		if len(parts) == 2 {
			startP, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			endP, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && startP <= endP {
				if port < startP || port > endP {
					port = startP
				}
			}
		}
	}

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

	finalmask := map[string]interface{}{}
	if node.ObfsPassword != "" {
		finalmask["salamander"] = map[string]interface{}{
			"password": node.ObfsPassword,
		}
	}
	if node.PortHopping != "" {
		finalmask["udphop"] = map[string]interface{}{
			"mode":  "intervalremote",
			"ports": node.PortHopping,
		}
	}
	if len(finalmask) > 0 {
		streamSettings["finalmask"] = finalmask
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
