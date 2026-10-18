package security

import (
	"net"
	"strings"
)

// IsSafeSystemTraffic checks if a destination is standard web/DNS/LAN infrastructure.
func IsSafeSystemTraffic(destIP, destHost string, port int) bool {
	if port == 53 || port == 80 || port == 443 || port == 853 {
		return true
	}
	if destIP == "127.0.0.1" || destIP == "::1" || destIP == "localhost" || destHost == "localhost" {
		return true
	}
	ip := net.ParseIP(destIP)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return true
	}
	return false
}

// IsCloudMetadataEndpoint checks for SSRF targets.
func IsCloudMetadataEndpoint(destIP, destHost string) bool {
	destIP = strings.TrimSpace(destIP)
	destHost = strings.ToLower(strings.TrimSpace(destHost))
	if destIP == "169.254.169.254" || destIP == "100.100.100.200" || destIP == "169.254.170.2" {
		return true
	}
	if strings.Contains(destHost, "metadata.google.internal") || strings.Contains(destHost, "metadata.goog") || strings.Contains(destHost, "instance-data") || strings.Contains(destHost, "169.254.169.254") || strings.Contains(destHost, "169.254.170.2") || strings.Contains(destHost, "100.100.100.200") {
		return true
	}
	return false
}
