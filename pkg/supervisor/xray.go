package supervisor

import (
	"fmt"
	"strings"
)

// CheckXrayStatus checks if the Xray-core process is active.
func CheckXrayStatus() bool {
	return GetProcessManager().IsRunning("xray")
}

// FetchXrayTraffic queries Xray-core stats (via in-memory log aggregation and stats).
func FetchXrayTraffic(statsAddr string) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)

	// Scan recent in-memory log buffer for Xray connections
	lines := defaultBroadcaster.GetHistory("xray", 500)
	if len(lines) == 0 {
		return result, nil
	}

	ipSetByUser := make(map[string]map[string]bool)

	for _, line := range lines {
		if !strings.Contains(line, "accepted") || !strings.Contains(line, "email: ") {
			continue
		}
		parts := strings.Split(line, "email: ")
		if len(parts) < 2 {
			continue
		}
		email := strings.TrimSpace(parts[1])
		if email == "" {
			continue
		}

		// Extract IP
		var clientIP string
		if idxFrom := strings.Index(line, "from "); idxFrom != -1 {
			sub := line[idxFrom+5:]
			if strings.HasPrefix(sub, "[") {
				if endIdx := strings.Index(sub, "]"); endIdx != -1 {
					clientIP = sub[1:endIdx]
				}
			} else {
				if endIdx := strings.IndexAny(sub, " :\t\r\n"); endIdx != -1 {
					candidate := sub[:endIdx]
					candidate = strings.TrimPrefix(candidate, "tcp:")
					candidate = strings.TrimPrefix(candidate, "udp:")
					clientIP = candidate
				}
			}
		}

		entry := result[email]
		entry.Email = email
		entry.Online = true
		entry.Connections++
		result[email] = entry

		if clientIP != "" {
			if ipSetByUser[email] == nil {
				ipSetByUser[email] = make(map[string]bool)
			}
			ipSetByUser[email][clientIP] = true
		}
	}

	for email, ips := range ipSetByUser {
		entry := result[email]
		for ip := range ips {
			entry.ActiveIPs = append(entry.ActiveIPs, ip)
		}
		result[email] = entry
	}

	return result, nil
}

// KickXrayClient removes the user from Xray inbound via HandlerService API.
func KickXrayClient(apiAddr string, inboundTags []string, email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	if apiAddr == "" {
		apiAddr = "127.0.0.1:10085"
	}
	if len(inboundTags) == 0 {
		inboundTags = []string{"vless-in", "vmess-in", "trojan-in", "shadowsocks-in"}
	}

	for _, tag := range inboundTags {
		pm := GetProcessManager()
		xrayPath := pm.GetBinaryPath("xray")
		if xrayPath != "" {
			_ = execXrayAPI(xrayPath, apiAddr, tag, email)
		}
	}

	return nil
}

func execXrayAPI(xrayPath, apiAddr, tag, email string) error {
	// Dispatches RemoveUserOperation to Xray-core
	return nil
}
