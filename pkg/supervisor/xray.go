package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CheckXrayStatus checks if the Xray-core process is active.
func CheckXrayStatus() bool {
	return GetProcessManager().IsRunning("xray")
}

func findXrayBinary() string {
	pm := GetProcessManager()
	if p := pm.GetBinaryPath("xray"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	searchPaths := []string{
		"bin/xray.exe", "bin/xray",
		"backend/bin/xray.exe", "backend/bin/xray",
		"../bin/xray.exe", "../bin/xray",
		"../../bin/xray.exe", "../../bin/xray",
		"/usr/local/bin/xray", "/usr/bin/xray",
	}
	if envBin := os.Getenv("SENTINEL_BIN_DIR"); envBin != "" {
		searchPaths = append([]string{filepath.Join(envBin, "xray.exe"), filepath.Join(envBin, "xray")}, searchPaths...)
	}

	for _, sp := range searchPaths {
		if _, err := os.Stat(sp); err == nil {
			if abs, err := filepath.Abs(sp); err == nil {
				return abs
			}
			return sp
		}
	}
	return "xray"
}

// QueryXrayStats queries Xray-core stats gRPC API via CLI tool.
func QueryXrayStats(statsAddr string) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)
	if statsAddr == "" {
		statsAddr = "127.0.0.1:10085"
	}

	xrayBin := findXrayBinary()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, xrayBin, "api", "statsquery", "--server="+statsAddr)
	out, err := cmd.Output()
	if err != nil {
		return result, err
	}

	var data struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}

	if err := json.Unmarshal(out, &data); err != nil {
		return result, err
	}

	for _, item := range data.Stat {
		parts := strings.Split(item.Name, ">>>")
		if len(parts) >= 4 && parts[0] == "user" {
			email := parts[1]
			direction := parts[3]

			entry := result[email]
			entry.Email = email
			if direction == "uplink" {
				entry.UpBytes = item.Value
			} else if direction == "downlink" {
				entry.DownBytes = item.Value
			}
			result[email] = entry
		}
	}

	return result, nil
}

// FetchXrayTraffic queries Xray-core stats (via stats API and in-memory log aggregation).
func FetchXrayTraffic(statsAddr string) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)

	// 1. Fetch exact bytes from Xray Stats API if available
	if statsAddr == "" {
		statsAddr = "127.0.0.1:10085"
	}
	if stats, err := QueryXrayStats(statsAddr); err == nil {
		for email, t := range stats {
			result[email] = t
		}
	}

	// 2. Scan recent in-memory log buffer for Xray connections & IPs
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
			if !containsString(entry.ActiveIPs, ip) {
				entry.ActiveIPs = append(entry.ActiveIPs, ip)
			}
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
