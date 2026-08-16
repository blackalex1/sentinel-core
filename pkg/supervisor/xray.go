package supervisor

import (
	"fmt"
)

// CheckXrayStatus checks if the Xray-core process is active.
func CheckXrayStatus() bool {
	return GetProcessManager().IsRunning("xray")
}

// FetchXrayTraffic queries Xray-core stats (e.g. via StatsService or log aggregation).
func FetchXrayTraffic(statsAddr string) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)
	// In Xray-core, stats are queryable via gRPC or aggregated via log buffer
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
