package diagnostics

import (
	"fmt"
	"net"
	"time"
)

// PingResult represents the result of a connectivity/latency probe
type PingResult struct {
	Success   bool    `json:"success"`
	LatencyMs float64 `json:"latencyMs,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// PingHostPort measures exact TCP handshake latency to target address:port
func PingHostPort(address string, port int, timeout time.Duration) PingResult {
	if address == "" {
		return PingResult{Success: false, Error: "address cannot be empty"}
	}
	if port <= 0 {
		port = 443
	}
	target := fmt.Sprintf("%s:%d", address, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return PingResult{Success: false, Error: err.Error()}
	}
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	_ = conn.Close()
	return PingResult{
		Success:   true,
		LatencyMs: latency,
	}
}
