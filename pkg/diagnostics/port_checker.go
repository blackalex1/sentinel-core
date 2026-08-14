package diagnostics

import (
	"fmt"
	"net"
	"time"
)

// PortCheckResult represents the status of a checked local port
type PortCheckResult struct {
	Port      int    `json:"port"`
	IsFree    bool   `json:"isFree"`
	Error     string `json:"error,omitempty"`
}

// IsPortAvailable checks if a TCP port can be bound locally on 127.0.0.1
func IsPortAvailable(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// CheckPorts checks an array of ports and returns detailed diagnostics
func CheckPorts(ports []int) []PortCheckResult {
	results := make([]PortCheckResult, 0, len(ports))
	for _, p := range ports {
		free := IsPortAvailable(p)
		res := PortCheckResult{
			Port:   p,
			IsFree: free,
		}
		if !free {
			res.Error = fmt.Sprintf("Port %d is currently in use by another process", p)
		}
		results = append(results, res)
	}
	return results
}

// CheckRemoteReachable tests if a remote host:port can establish a TCP handshake
func CheckRemoteReachable(host string, port int, timeout time.Duration) (bool, time.Duration, error) {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, 0, err
	}
	latency := time.Since(start)
	_ = conn.Close()
	return true, latency, nil
}
