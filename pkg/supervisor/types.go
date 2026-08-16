package supervisor

import "time"

// CoreType defines supported proxy core engines
type CoreType string

const (
	CoreXray      CoreType = "xray"
	CoreSingBox   CoreType = "sing-box"
	CoreHysteria2 CoreType = "hysteria2"
)

// CoreStatus represents the current runtime state of a core engine
type CoreStatus struct {
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	Running       bool   `json:"running"`
	PID           int    `json:"pid"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	MemoryBytes   uint64 `json:"memoryBytes"`
	Error         string `json:"error,omitempty"`
}

// ClientTraffic represents accumulated/delta traffic and active IPs for a client
type ClientTraffic struct {
	Email       string   `json:"email"`
	UpBytes     int64    `json:"upBytes"`
	DownBytes   int64    `json:"downBytes"`
	Online      bool     `json:"online"`
	ActiveIPs   []string `json:"activeIps,omitempty"`
	Connections int      `json:"connections,omitempty"`
}

// SupervisorReport contains status of all cores and aggregated traffic
type SupervisorReport struct {
	Timestamp int64                    `json:"timestamp"`
	Cores     map[string]CoreStatus    `json:"cores"`
	Traffic   map[string]ClientTraffic `json:"traffic"`
}

// LogEntry represents a single log line or block
type LogEntry struct {
	Core      string    `json:"core"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}
