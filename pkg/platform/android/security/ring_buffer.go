package security

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// AndroidLogEntry represents an enriched socket connection record for Android audit
type AndroidLogEntry struct {
	ID              string `json:"id"`
	Timestamp       int64  `json:"timestamp"`
	PackageName     string `json:"packageName"`
	AppName         string `json:"appName"`
	SourceIP        string `json:"sourceIp,omitempty"`
	SourcePort      int    `json:"sourcePort,omitempty"`
	DestinationIP   string `json:"destinationIp"`
	DestinationPort int    `json:"destinationPort"`
	Protocol        string `json:"protocol"`
	ServiceName     string `json:"serviceName,omitempty"`
	Action          string `json:"action,omitempty"` // "direct", "proxy", "block"
	ThreatType      string `json:"threatType,omitempty"`
	RiskScore       int    `json:"riskScore,omitempty"`
}

// AppStat represents aggregated metrics for an application
type AppStat struct {
	PackageName string `json:"packageName"`
	AppName     string `json:"appName"`
	Count       int64  `json:"count"`
}

// PortStat represents connection count for a specific port
type PortStat struct {
	Port        int    `json:"port"`
	ServiceName string `json:"serviceName"`
	Count       int64  `json:"count"`
}

// AndroidLogStats contains aggregated analytics of the in-memory log buffer
type AndroidLogStats struct {
	TotalConnections  int64            `json:"totalConnections"`
	ActiveAppsCount   int              `json:"activeAppsCount"`
	ThreatCount       int64            `json:"threatCount"`
	ProtocolBreakdown map[string]int64 `json:"protocolBreakdown"`
	TopApps           []AppStat        `json:"topApps"`
	TopPorts          []PortStat       `json:"topPorts"`
}

// AndroidLogRingBuffer is a high-performance in-memory ring buffer for connection audit logs
type AndroidLogRingBuffer struct {
	mu          sync.RWMutex
	capacity    int
	entries     []AndroidLogEntry
	head        int
	count       int
	totalLogged int64
	serviceMap  map[int]string
}

var (
	globalLogBuffer     *AndroidLogRingBuffer
	globalLogBufferOnce sync.Once
)

// GetGlobalLogBuffer returns the global ring buffer instance for Android
func GetGlobalLogBuffer() *AndroidLogRingBuffer {
	globalLogBufferOnce.Do(func() {
		globalLogBuffer = NewAndroidLogRingBuffer(5000)
	})
	return globalLogBuffer
}

// NewAndroidLogRingBuffer creates a ring buffer with specified maximum capacity
func NewAndroidLogRingBuffer(capacity int) *AndroidLogRingBuffer {
	if capacity <= 0 {
		capacity = 5000
	}

	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		853: "DoT", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
		1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
		6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
	}

	return &AndroidLogRingBuffer{
		capacity:   capacity,
		entries:    make([]AndroidLogEntry, capacity),
		head:       0,
		count:      0,
		serviceMap: services,
	}
}

// Push appends a new log entry to the ring buffer in O(1) time
func (b *AndroidLogRingBuffer) Push(entry AndroidLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if entry.Timestamp <= 0 {
		entry.Timestamp = time.Now().UnixMilli()
	}
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("%d-%s-%d", entry.Timestamp, entry.PackageName, entry.DestinationPort)
	}
	if entry.ServiceName == "" && entry.DestinationPort > 0 {
		if s, ok := b.serviceMap[entry.DestinationPort]; ok {
			entry.ServiceName = s
		}
	}

	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.capacity
	if b.count < b.capacity {
		b.count++
	}
	b.totalLogged++
}

// GetLogs returns a filtered, paginated slice of logs sorted newest first
func (b *AndroidLogRingBuffer) GetLogs(limit, offset, portFilter int, query string) []AndroidLogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.count == 0 {
		return []AndroidLogEntry{}
	}

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	qLower := strings.ToLower(strings.TrimSpace(query))
	matched := make([]AndroidLogEntry, 0, b.count)

	// Iterate newest to oldest
	for i := 0; i < b.count; i++ {
		idx := (b.head - 1 - i + b.capacity) % b.capacity
		e := b.entries[idx]

		// Port filter
		if portFilter > 0 && e.DestinationPort != portFilter {
			continue
		}

		// Text search filter
		if qLower != "" {
			match := strings.Contains(strings.ToLower(e.AppName), qLower) ||
				strings.Contains(strings.ToLower(e.PackageName), qLower) ||
				strings.Contains(strings.ToLower(e.DestinationIP), qLower) ||
				strings.Contains(strings.ToLower(e.ServiceName), qLower) ||
				strings.Contains(strings.ToLower(e.Protocol), qLower)
			if !match {
				continue
			}
		}

		matched = append(matched, e)
	}

	if offset >= len(matched) {
		return []AndroidLogEntry{}
	}

	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}

	return matched[offset:end]
}

// GetStats computes aggregated traffic analytics across all stored entries
func (b *AndroidLogRingBuffer) GetStats() AndroidLogStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	appCounts := make(map[string]*AppStat)
	portCounts := make(map[int]int64)
	protoBreakdown := make(map[string]int64)
	var threatCount int64

	for i := 0; i < b.count; i++ {
		idx := (b.head - 1 - i + b.capacity) % b.capacity
		e := b.entries[idx]

		// App stats
		pkg := e.PackageName
		if pkg == "" {
			pkg = "unknown"
		}
		if _, ok := appCounts[pkg]; !ok {
			appCounts[pkg] = &AppStat{
				PackageName: pkg,
				AppName:     e.AppName,
				Count:       0,
			}
		}
		appCounts[pkg].Count++

		// Port stats
		if e.DestinationPort > 0 {
			portCounts[e.DestinationPort]++
		}

		// Protocol stats
		proto := strings.ToUpper(e.Protocol)
		if proto == "" {
			proto = "TCP"
		}
		protoBreakdown[proto]++

		// Threat stats
		if e.ThreatType != "" && e.ThreatType != "NONE" {
			threatCount++
		}
	}

	// Sort top apps
	topApps := make([]AppStat, 0, len(appCounts))
	for _, a := range appCounts {
		topApps = append(topApps, *a)
	}
	sort.Slice(topApps, func(i, j int) bool {
		return topApps[i].Count > topApps[j].Count
	})
	if len(topApps) > 10 {
		topApps = topApps[:10]
	}

	// Sort top ports
	topPorts := make([]PortStat, 0, len(portCounts))
	for p, c := range portCounts {
		sName := b.serviceMap[p]
		if sName == "" {
			sName = fmt.Sprintf("Port %d", p)
		}
		topPorts = append(topPorts, PortStat{
			Port:        p,
			ServiceName: sName,
			Count:       c,
		})
	}
	sort.Slice(topPorts, func(i, j int) bool {
		return topPorts[i].Count > topPorts[j].Count
	})
	if len(topPorts) > 10 {
		topPorts = topPorts[:10]
	}

	return AndroidLogStats{
		TotalConnections:  b.totalLogged,
		ActiveAppsCount:   len(appCounts),
		ThreatCount:       threatCount,
		ProtocolBreakdown: protoBreakdown,
		TopApps:           topApps,
		TopPorts:          topPorts,
	}
}

// Clear resets the buffer
func (b *AndroidLogRingBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.head = 0
	b.count = 0
	b.totalLogged = 0
}
