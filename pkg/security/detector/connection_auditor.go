package detector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/filter"
)

// ActiveConnection represents a single live socket reported by a proxy core.
type ActiveConnection struct {
	ID           string    `json:"id"`
	User         string    `json:"user"`          // Client email or ID
	SourceIP     string    `json:"source_ip"`     // Real client IP
	DestHost     string    `json:"dest_host"`     // Remote target domain or IP
	DestPort     int       `json:"dest_port"`     // Remote target port
	UploadBytes  int64     `json:"upload_bytes"`
	DownloadBytes int64    `json:"download_bytes"`
	StartTime    time.Time `json:"start_time"`
}

// ConnectionAuditReport details findings from a connection snapshot audit.
type ConnectionAuditReport struct {
	TotalConnections      int      `json:"total_connections"`
	UniqueClients         int      `json:"unique_clients"`
	CompromisedClients    []string `json:"compromised_clients"`
	ViolationsFound       int      `json:"violations_found"`
	ActionRecommended     string   `json:"action_recommended"`
}

// ConnectionAuditor analyzes batches of active proxy connections to spot port scanners and botnets.
type ConnectionAuditor struct {
	mu              sync.RWMutex
	tracker         *ClientRiskTracker
	registry        *ClientRegistry
	threatEngine    *filter.ThreatEngine
	sensitivePorts  map[int]bool
	maxConnsPerUser int
}

// NewConnectionAuditor creates a connection snapshot auditor.
func NewConnectionAuditor(
	tracker *ClientRiskTracker,
	registry *ClientRegistry,
	threatEngine *filter.ThreatEngine,
	sensitivePorts []int,
	maxConnsPerUser int,
) *ConnectionAuditor {
	if registry == nil {
		registry = NewClientRegistry()
	}
	if maxConnsPerUser <= 0 {
		maxConnsPerUser = 200
	}
	ports := make(map[int]bool)
	for _, p := range sensitivePorts {
		ports[p] = true
	}

	return &ConnectionAuditor{
		tracker:         tracker,
		registry:        registry,
		threatEngine:    threatEngine,
		sensitivePorts:  ports,
		maxConnsPerUser: maxConnsPerUser,
	}
}

// AuditConnections inspects all currently active connections across the server.
func (ca *ConnectionAuditor) AuditConnections(connections []ActiveConnection) ConnectionAuditReport {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	userConnCount := make(map[string]int)
	userPorts := make(map[string]map[int]bool)
	violations := 0

	for _, conn := range connections {
		rawID := conn.User
		if rawID == "" {
			rawID = conn.SourceIP
		}
		if rawID == "" {
			continue
		}

		clientID := ca.registry.ResolvePrimaryID(rawID)
		if conn.SourceIP != "" && conn.SourceIP != clientID {
			ca.registry.RegisterClient(clientID, "", "", conn.SourceIP)
		}

		userConnCount[clientID]++

		// 1. Check sensitive port access
		if ca.sensitivePorts[conn.DestPort] {
			if userPorts[clientID] == nil {
				userPorts[clientID] = make(map[int]bool)
			}
			userPorts[clientID][conn.DestPort] = true
			violations++

			ca.tracker.RecordIncident(
				clientID,
				"SENSITIVE_PORT_ACCESS",
				conn.DestHost+":"+strconv.Itoa(conn.DestPort),
				fmt.Sprintf("Active socket connected to sensitive port %d", conn.DestPort),
				35,
			)
		}

		// 2. Check Threat Intelligence (Malware / C2 / Phishing)
		if ca.threatEngine != nil {
			match := ca.threatEngine.CheckHost(conn.DestHost)
			if match.Blocked {
				violations++
				ca.tracker.RecordIncident(
					clientID,
					string(match.Category),
					conn.DestHost,
					match.Reason,
					50,
				)
			}
		}
	}

	// 3. Check for Port Scanning (user probed multiple unique sensitive ports)
	for clientID, portsMap := range userPorts {
		if len(portsMap) >= 3 {
			violations++
			ca.tracker.RecordIncident(
				clientID,
				"PORT_SCAN_DETECTED",
				fmt.Sprintf("%d distinct sensitive ports", len(portsMap)),
				"Client performed multi-port probing behavior",
				60,
			)
		}
	}

	// 4. Check for Connection Flooding / DDoS attempt
	for clientID, count := range userConnCount {
		if count > ca.maxConnsPerUser {
			violations++
			ca.tracker.RecordIncident(
				clientID,
				"FLOOD_SPIKE",
				fmt.Sprintf("%d active sockets", count),
				fmt.Sprintf("Client exceeded maximum simultaneous sockets (%d > %d)", count, ca.maxConnsPerUser),
				40,
			)
		}
	}

	quarantined := ca.tracker.GetQuarantinedClients()
	action := "NONE"
	if len(quarantined) > 0 {
		action = "KICK_COMPROMISED_CLIENTS"
	}

	return ConnectionAuditReport{
		TotalConnections:   len(connections),
		UniqueClients:      len(userConnCount),
		CompromisedClients: quarantined,
		ViolationsFound:    violations,
		ActionRecommended:  action,
	}
}

// ParseClashConnectionsJSON parses raw Clash API /connections JSON payload into structured ActiveConnections.
func ParseClashConnectionsJSON(rawJSON []byte) ([]ActiveConnection, error) {
	// Simple structure mapper for Clash API format
	type clashConn struct {
		ID       string `json:"id"`
		Metadata struct {
			User        string `json:"user"`
			SourceIP    string `json:"sourceIP"`
			Host        string `json:"host"`
			Destination string `json:"destinationIP"`
			DestPort    string `json:"destinationPort"`
		} `json:"metadata"`
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}

	type clashResp struct {
		Connections []clashConn `json:"connections"`
	}

	var resp clashResp
	if err := json.Unmarshal(rawJSON, &resp); err != nil {
		return nil, err
	}

	var res []ActiveConnection
	for _, c := range resp.Connections {
		p, _ := strconv.Atoi(c.Metadata.DestPort)
		host := c.Metadata.Host
		if host == "" {
			host = c.Metadata.Destination
		}
		user := c.Metadata.User
		if user == "" {
			user = c.Metadata.SourceIP
		}

		res = append(res, ActiveConnection{
			ID:            c.ID,
			User:          user,
			SourceIP:      c.Metadata.SourceIP,
			DestHost:      host,
			DestPort:      p,
			UploadBytes:   c.Upload,
			DownloadBytes: c.Download,
			StartTime:     time.Now(),
		})
	}

	return res, nil
}
