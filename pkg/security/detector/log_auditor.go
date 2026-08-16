package detector

import (
	"fmt"
	"sync"
)

// LogAuditor inspects real-time proxy core logs (Sing-box, Xray, Hysteria 2) to detect attack signatures.
type LogAuditor struct {
	mu             sync.RWMutex
	tracker        *ClientRiskTracker
	registry       *ClientRegistry
	sensitivePorts map[int]bool
}

// NewLogAuditor creates a new real-time log auditor.
func NewLogAuditor(tracker *ClientRiskTracker, registry *ClientRegistry, sensitivePorts []int) *LogAuditor {
	if registry == nil {
		registry = NewClientRegistry()
	}
	ports := make(map[int]bool)
	for _, p := range sensitivePorts {
		ports[p] = true
	}
	return &LogAuditor{
		tracker:        tracker,
		registry:       registry,
		sensitivePorts: ports,
	}
}

// AuditLogLine processes a single log line from Sing-box, Xray, or Hysteria 2 and updates risk metrics.
func (a *LogAuditor) AuditLogLine(coreName, line string) {
	if line == "" || a.tracker == nil {
		return
	}

	event, ok := ParseCoreLogLine(coreName, line)
	if !ok || event == nil {
		return
	}

	rawID := event.ClientRawID
	if rawID == "" {
		rawID = event.ClientIP
	}
	if rawID == "" {
		return
	}

	// Resolve alias to unified primary client ID
	primaryID := a.registry.ResolvePrimaryID(rawID)

	// If client IP is present, associate it with this primary identity
	if event.ClientIP != "" && event.ClientIP != primaryID {
		a.registry.RegisterClient(primaryID, "", "", event.ClientIP)
	}

	switch event.EventType {
	case "SSRF_PROBE":
		a.tracker.RecordIncident(
			primaryID,
			"SSRF_PROBE",
			event.TargetHost,
			fmt.Sprintf("[%s] Attempted connection to Cloud Metadata endpoint", event.CoreName),
			60,
		)

	case "AUTH_FAIL":
		a.tracker.RecordIncident(
			primaryID,
			"AUTH_FAIL",
			event.CoreName,
			fmt.Sprintf("[%s] Authentication failure on proxy server", event.CoreName),
			30,
		)

	case "SENSITIVE_PORT_PROBE":
		if a.sensitivePorts[event.TargetPort] {
			a.tracker.RecordIncident(
				primaryID,
				"SENSITIVE_PORT_PROBE",
				fmt.Sprintf("%s:%d", event.TargetHost, event.TargetPort),
				fmt.Sprintf("[%s] Client opened connection to sensitive system port %d", event.CoreName, event.TargetPort),
				35,
			)
		}

	case "ROUTING_REJECT":
		if a.sensitivePorts[event.TargetPort] {
			a.tracker.RecordIncident(
				primaryID,
				"SENSITIVE_PORT_PROBE",
				fmt.Sprintf("%s:%d", event.TargetHost, event.TargetPort),
				fmt.Sprintf("[%s] Core blocked unauthorized request to port %d", event.CoreName, event.TargetPort),
				35,
			)
		}
	}
}

// Registry returns the client alias registry.
func (a *LogAuditor) Registry() *ClientRegistry {
	return a.registry
}
