package security

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

// IngestCoreLog parses raw core logs, extracts endpoints/PID, audits threat, and records forensics.
func (e *UnifiedSecurityEngine) IngestCoreLog(logLine string) *SecurityAuditVerdict {
	clean := strings.TrimSpace(logLine)
	if clean == "" {
		return nil
	}

	ev, ok := e.singboxParser.ParseLogLine(clean)
	if !ok || ev == nil {
		ev, ok = detector.ParseCoreLogLine("", clean)
	}
	if !ok || ev == nil {
		return nil
	}

	lower := strings.ToLower(clean)
	isBlock := strings.Contains(lower, "outbound/block") || strings.Contains(lower, "action=block") || strings.Contains(lower, "match[block]") || strings.Contains(lower, "ssrf_probe")

	req := SecurityAuditRequest{
		CallerID:        ev.ClientRawID,
		ExecutablePath:  ev.ExecutablePath,
		DestinationIP:   ev.TargetHost,
		DestinationHost: ev.TargetHost,
		Port:            ev.TargetPort,
		Protocol:        "TCP",
		IsExplicitBlock: isBlock,
		Platform:        "windows",
	}

	v := e.AuditConnection(req)
	return &v
}
