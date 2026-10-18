package security

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EnsureActivePcapSession starts a 5-minute forensic session if none is active, returning the active PCAP file path.
func (e *UnifiedSecurityEngine) EnsureActivePcapSession(reason string, policy SecurityPolicyConfig, now time.Time) string {
	if !policy.AutoPcapCapture {
		return ""
	}
	if now.Before(e.pcapActiveUntil) && e.pcapActiveFile != "" {
		return e.pcapActiveFile
	}

	pcapDir := policy.PcapDirectory
	if pcapDir == "" {
		pcapDir = "data/pcaps"
	}
	_ = os.MkdirAll(pcapDir, 0755)

	e.pcapActiveUntil = now.Add(5 * time.Minute)
	e.pcapActiveReason = reason
	e.pcapActiveFile = filepath.Join(pcapDir, fmt.Sprintf("threat_capture_%s.pcap", now.Format("20060102_150405")))

	f, err := os.OpenFile(e.pcapActiveFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		_ = WritePcapGlobalHeader(f, PCAPLinkTypeRawIP)
		f.Close()
	}

	return e.pcapActiveFile
}

// StartPcapSession starts an active continuous forensic capture session.
func (e *UnifiedSecurityEngine) StartPcapSession(reason string, duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	e.EnsureActivePcapSession(reason, e.policy, now)
	if duration > 0 {
		e.pcapActiveUntil = now.Add(duration)
	}
}

// StopPcapSession stops any active forensic capture session.
func (e *UnifiedSecurityEngine) StopPcapSession() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pcapActiveUntil = time.Time{}
}

// GetPcapStatus returns the live status of the PCAP capture session.
func (e *UnifiedSecurityEngine) GetPcapStatus() PcapCaptureStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := time.Now()
	active := now.Before(e.pcapActiveUntil)
	remSec := 0
	if active {
		remSec = int(e.pcapActiveUntil.Sub(now).Seconds())
	}
	return PcapCaptureStatus{
		IsActive:         active,
		Reason:           e.pcapActiveReason,
		FilePath:         e.pcapActiveFile,
		RemainingSeconds: remSec,
	}
}
