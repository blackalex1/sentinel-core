package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/events"
)

// ClientStatus represents the assessed security posture of a connected proxy user.
type ClientStatus string

const (
	StatusClean       ClientStatus = "CLEAN"
	StatusSuspicious  ClientStatus = "SUSPICIOUS"
	StatusCompromised ClientStatus = "COMPROMISED"
	StatusQuarantined ClientStatus = "QUARANTINED"
)

// ThreatIncident records an individual suspicious behavior from a client.
type ThreatIncident struct {
	Timestamp   time.Time `json:"timestamp"`
	ThreatType  string    `json:"threat_type"` // PORT_SCAN, SENSITIVE_PORT_PROBE, MALWARE_C2, FLOOD_SPIKE, SSRF_PROBE
	Target      string    `json:"target"`
	ScoreDelta  int       `json:"score_delta"`
	Description string    `json:"description"`
}

// ClientRiskProfile tracks the security metrics and violation history of a single user/client.
type ClientRiskProfile struct {
	ClientID        string           `json:"client_id"` // User email, UUID, or source IP
	RiskScore       int              `json:"risk_score"`
	Status          ClientStatus     `json:"status"`
	ProbedPorts     map[int]time.Time `json:"probed_ports"`
	Incidents       []ThreatIncident `json:"incidents"`
	FirstSeen       time.Time        `json:"first_seen"`
	LastViolation   time.Time        `json:"last_violation"`
	QuarantinedUntil time.Time       `json:"quarantined_until"`
}

// RiskScorerConfig defines threshold values for compromised client detection.
type RiskScorerConfig struct {
	CompromiseThreshold int           `json:"compromise_threshold"` // default 100
	SuspiciousThreshold int           `json:"suspicious_threshold"` // default 40
	QuarantineDuration  time.Duration `json:"quarantine_duration"`  // default 5m
	ScoreDecayInterval  time.Duration `json:"score_decay_interval"`  // default 1m (-10 points)
	ScoreDecayAmount    int           `json:"score_decay_amount"`    // default 10
	AutoKickOnCompromise bool         `json:"auto_kick_on_compromise"`
}

// DefaultRiskScorerConfig returns production-ready risk scoring parameters.
func DefaultRiskScorerConfig() RiskScorerConfig {
	return RiskScorerConfig{
		CompromiseThreshold:  100,
		SuspiciousThreshold:  40,
		QuarantineDuration:   5 * time.Minute,
		ScoreDecayInterval:   1 * time.Minute,
		ScoreDecayAmount:     10,
		AutoKickOnCompromise: true,
	}
}

// CompromiseCallback is invoked when a client crosses into COMPROMISED status.
type CompromiseCallback func(client *ClientRiskProfile, incident ThreatIncident)

// ClientRiskTracker maintains risk scores and automatically flags compromised clients.
type ClientRiskTracker struct {
	mu            sync.RWMutex
	cfg           RiskScorerConfig
	profiles      map[string]*ClientRiskProfile
	whitelist     map[string]bool
	onCompromised []CompromiseCallback
	eventBus      *events.EventBus
	stopDecay     chan struct{}
}

// NewClientRiskTracker creates a new risk tracking engine.
func NewClientRiskTracker(cfg RiskScorerConfig, whitelistIPsOrUsers []string) *ClientRiskTracker {
	wl := make(map[string]bool)
	for _, w := range whitelistIPsOrUsers {
		wl[w] = true
	}
	wl["127.0.0.1"] = true
	wl["::1"] = true

	tracker := &ClientRiskTracker{
		cfg:           cfg,
		profiles:      make(map[string]*ClientRiskProfile),
		whitelist:     wl,
		onCompromised: make([]CompromiseCallback, 0),
		eventBus:      events.GetGlobalBus(),
		stopDecay:     make(chan struct{}),
	}

	go tracker.startDecayLoop()
	return tracker
}

// OnCompromised registers an incident response action (e.g. Kick client).
func (t *ClientRiskTracker) OnCompromised(cb CompromiseCallback) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onCompromised = append(t.onCompromised, cb)
}

// RecordIncident adds a violation and recalculates the client's risk posture.
func (t *ClientRiskTracker) RecordIncident(clientID, threatType, target, desc string, scoreDelta int) *ClientRiskProfile {
	if clientID == "" {
		return nil
	}

	t.mu.Lock()
	if t.whitelist[clientID] {
		t.mu.Unlock()
		return nil
	}

	now := time.Now()
	profile, exists := t.profiles[clientID]
	if !exists {
		profile = &ClientRiskProfile{
			ClientID:    clientID,
			RiskScore:   0,
			Status:      StatusClean,
			ProbedPorts: make(map[int]time.Time),
			Incidents:   make([]ThreatIncident, 0),
			FirstSeen:   now,
		}
		t.profiles[clientID] = profile
	}

	incident := ThreatIncident{
		Timestamp:   now,
		ThreatType:  threatType,
		Target:      target,
		ScoreDelta:  scoreDelta,
		Description: desc,
	}

	profile.RiskScore += scoreDelta
	profile.LastViolation = now
	profile.Incidents = append(profile.Incidents, incident)

	var callbacksToRun []CompromiseCallback
	shouldAlert := false
	oldStatus := profile.Status

	// Status transitions
	if profile.RiskScore >= t.cfg.CompromiseThreshold {
		profile.Status = StatusCompromised
		profile.QuarantinedUntil = now.Add(t.cfg.QuarantineDuration)
	} else if profile.RiskScore >= t.cfg.SuspiciousThreshold {
		profile.Status = StatusSuspicious
	} else {
		profile.Status = StatusClean
	}

	// Trigger alerts & actions on transition to compromised
	if oldStatus != StatusCompromised && profile.Status == StatusCompromised {
		callbacksToRun = append(callbacksToRun, t.onCompromised...)
		shouldAlert = true
	}
	t.mu.Unlock()

	for _, cb := range callbacksToRun {
		cb(profile, incident)
	}

	if shouldAlert && t.eventBus != nil {
		t.eventBus.Publish(events.SentinelEvent{
			Category:       events.CategoryThreatBlocked,
			Severity:       events.SeverityFatal,
			Code:           events.CodeThreatAppIsolated,
			Message:        fmt.Sprintf("🚨 Client '%s' FLAGGED AS COMPROMISED! (Score: %d/%d). Incident: %s (%s)", clientID, profile.RiskScore, t.cfg.CompromiseThreshold, threatType, desc),
			Timestamp:      now.Unix(),
			SuggestedAction: events.ActionNone,
		})
	}

	return profile
}

// IsCompromisedOrQuarantined returns true if the client is currently isolated.
func (t *ClientRiskTracker) IsCompromisedOrQuarantined(clientID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	p, exists := t.profiles[clientID]
	if !exists {
		return false
	}
	if p.Status == StatusCompromised {
		return true
	}
	if time.Now().Before(p.QuarantinedUntil) {
		return true
	}
	return false
}

// GetQuarantinedClients returns a list of all currently isolated user IDs.
func (t *ClientRiskTracker) GetQuarantinedClients() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var res []string
	now := time.Now()
	for id, p := range t.profiles {
		if p.Status == StatusCompromised || now.Before(p.QuarantinedUntil) {
			res = append(res, id)
		}
	}
	return res
}

// GetProfile returns the profile snapshot for a client.
func (t *ClientRiskTracker) GetProfile(clientID string) (*ClientRiskProfile, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, exists := t.profiles[clientID]
	return p, exists
}

// GetAllProfiles returns snapshots of all tracked client risk profiles.
func (t *ClientRiskTracker) GetAllProfiles() []*ClientRiskProfile {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var res []*ClientRiskProfile
	for _, p := range t.profiles {
		res = append(res, p)
	}
	return res
}

// ResetClientScore clears a client's risk score and unblocks them from quarantine.
func (t *ClientRiskTracker) ResetClientScore(clientID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if p, exists := t.profiles[clientID]; exists {
		p.RiskScore = 0
		p.Status = StatusClean
		p.QuarantinedUntil = time.Time{}
		p.ProbedPorts = make(map[int]time.Time)
	}
}

// Stop cleanly terminates the background decay routine.
func (t *ClientRiskTracker) Stop() {
	select {
	case <-t.stopDecay:
	default:
		close(t.stopDecay)
	}
}

func (t *ClientRiskTracker) startDecayLoop() {
	ticker := time.NewTicker(t.cfg.ScoreDecayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopDecay:
			return
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for _, p := range t.profiles {
				// Only decay score if client has stopped violating for at least decay interval
				if now.Sub(p.LastViolation) >= t.cfg.ScoreDecayInterval {
					p.RiskScore -= t.cfg.ScoreDecayAmount
					if p.RiskScore < 0 {
						p.RiskScore = 0
					}
					// Update status after decay if quarantine expired
					if now.After(p.QuarantinedUntil) {
						if p.RiskScore >= t.cfg.CompromiseThreshold {
							p.Status = StatusCompromised
						} else if p.RiskScore >= t.cfg.SuspiciousThreshold {
							p.Status = StatusSuspicious
						} else {
							p.Status = StatusClean
						}
					}
				}
			}
			t.mu.Unlock()
		}
	}
}
