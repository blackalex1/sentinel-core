package security

import (
	"time"
)

// Stop halts background tasks.
func (e *UnifiedSecurityEngine) Stop() {
	if e.decayTicker != nil {
		e.decayTicker.Stop()
	}
	close(e.stopChan)
}

func (e *UnifiedSecurityEngine) decayWorker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.runDecayStep(time.Now())
		case <-e.stopChan:
			return
		}
	}
}

func (e *UnifiedSecurityEngine) runDecayStep(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Auto-unblock TTL check for quarantined entities
	if e.policy.AutoUnblockMinutes > 0 {
		ttl := time.Duration(e.policy.AutoUnblockMinutes) * time.Minute
		for id, b := range e.bannedEntities {
			if now.Sub(b.BlockedAt) > ttl {
				delete(e.bannedEntities, id)
			}
		}
	}

	// 2. Risk profile decay
	for id, p := range e.profiles {
		if now.Sub(p.LastSeen) > 10*time.Minute {
			delete(e.profiles, id)
			continue
		}
		if p.RiskScore > 0 {
			p.RiskScore -= 20
			if p.RiskScore < 0 {
				p.RiskScore = 0
			}
		}
		if p.ThreatCount > 0 {
			p.ThreatCount--
		}
	}
}
