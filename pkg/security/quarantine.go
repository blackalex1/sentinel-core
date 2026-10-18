package security

import (
	"time"
)

// GetBlockedEntities returns all currently quarantined processes/packages.
func (e *UnifiedSecurityEngine) GetBlockedEntities() []*BannedEntity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	list := make([]*BannedEntity, 0, len(e.bannedEntities))
	for _, b := range e.bannedEntities {
		list = append(list, b)
	}
	return list
}

// BanEntity explicitly adds an entity to the quarantine list.
func (e *UnifiedSecurityEngine) BanEntity(callerID string, reason ThreatClassification, desc string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.bannedEntities) >= 10000 {
		for k := range e.bannedEntities {
			delete(e.bannedEntities, k)
			break
		}
	}
	e.bannedEntities[callerID] = &BannedEntity{
		CallerID:  callerID,
		BlockedAt: time.Now(),
		Reason:    desc,
		RiskScore: 100,
	}
}

// UnblockEntity removes a quarantined entity by caller ID.
func (e *UnifiedSecurityEngine) UnblockEntity(callerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.bannedEntities, callerID)
	if p, ok := e.profiles[callerID]; ok {
		p.ThreatCount = 0
		p.RiskScore = 0
	}
}

// UnblockAllEntities clears all quarantines and resets all entity profiles.
func (e *UnifiedSecurityEngine) UnblockAllEntities() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bannedEntities = make(map[string]*BannedEntity)
	e.profiles = make(map[string]*entitySecurityProfile)
}

// IsEntityBlocked checks if an entity is currently quarantined.
func (e *UnifiedSecurityEngine) IsEntityBlocked(callerID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.bannedEntities[callerID]
	return exists
}
