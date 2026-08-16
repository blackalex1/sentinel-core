package detector

import (
	"strings"
	"sync"
)

// ClientIdentity maintains unified cross-core client mapping.
// Since Sing-box, Xray, and Hysteria 2 represent clients differently (UUID vs Email vs Username vs IP),
// ClientIdentity links all representations to the same physical subscriber.
type ClientIdentity struct {
	PrimaryID    string   `json:"primary_id"`    // Usually User Email or Account ID
	UUIDs        []string `json:"uuids"`         // Xray & Sing-box VLESS/VMess UUIDs
	HysteriaUser string   `json:"hysteria_user"` // Hysteria 2 Auth Username/Token
	SourceIPs    []string `json:"source_ips"`    // Recent client IP addresses
	InboundTags  []string `json:"inbound_tags"`  // Associated inbounds
}

// ClientRegistry stores and resolves aliases across Sing-box, Xray, and Hysteria.
type ClientRegistry struct {
	mu           sync.RWMutex
	identities   map[string]*ClientIdentity // key: PrimaryID
	aliasToID    map[string]string          // alias (UUID, email, HysteriaUser, IP) -> PrimaryID
}

// NewClientRegistry creates a new multi-core client alias registry.
func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{
		identities: make(map[string]*ClientIdentity),
		aliasToID:  make(map[string]string),
	}
}

// RegisterClient registers or updates a client with their identifiers across the 3 cores.
func (r *ClientRegistry) RegisterClient(primaryID string, uuid string, hysteriaUser string, sourceIP string) *ClientIdentity {
	r.mu.Lock()
	defer r.mu.Unlock()

	cleanPrimary := strings.ToLower(strings.TrimSpace(primaryID))
	if cleanPrimary == "" {
		if uuid != "" {
			cleanPrimary = strings.ToLower(strings.TrimSpace(uuid))
		} else if hysteriaUser != "" {
			cleanPrimary = strings.ToLower(strings.TrimSpace(hysteriaUser))
		} else {
			return nil
		}
	}

	identity, exists := r.identities[cleanPrimary]
	if !exists {
		identity = &ClientIdentity{
			PrimaryID:    cleanPrimary,
			UUIDs:        make([]string, 0),
			HysteriaUser: strings.TrimSpace(hysteriaUser),
			SourceIPs:    make([]string, 0),
			InboundTags:  make([]string, 0),
		}
		r.identities[cleanPrimary] = identity
	}

	r.aliasToID[cleanPrimary] = cleanPrimary

	if uuid != "" {
		cleanUUID := strings.ToLower(strings.TrimSpace(uuid))
		if !contains(identity.UUIDs, cleanUUID) {
			identity.UUIDs = append(identity.UUIDs, cleanUUID)
		}
		r.aliasToID[cleanUUID] = cleanPrimary
	}

	if hysteriaUser != "" {
		cleanHy := strings.TrimSpace(hysteriaUser)
		identity.HysteriaUser = cleanHy
		r.aliasToID[strings.ToLower(cleanHy)] = cleanPrimary
	}

	if sourceIP != "" {
		cleanIP := strings.TrimSpace(sourceIP)
		if !contains(identity.SourceIPs, cleanIP) {
			identity.SourceIPs = append(identity.SourceIPs, cleanIP)
		}
		r.aliasToID[cleanIP] = cleanPrimary
	}

	return identity
}

// ResolvePrimaryID maps any core identifier (UUID, Email, Hysteria user, or IP) to the unified PrimaryID.
func (r *ClientRegistry) ResolvePrimaryID(identifier string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clean := strings.ToLower(strings.TrimSpace(identifier))
	if primary, exists := r.aliasToID[clean]; exists {
		return primary
	}
	return clean
}

// GetAllAliases returns all known identifiers (Emails, UUIDs, Hysteria usernames, IPs) for a primary client.
func (r *ClientRegistry) GetAllAliases(primaryID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clean := strings.ToLower(strings.TrimSpace(primaryID))
	identity, exists := r.identities[clean]
	if !exists {
		return []string{clean}
	}

	aliases := []string{identity.PrimaryID}
	aliases = append(aliases, identity.UUIDs...)
	if identity.HysteriaUser != "" && identity.HysteriaUser != identity.PrimaryID {
		aliases = append(aliases, identity.HysteriaUser)
	}
	aliases = append(aliases, identity.SourceIPs...)
	return aliases
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
