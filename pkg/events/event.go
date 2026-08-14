package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// SentinelEvent represents a structured event transmitted from the core to UI applications.
type SentinelEvent struct {
	EventID         string                 `json:"eventId"`
	Timestamp       int64                  `json:"timestamp"`
	Category        EventCategory          `json:"category"`
	Severity        EventSeverity          `json:"severity"`
	Code            string                 `json:"code"`
	Message         string                 `json:"message"`
	Context         map[string]interface{} `json:"context,omitempty"`
	SuggestedAction string                 `json:"suggestedAction,omitempty"`
}

// NewEvent creates a new SentinelEvent with a unique ID and current timestamp.
func NewEvent(
	category EventCategory,
	severity EventSeverity,
	code string,
	message string,
	context map[string]interface{},
	suggestedAction string,
) SentinelEvent {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	eventId := "evt-" + hex.EncodeToString(b)

	return SentinelEvent{
		EventID:         eventId,
		Timestamp:       time.Now().Unix(),
		Category:        category,
		Severity:        severity,
		Code:            code,
		Message:         message,
		Context:         context,
		SuggestedAction: suggestedAction,
	}
}

// ToJSON serializes the event to JSON string.
func (e *SentinelEvent) ToJSON() (string, error) {
	bytes, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
