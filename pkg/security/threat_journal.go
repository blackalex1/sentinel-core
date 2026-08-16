package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

// ThreatRecord is a single structured audit entry written to threats.jsonl when an anomaly or threat is detected.
type ThreatRecord struct {
	Timestamp      int64    `json:"timestamp"`
	NodeID         string   `json:"node_id,omitempty"`
	EventType      string   `json:"event_type"` // INCIDENT, COMPROMISED, QUARANTINED, UNQUARANTINED, THREAT_BLOCKED
	ThreatCategory string   `json:"threat_category,omitempty"`
	ClientID       string   `json:"client_id"`
	ClientAliases  []string `json:"client_aliases,omitempty"`
	RiskScore      int      `json:"risk_score"`
	Status         string   `json:"status"` // CLEAN, SUSPICIOUS, COMPROMISED, QUARANTINED
	Target         string   `json:"target,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	ActionTaken    string   `json:"action_taken,omitempty"` // KICKED, BLOCKED, ISOLATED, LOGGED
}

// ThreatJournal manages the low-overhead, threat-only JSONL log file.
type ThreatJournal struct {
	mu       sync.Mutex
	filePath string
	nodeID   string
	maxSize  int64 // max file size in bytes before rotation (default 10MB)
}

// NewThreatJournal creates a new threat journal manager.
func NewThreatJournal(filePath, nodeID string) (*ThreatJournal, error) {
	if filePath == "" {
		filePath = filepath.Join(os.TempDir(), "sentinel-threats.jsonl")
	}
	if nodeID == "" {
		nodeID, _ = os.Hostname()
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create threat journal directory: %w", err)
	}

	return &ThreatJournal{
		filePath: filePath,
		nodeID:   nodeID,
		maxSize:  10 * 1024 * 1024, // 10MB
	}, nil
}

// LogIncident writes a threat record to the journal ONLY if a threat or suspicious event occurs.
func (j *ThreatJournal) LogIncident(
	eventType string,
	category string,
	clientID string,
	aliases []string,
	score int,
	status detector.ClientStatus,
	target string,
	reason string,
	actionTaken string,
) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	rec := ThreatRecord{
		Timestamp:      time.Now().Unix(),
		NodeID:         j.nodeID,
		EventType:      eventType,
		ThreatCategory: category,
		ClientID:       clientID,
		ClientAliases:  aliases,
		RiskScore:      score,
		Status:         string(status),
		Target:         target,
		Reason:         reason,
		ActionTaken:    actionTaken,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	j.rotateIfNeeded()

	f, err := os.OpenFile(j.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

// ReadRecentRecords reads the last N records from the journal file.
func (j *ThreatJournal) ReadRecentRecords(maxLines int) ([]ThreatRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if _, err := os.Stat(j.filePath); os.IsNotExist(err) {
		return []ThreatRecord{}, nil
	}

	content, err := os.ReadFile(j.filePath)
	if err != nil {
		return nil, err
	}

	var lines []string
	var current []byte
	for _, b := range content {
		if b == '\n' {
			if len(current) > 0 {
				lines = append(lines, string(current))
				current = nil
			}
		} else if b != '\r' {
			current = append(current, b)
		}
	}
	if len(current) > 0 {
		lines = append(lines, string(current))
	}

	start := 0
	if maxLines > 0 && len(lines) > maxLines {
		start = len(lines) - maxLines
	}

	var records []ThreatRecord
	for i := start; i < len(lines); i++ {
		var rec ThreatRecord
		if err := json.Unmarshal([]byte(lines[i]), &rec); err == nil {
			records = append(records, rec)
		}
	}

	return records, nil
}

// FilePath returns the location of the journal file.
func (j *ThreatJournal) FilePath() string {
	return j.filePath
}

func (j *ThreatJournal) rotateIfNeeded() {
	fi, err := os.Stat(j.filePath)
	if err != nil || fi.Size() < j.maxSize {
		return
	}

	backupPath := j.filePath + ".1"
	_ = os.Remove(backupPath)
	_ = os.Rename(j.filePath, backupPath)
}
