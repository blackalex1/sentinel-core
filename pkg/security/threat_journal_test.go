package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

func TestThreatJournal_LogReadAndRotate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel-journal-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	journalPath := filepath.Join(tempDir, "threats.jsonl")
	tj, err := NewThreatJournal(journalPath, "test-node-01")
	if err != nil {
		t.Fatalf("NewThreatJournal failed: %v", err)
	}

	if tj.FilePath() != journalPath {
		t.Errorf("expected FilePath=%s, got %s", journalPath, tj.FilePath())
	}

	// 1. Initial read should be empty
	records, err := tj.ReadRecentRecords(10)
	if err != nil {
		t.Fatalf("ReadRecentRecords failed on empty file: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}

	// 2. Log several incidents
	for i := 1; i <= 5; i++ {
		err = tj.LogIncident(
			"INCIDENT",
			"SSRF_PROBE",
			"bad-client-1",
			[]string{"bad-alias"},
			80+i,
			detector.StatusSuspicious,
			"169.254.169.254:80",
			"Metadata probe",
			"BLOCKED",
		)
		if err != nil {
			t.Fatalf("LogIncident %d failed: %v", i, err)
		}
	}

	// 3. Read recent records with limit
	recent3, err := tj.ReadRecentRecords(3)
	if err != nil {
		t.Fatalf("ReadRecentRecords(3) failed: %v", err)
	}
	if len(recent3) != 3 {
		t.Errorf("expected 3 records, got %d", len(recent3))
	}
	if recent3[2].RiskScore != 85 {
		t.Errorf("expected last record score=85, got %d", recent3[2].RiskScore)
	}

	// 4. Test rotation by setting a tiny maxSize
	tj.maxSize = 50 // byte limit to force rotation
	err = tj.LogIncident(
		"INCIDENT",
		"PORT_SCAN",
		"bad-client-2",
		nil,
		100,
		detector.StatusCompromised,
		"192.168.1.1:445",
		"SMB scan",
		"ISOLATED",
	)
	if err != nil {
		t.Fatalf("LogIncident after rotation limit failed: %v", err)
	}

	// Backup file (.1) should exist
	backupPath := journalPath + ".1"
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("expected rotated backup file %s to exist: %v", backupPath, err)
	}
}

func TestThreatJournal_DefaultPathAndNodeID(t *testing.T) {
	tj, err := NewThreatJournal("", "")
	if err != nil {
		t.Fatalf("NewThreatJournal with defaults failed: %v", err)
	}
	if tj.FilePath() == "" {
		t.Errorf("expected non-empty default filePath")
	}
}
