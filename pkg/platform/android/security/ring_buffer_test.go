package security

import (
	"fmt"
	"testing"
	"time"
)

func TestAndroidLogRingBuffer(t *testing.T) {
	buf := NewAndroidLogRingBuffer(5)

	// Push 7 entries (will wrap around 5)
	for i := 1; i <= 7; i++ {
		buf.Push(AndroidLogEntry{
			PackageName:     fmt.Sprintf("org.telegram.messenger.%d", i),
			AppName:         "Telegram",
			DestinationIP:   "149.154.167.50",
			DestinationPort: 443,
			Protocol:        "TCP",
			Timestamp:       time.Now().UnixMilli() + int64(i),
		})
	}

	stats := buf.GetStats()
	if stats.TotalConnections != 7 {
		t.Errorf("expected total logged 7, got %d", stats.TotalConnections)
	}

	// Should contain 5 stored entries (since capacity is 5)
	logs := buf.GetLogs(10, 0, 0, "")
	if len(logs) != 5 {
		t.Fatalf("expected 5 stored logs, got %d", len(logs))
	}

	// Newest first -> index 7 should be first
	if logs[0].PackageName != "org.telegram.messenger.7" {
		t.Errorf("expected newest entry first, got %s", logs[0].PackageName)
	}

	// Test port filter
	buf.Push(AndroidLogEntry{
		PackageName:     "com.google.android.youtube",
		AppName:         "YouTube",
		DestinationIP:   "172.217.16.206",
		DestinationPort: 80,
		Protocol:        "TCP",
	})

	port80Logs := buf.GetLogs(10, 0, 80, "")
	if len(port80Logs) != 1 || port80Logs[0].AppName != "YouTube" {
		t.Errorf("expected 1 port 80 log for YouTube, got %+v", port80Logs)
	}

	// Test search query
	ytLogs := buf.GetLogs(10, 0, 0, "youtube")
	if len(ytLogs) != 1 || ytLogs[0].AppName != "YouTube" {
		t.Errorf("expected search match for YouTube, got %+v", ytLogs)
	}

	// Clear
	buf.Clear()
	if len(buf.GetLogs(10, 0, 0, "")) != 0 {
		t.Errorf("expected empty buffer after Clear()")
	}
}
