package events

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewEvent_And_ToJSON(t *testing.T) {
	ctx := map[string]interface{}{
		"port":  10808,
		"core":  "sing-box",
		"error": "address already in use",
	}

	evt := NewEvent(
		CategoryRuntimeError,
		SeverityError,
		CodePortInUse,
		"Port 10808 is occupied",
		ctx,
		ActionKillConflictingPort,
	)

	if !strings.HasPrefix(evt.EventID, "evt-") {
		t.Errorf("expected event ID starting with 'evt-', got: %s", evt.EventID)
	}
	if evt.Timestamp <= 0 {
		t.Errorf("expected positive timestamp, got: %d", evt.Timestamp)
	}
	if evt.Category != CategoryRuntimeError || evt.Severity != SeverityError {
		t.Errorf("unexpected category/severity: %+v", evt)
	}
	if evt.Code != CodePortInUse || evt.SuggestedAction != ActionKillConflictingPort {
		t.Errorf("unexpected code/action: %+v", evt)
	}

	jsonStr, err := evt.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize event to JSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to parse generated JSON: %v", err)
	}

	if parsed["code"] != CodePortInUse || parsed["severity"] != string(SeverityError) {
		t.Errorf("JSON contents mismatch: %v", parsed)
	}
}

func TestGetGlobalBus(t *testing.T) {
	bus1 := GetGlobalBus()
	bus2 := GetGlobalBus()
	if bus1 == nil || bus2 == nil || bus1 != bus2 {
		t.Fatalf("expected singleton instance from GetGlobalBus")
	}
}

func TestEventBus_History_And_Capacity(t *testing.T) {
	bus := NewEventBus(-5) // should default to 100

	if bus.maxHistory != 100 {
		t.Errorf("expected maxHistory default to 100, got: %d", bus.maxHistory)
	}

	smallBus := NewEventBus(3)

	for i := 1; i <= 5; i++ {
		evt := NewEvent(
			CategoryDiagnostic,
			SeverityInfo,
			CodeHealthCheckPassed,
			fmt.Sprintf("event-%d", i),
			nil,
			ActionNone,
		)
		smallBus.Publish(evt)
	}

	history := smallBus.GetHistory()
	if len(history) != 3 {
		t.Fatalf("expected 3 history items, got %d", len(history))
	}

	// Should contain event-3, event-4, event-5
	if history[0].Message != "event-3" || history[2].Message != "event-5" {
		t.Errorf("expected sliding window history [event-3..event-5], got [%s, %s, %s]",
			history[0].Message, history[1].Message, history[2].Message)
	}

	// Clear History
	smallBus.ClearHistory()
	if len(smallBus.GetHistory()) != 0 {
		t.Errorf("expected empty history after ClearHistory")
	}
}

func TestEventBus_MultipleListeners_Concurrent(t *testing.T) {
	bus := NewEventBus(20)

	var wg sync.WaitGroup
	wg.Add(2)

	var l1Msg, l2Msg string
	var mu sync.Mutex

	bus.Subscribe(func(e SentinelEvent) {
		mu.Lock()
		l1Msg = e.Message
		mu.Unlock()
		wg.Done()
	})

	bus.Subscribe(func(e SentinelEvent) {
		mu.Lock()
		l2Msg = e.Message
		mu.Unlock()
		wg.Done()
	})

	evt := NewEvent(CategoryThreatBlocked, SeverityWarn, CodeThreatAppIsolated, "threat-blocked", nil, ActionNone)
	bus.Publish(evt)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		mu.Lock()
		if l1Msg != "threat-blocked" || l2Msg != "threat-blocked" {
			t.Errorf("expected both listeners to receive message, got l1=%s, l2=%s", l1Msg, l2Msg)
		}
		mu.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for multi-listener notification")
	}
}
