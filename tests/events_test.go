package tests

import (
	"sync"
	"testing"
	"time"
	"github.com/blackalex1/sentinel-core/pkg/events"
)

func TestEventBus_PublishSubscribe(t *testing.T) {
	bus := events.NewEventBus(50)

	var wg sync.WaitGroup
	wg.Add(1)

	var receivedEvent events.SentinelEvent

	bus.Subscribe(func(evt events.SentinelEvent) {
		receivedEvent = evt
		wg.Done()
	})

	testEvt := events.NewEvent(
		events.CategoryCompileWarning,
		events.SeverityWarn,
		events.CodeFeatureDowngrade,
		"Test downgrade message",
		map[string]interface{}{"core": "singbox"},
		events.ActionNone,
	)

	bus.Publish(testEvt)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if receivedEvent.Code != events.CodeFeatureDowngrade {
			t.Errorf("expected event code %s, got %s", events.CodeFeatureDowngrade, receivedEvent.Code)
		}
		if receivedEvent.Message != "Test downgrade message" {
			t.Errorf("message mismatch, got: %s", receivedEvent.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event on EventBus")
	}
}
