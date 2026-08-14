package events

import (
	"sync"
)

// EventListener is a callback function invoked on new events
type EventListener func(event SentinelEvent)

// EventBus provides thread-safe pub/sub dispatching of SentinelEvents
type EventBus struct {
	mu        sync.RWMutex
	listeners []EventListener
	history   []SentinelEvent
	maxHistory int
}

var (
	globalBus  *EventBus
	busOnce    sync.Once
)

// GetGlobalBus returns the singleton EventBus instance
func GetGlobalBus() *EventBus {
	busOnce.Do(func() {
		globalBus = NewEventBus(100)
	})
	return globalBus
}

// NewEventBus creates a new EventBus with bounded history
func NewEventBus(maxHistory int) *EventBus {
	if maxHistory <= 0 {
		maxHistory = 100
	}
	return &EventBus{
		listeners:  make([]EventListener, 0),
		history:    make([]SentinelEvent, 0),
		maxHistory: maxHistory,
	}
}

// Subscribe registers a listener callback
func (b *EventBus) Subscribe(listener EventListener) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners = append(b.listeners, listener)
}

// Publish emits an event to all registered listeners asynchronously
func (b *EventBus) Publish(event SentinelEvent) {
	b.mu.Lock()
	if len(b.history) >= b.maxHistory {
		b.history = b.history[1:]
	}
	b.history = append(b.history, event)
	currentListeners := make([]EventListener, len(b.listeners))
	copy(currentListeners, b.listeners)
	b.mu.Unlock()

	// Notify listeners
	for _, l := range currentListeners {
		go l(event)
	}
}

// GetHistory returns a copy of stored event history
func (b *EventBus) GetHistory() []SentinelEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]SentinelEvent, len(b.history))
	copy(copied, b.history)
	return copied
}

// ClearHistory resets the history buffer
func (b *EventBus) ClearHistory() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.history = make([]SentinelEvent, 0)
}
