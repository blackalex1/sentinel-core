package ingest

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// SecurityEvent represents a normalized, structured security incident emitted by sentinel-core.
type SecurityEvent struct {
	EventID        string    `json:"event_id"`
	EventType      string    `json:"event_type"` // THREAT_DETECTED, ROUTER_AUTOBLOCK, SUSPICIOUS_PORT_ACCESS, PROCESS_KILLED
	Source         string    `json:"source"`     // proxmox_iptables, router_conntrack, router_syslog, proxy_core, auth_ssh
	Timestamp      time.Time `json:"timestamp"`
	RiskLevel      string    `json:"risk_level"` // INFO, WARNING, CRITICAL
	SrcIP          string    `json:"src_ip"`
	SrcPort        int       `json:"src_port"`
	DstHost        string    `json:"dst_host"`
	DstPort        int       `json:"dst_port"`
	Proto          string    `json:"proto"`
	VMID           int       `json:"vmid,omitempty"`
	Direction      string    `json:"direction,omitempty"` // IN, OUT
	Reason         string    `json:"reason"`
	ThreatType     string    `json:"threat_type,omitempty"`
	ShouldAutoBan  bool      `json:"should_autoban"`
	ClientEmail    string    `json:"client_email,omitempty"`
	RealClientIP   string    `json:"real_client_ip,omitempty"`
	ProcessName    string    `json:"process_name,omitempty"`
	PID            int       `json:"pid,omitempty"`
	RawLine        string    `json:"raw_line,omitempty"`
}

// EventDispatcher manages in-memory event streaming and fan-out to subscribers.
type EventDispatcher struct {
	mu          sync.RWMutex
	maxHistory  int
	history     []SecurityEvent
	subscribers []chan SecurityEvent
	popQueue    chan SecurityEvent
}

var defaultDispatcher = NewEventDispatcher(500)

// GetDefaultEventDispatcher returns the singleton event dispatcher instance.
func GetDefaultEventDispatcher() *EventDispatcher {
	return defaultDispatcher
}

// NewEventDispatcher creates a new EventDispatcher.
func NewEventDispatcher(maxHistory int) *EventDispatcher {
	if maxHistory <= 0 {
		maxHistory = 500
	}
	return &EventDispatcher{
		maxHistory:  maxHistory,
		history:     make([]SecurityEvent, 0, maxHistory),
		subscribers: make([]chan SecurityEvent, 0),
		popQueue:    make(chan SecurityEvent, 1000),
	}
}

// Emit broadcasts a security event to all active subscribers and updates the history ring buffer.
func (d *EventDispatcher) Emit(ev SecurityEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.EventType == "" {
		ev.EventType = "THREAT_DETECTED"
	}

	d.mu.Lock()
	d.history = append(d.history, ev)
	if len(d.history) > d.maxHistory {
		d.history = d.history[len(d.history)-d.maxHistory:]
	}

	// Fan out to active channels
	var activeSubs []chan SecurityEvent
	for _, ch := range d.subscribers {
		select {
		case ch <- ev:
			activeSubs = append(activeSubs, ch)
		default:
			// Queue full - keep subscriber alive
			activeSubs = append(activeSubs, ch)
		}
	}
	d.subscribers = activeSubs
	d.mu.Unlock()

	// Push to popQueue
	select {
	case d.popQueue <- ev:
	default:
		// Queue full, drop oldest
		select {
		case <-d.popQueue:
		default:
		}
		d.popQueue <- ev
	}
}

// Subscribe returns a channel that receives live security events.
func (d *EventDispatcher) Subscribe() chan SecurityEvent {
	ch := make(chan SecurityEvent, 200)
	d.mu.Lock()
	d.subscribers = append(d.subscribers, ch)
	d.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel.
func (d *EventDispatcher) Unsubscribe(ch chan SecurityEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, c := range d.subscribers {
		if c == ch {
			d.subscribers = append(d.subscribers[:i], d.subscribers[i+1:]...)
			close(ch)
			break
		}
	}
}

// PopEventJSON pops an event as JSON string with a timeout (for C-FFI / Python bindings).
func (d *EventDispatcher) PopEventJSON(timeout time.Duration) string {
	if timeout <= 0 {
		select {
		case ev := <-d.popQueue:
			bytes, _ := json.Marshal(ev)
			return string(bytes)
		default:
			return ""
		}
	}

	select {
	case ev := <-d.popQueue:
		bytes, _ := json.Marshal(ev)
		return string(bytes)
	case <-time.After(timeout):
		return ""
	}
}

// GetHistory returns recent buffered security events.
func (d *EventDispatcher) GetHistory(limit int) []SecurityEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.history) == 0 {
		return []SecurityEvent{}
	}
	if limit <= 0 || limit > len(d.history) {
		limit = len(d.history)
	}
	result := make([]SecurityEvent, limit)
	copy(result, d.history[len(d.history)-limit:])
	return result
}

// Clear removes all history and drains the pop queue.
func (d *EventDispatcher) Clear() {
	d.mu.Lock()
	d.history = d.history[:0]
	d.mu.Unlock()

	for len(d.popQueue) > 0 {
		select {
		case <-d.popQueue:
		default:
		}
	}
}

// JSONString returns JSON representation of the event.
func (e *SecurityEvent) JSONString() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func normalizeProto(p string) string {
	return strings.ToUpper(strings.TrimSpace(p))
}
