package supervisor

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LogBroadcaster manages in-memory live log streams and ring buffers for cores
type LogBroadcaster struct {
	mu          sync.RWMutex
	maxHistory  int
	history     map[string][]string
	subscribers map[string][]chan string
	popQueues   map[string]chan string
}

var defaultBroadcaster = NewLogBroadcaster(500)

// GetLogBroadcaster returns the singleton in-memory log broadcaster
func GetLogBroadcaster() *LogBroadcaster {
	return defaultBroadcaster
}

// NewLogBroadcaster creates a new log broadcaster with history limit
func NewLogBroadcaster(maxHistory int) *LogBroadcaster {
	if maxHistory <= 0 {
		maxHistory = 500
	}
	return &LogBroadcaster{
		maxHistory:  maxHistory,
		history:     make(map[string][]string),
		subscribers: make(map[string][]chan string),
		popQueues:   make(map[string]chan string),
	}
}

func (lb *LogBroadcaster) getPopQueue(coreName string) chan string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	q, exists := lb.popQueues[coreName]
	if !exists {
		q = make(chan string, 1000)
		lb.popQueues[coreName] = q
	}
	return q
}

// PushLine appends a line to history and delivers to all active stream channels
func (lb *LogBroadcaster) PushLine(coreName, line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}

	norm := normalizeCoreName(coreName)

	lb.mu.Lock()
	// 1. History ring buffer
	hist := lb.history[norm]
	hist = append(hist, line)
	if len(hist) > lb.maxHistory {
		hist = hist[len(hist)-lb.maxHistory:]
	}
	lb.history[norm] = hist

	// 2. Broadcast to subscribers
	subs := lb.subscribers[norm]
	var activeSubs []chan string
	for _, ch := range subs {
		select {
		case ch <- line:
			activeSubs = append(activeSubs, ch)
		default:
			// Queue full, drop or preserve channel
			activeSubs = append(activeSubs, ch)
		}
	}
	lb.subscribers[norm] = activeSubs

	// 3. Push to pop queue
	q, exists := lb.popQueues[norm]
	if !exists {
		q = make(chan string, 1000)
		lb.popQueues[norm] = q
	}
	lb.mu.Unlock()

	select {
	case q <- line:
	default:
		// Queue full, discard oldest if needed
	}

	// 4. Update session tracking in-memory
	GetSessionTracker().ProcessLogLine(norm, line)
}

// GetHistory returns recent buffered log lines for the core
func (lb *LogBroadcaster) GetHistory(coreName string, limit int) []string {
	norm := normalizeCoreName(coreName)
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	hist := lb.history[norm]
	if len(hist) == 0 {
		return []string{}
	}
	if limit <= 0 || limit > len(hist) {
		limit = len(hist)
	}
	result := make([]string, limit)
	copy(result, hist[len(hist)-limit:])
	return result
}

// Subscribe returns a channel that receives live log lines
func (lb *LogBroadcaster) Subscribe(coreName string) chan string {
	norm := normalizeCoreName(coreName)
	ch := make(chan string, 200)

	lb.mu.Lock()
	lb.subscribers[norm] = append(lb.subscribers[norm], ch)
	lb.mu.Unlock()

	return ch
}

// Unsubscribe removes a subscription channel
func (lb *LogBroadcaster) Unsubscribe(coreName string, ch chan string) {
	norm := normalizeCoreName(coreName)
	lb.mu.Lock()
	defer lb.mu.Unlock()

	subs := lb.subscribers[norm]
	for i, c := range subs {
		if c == ch {
			lb.subscribers[norm] = append(subs[:i], subs[i+1:]...)
			close(ch)
			break
		}
	}
}

// PopLine pops a line with a timeout (for C-FFI non-blocking/short-polling streaming)
func (lb *LogBroadcaster) PopLine(coreName string, timeout time.Duration) string {
	norm := normalizeCoreName(coreName)
	q := lb.getPopQueue(norm)

	if timeout <= 0 {
		select {
		case line := <-q:
			return line
		default:
			return ""
		}
	}

	select {
	case line := <-q:
		return line
	case <-time.After(timeout):
		return ""
	}
}

// Clear clears in-memory logs for a core
func (lb *LogBroadcaster) Clear(coreName string) {
	norm := normalizeCoreName(coreName)
	lb.mu.Lock()
	delete(lb.history, norm)
	if q, ok := lb.popQueues[norm]; ok {
		// Drain queue
		for len(q) > 0 {
			select {
			case <-q:
			default:
			}
		}
	}
	lb.mu.Unlock()
}

// StreamPipe reads from an io.Reader (such as process stdout/stderr pipe) line-by-line in real time
func StreamPipe(coreName string, r io.Reader) {
	if r == nil {
		return
	}
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		defaultBroadcaster.PushLine(coreName, line)
	}
}

// TailFile follows a log file line-by-line in real time, pushing new lines into LogBroadcaster.
func TailFile(coreName string, filePath string, stopCh <-chan struct{}) {
	if filePath == "" {
		return
	}
	cleanPath := filepath.Clean(filePath)

	// Wait up to 5s for the log file to appear if it is being created by a newly started process
	for i := 0; i < 50; i++ {
		select {
		case <-stopCh:
			return
		default:
		}
		if _, err := os.Stat(cleanPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Seek to end of file to tail live additions
	_, _ = file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed != "" {
				defaultBroadcaster.PushLine(coreName, trimmed)
			}
		} else if err == io.EOF {
			// Check if file was truncated/recreated
			if fi, statErr := os.Stat(cleanPath); statErr == nil {
				if curOffset, _ := file.Seek(0, io.SeekCurrent); fi.Size() < curOffset {
					_, _ = file.Seek(0, io.SeekStart)
				}
			}
			time.Sleep(50 * time.Millisecond)
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// ReadCoreLogs reads the last N lines from the given log file path.
func ReadCoreLogs(logPath string, maxLines int) ([]string, error) {
	if maxLines <= 0 {
		maxLines = 100
	}

	cleanPath := filepath.Clean(logPath)
	file, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	// Read lines efficiently with circular buffer or scanning
	var lines []string
	scanner := bufio.NewScanner(file)
	// Buffer size for long lines
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxLines*2 {
			lines = lines[len(lines)-maxLines:]
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		// return whatever lines were captured
		if len(lines) > 0 {
			if len(lines) > maxLines {
				return lines[len(lines)-maxLines:], nil
			}
			return lines, nil
		}
		return nil, err
	}

	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	return lines, nil
}

