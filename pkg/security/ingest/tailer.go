package ingest

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LogLineCallback is a function invoked for every ingested log line.
type LogLineCallback func(line string)

// LogTailer tails local log files or journalctl command streams in real time.
type LogTailer struct {
	mu        sync.Mutex
	source    string   // File path or command name
	cmdArgs   []string // Arguments if source is a command
	isCommand bool
	callback  LogLineCallback
	running   bool
	cancelFn  context.CancelFunc
}

// NewFileTailer creates a LogTailer that tails a local log file.
func NewFileTailer(filePath string, callback LogLineCallback) *LogTailer {
	return &LogTailer{
		source:    filePath,
		isCommand: false,
		callback:  callback,
	}
}

// NewCommandTailer creates a LogTailer that reads live stdout lines from a command (e.g. journalctl).
func NewCommandTailer(cmd string, args []string, callback LogLineCallback) *LogTailer {
	return &LogTailer{
		source:    cmd,
		cmdArgs:   args,
		isCommand: true,
		callback:  callback,
	}
}

// Start begins asynchronous streaming in a background goroutine.
func (t *LogTailer) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return nil
	}
	t.running = true
	subCtx, cancel := context.WithCancel(ctx)
	t.cancelFn = cancel
	t.mu.Unlock()

	go func() {
		defer func() {
			t.mu.Lock()
			t.running = false
			t.mu.Unlock()
		}()

		for {
			select {
			case <-subCtx.Done():
				return
			default:
			}

			if t.isCommand {
				t.runCommand(subCtx)
			} else {
				t.runFile(subCtx)
			}

			// If exited and still supposed to be running, backoff and retry
			select {
			case <-subCtx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	return nil
}

// Stop terminates the tailer goroutine.
func (t *LogTailer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancelFn != nil {
		t.cancelFn()
	}
	t.running = false
}

// IsRunning returns true if the tailer is active.
func (t *LogTailer) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

func (t *LogTailer) runCommand(ctx context.Context) {
	cmd := exec.CommandContext(ctx, t.source, t.cmdArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	_ = cmd.Start()

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line != "" && t.callback != nil {
			t.callback(line)
		}
	}

	_ = cmd.Wait()
}

func (t *LogTailer) runFile(ctx context.Context) {
	cleanPath := filepath.Clean(t.source)

	// Wait for file to exist
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := os.Stat(cleanPath); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Seek to end of file to tail only new logs
	_, _ = file.Seek(0, io.SeekEnd)

	var lastIno uint64
	if st, err := file.Stat(); err == nil {
		lastIno = getInode(st)
	}

	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			cleanLine := strings.TrimRight(line, "\r\n")
			if cleanLine != "" && t.callback != nil {
				t.callback(cleanLine)
			}
		}

		if err == io.EOF {
			time.Sleep(100 * time.Millisecond)

			// Check file rotation or truncation
			if st, statErr := os.Stat(cleanPath); statErr == nil {
				curIno := getInode(st)
				curPos, _ := file.Seek(0, io.SeekCurrent)
				if (lastIno != 0 && curIno != lastIno) || (st.Size() < curPos) {
					// File rotated or truncated - reopen
					return
				}
			}
			continue
		} else if err != nil {
			return
		}
	}
}
