package ingest

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RouterSSHConfig contains connection parameters for remote router streaming.
type RouterSSHConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	KeyPath  string `json:"key_path,omitempty"`
	Password string `json:"password,omitempty"`
	Mode     string `json:"mode"` // "conntrack", "syslog", "both"
}

// RouterSSHWatcher connects to OpenWrt / router and streams conntrack/iptables events.
type RouterSSHWatcher struct {
	mu       sync.Mutex
	config   RouterSSHConfig
	callback LogLineCallback
	running  bool
	cancelFn context.CancelFunc
}

// NewRouterSSHWatcher creates a new RouterSSHWatcher instance.
func NewRouterSSHWatcher(cfg RouterSSHConfig, callback LogLineCallback) *RouterSSHWatcher {
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Mode == "" {
		cfg.Mode = "conntrack"
	}
	return &RouterSSHWatcher{
		config:   cfg,
		callback: callback,
	}
}

// Start begins the SSH streaming loop in a background goroutine.
func (w *RouterSSHWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	subCtx, cancel := context.WithCancel(ctx)
	w.cancelFn = cancel
	w.mu.Unlock()

	go func() {
		defer func() {
			w.mu.Lock()
			w.running = false
			w.mu.Unlock()
		}()

		for {
			select {
			case <-subCtx.Done():
				return
			default:
			}

			w.streamRemote(subCtx)

			select {
			case <-subCtx.Done():
				return
			case <-time.After(5 * time.Second): // Auto-reconnect delay
			}
		}
	}()

	return nil
}

// Stop terminates the SSH streaming session.
func (w *RouterSSHWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancelFn != nil {
		w.cancelFn()
	}
	w.running = false
}

// IsRunning returns true if the watcher is active.
func (w *RouterSSHWatcher) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

func (w *RouterSSHWatcher) streamRemote(ctx context.Context) {
	var remoteCmd string
	pathPrefix := "export PATH=$PATH:/sbin:/usr/sbin:/opt/bin:/opt/sbin; "

	if w.config.Mode == "syslog" {
		remoteCmd = pathPrefix + "logread -f || tail -f /var/log/messages"
	} else {
		// default: conntrack
		remoteCmd = pathPrefix + "conntrack -E -p tcp -e NEW"
	}

	sshArgs, err := BuildSSHArgs(w.config, remoteCmd)
	if err != nil {
		return
	}

	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line != "" && w.callback != nil {
			w.callback(line)
		}
	}

	_ = cmd.Wait()
}

// BuildSSHArgs validates connection parameters and generates OpenSSH arguments safely,
// defending against OpenSSH flag/option injection (CWE-88) and command injection.
func BuildSSHArgs(cfg RouterSSHConfig, remoteCmd string) ([]string, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("empty ssh host")
	}
	if strings.HasPrefix(cfg.Host, "-") || strings.ContainsAny(cfg.Host, " \t\r\n'\"`;&|") {
		return nil, fmt.Errorf("invalid or insecure ssh host: %q", cfg.Host)
	}

	cleanUser := cfg.User
	if cleanUser == "" {
		cleanUser = "root"
	}
	if strings.HasPrefix(cleanUser, "-") || strings.ContainsAny(cleanUser, " \t\r\n'\"`;&|") {
		return nil, fmt.Errorf("invalid or insecure ssh user: %q", cleanUser)
	}

	port := cfg.Port
	if port <= 0 {
		port = 22
	}

	sshArgs := []string{
		"-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=10",
	}

	if cfg.KeyPath != "" {
		if strings.HasPrefix(cfg.KeyPath, "-") || strings.ContainsAny(cfg.KeyPath, "\r\n'\"`;&|") {
			return nil, fmt.Errorf("invalid or insecure ssh key path: %q", cfg.KeyPath)
		}
		sshArgs = append(sshArgs, "-i", cfg.KeyPath)
	}

	target := fmt.Sprintf("%s@%s", cleanUser, cfg.Host)
	// Use -- to separate options from destination, preventing option injection
	sshArgs = append(sshArgs, "--", target, remoteCmd)
	return sshArgs, nil
}

