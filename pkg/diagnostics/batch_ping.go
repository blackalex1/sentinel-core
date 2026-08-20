package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PingTarget specifies a single host/port destination for batch pinging
type PingTarget struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// BatchPingResult holds latency result for a single target in batch ping
type BatchPingResult struct {
	ID        string  `json:"id"`
	Address   string  `json:"address"`
	Port      int     `json:"port"`
	Success   bool    `json:"success"`
	LatencyMs float64 `json:"latencyMs,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// ProxyPingResult holds result for real HTTP/TLS handshake ping via SOCKS5 proxy
type ProxyPingResult struct {
	Success   bool    `json:"success"`
	LatencyMs float64 `json:"latencyMs,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// BatchPing executes concurrent TCP ping across multiple targets with a maximum concurrency limit
func BatchPing(targets []PingTarget, timeout time.Duration, concurrency int) []BatchPingResult {
	if len(targets) == 0 {
		return []BatchPingResult{}
	}
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 16
	}

	results := make([]BatchPingResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target PingTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := PingHostPort(target.Address, target.Port, timeout)
			results[idx] = BatchPingResult{
				ID:        target.ID,
				Address:   target.Address,
				Port:      target.Port,
				Success:   res.Success,
				LatencyMs: res.LatencyMs,
				Error:     res.Error,
			}
		}(i, t)
	}

	wg.Wait()
	return results
}

// PingThroughProxy measures real end-to-end RTT through a local SOCKS5 proxy (or direct if socksPort == 0) to a test URL (e.g. Cloudflare generate_204)
func PingThroughProxy(socksPort int, authUser, authPass, targetURL string, timeout time.Duration) ProxyPingResult {
	if socksPort < 0 || socksPort > 65535 {
		return ProxyPingResult{Success: false, Error: fmt.Sprintf("invalid proxy port: %d", socksPort)}
	}
	if targetURL == "" {
		targetURL = "http://cp.cloudflare.com/generate_204"
	}
	if timeout <= 0 {
		timeout = 3000 * time.Millisecond
	}

	var transport *http.Transport
	if socksPort > 0 {
		var proxyURL *url.URL
		var err error
		if authUser != "" {
			proxyURL, err = url.Parse(fmt.Sprintf("socks5://%s:%s@127.0.0.1:%d", url.QueryEscape(authUser), url.QueryEscape(authPass), socksPort))
		} else {
			proxyURL, err = url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
		}
		if err != nil {
			return ProxyPingResult{Success: false, Error: fmt.Sprintf("invalid proxy url: %v", err)}
		}

		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: -1,
			}).DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		}
	} else {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: -1,
			}).DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return ProxyPingResult{Success: false, Error: fmt.Sprintf("invalid request: %v", err)}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelCore/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return ProxyPingResult{Success: false, Error: cleanNetError(err)}
	}
	defer resp.Body.Close()

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return ProxyPingResult{
			Success:   true,
			LatencyMs: latency,
		}
	}

	return ProxyPingResult{
		Success:   false,
		LatencyMs: latency,
		Error:     fmt.Sprintf("HTTP status %d", resp.StatusCode),
	}
}

func cleanNetError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout") {
		return "timeout"
	}
	if strings.Contains(msg, "connection refused") {
		return "connection refused"
	}
	return msg
}
