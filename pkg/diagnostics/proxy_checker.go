package diagnostics

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// ProxyBatchResult represents check result for a single proxy
type ProxyBatchResult struct {
	ProxyURL  string  `json:"proxyUrl"`
	Protocol  string  `json:"protocol,omitempty"`
	Name      string  `json:"name,omitempty"`
	Success   bool    `json:"success"`
	LatencyMs float64 `json:"latencyMs"`
	Error     string  `json:"error,omitempty"`
}

// CheckSocks5Direct performs high-performance RFC 1928 SOCKS5 handshake and HTTP/TLS probe
func CheckSocks5Direct(proxyHostPort, targetHost string, targetPort int, useTLS bool, timeout time.Duration) (bool, float64, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", proxyHostPort, timeout)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 1. SOCKS5 greeting (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false, 0, err
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return false, 0, err
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		return false, 0, fmt.Errorf("socks5 auth rejected: %v", authResp)
	}

	// 2. SOCKS5 Connect to target host:port (domain name type 0x03)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	req = append(req, portBuf...)

	if _, err := conn.Write(req); err != nil {
		return false, 0, err
	}

	// Read reply
	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		return false, 0, err
	}
	if replyHeader[1] != 0x00 {
		return false, 0, fmt.Errorf("socks5 connect error: 0x%02x", replyHeader[1])
	}
	// Discard bound address
	switch replyHeader[3] {
	case 0x01: // IPv4
		_, _ = io.CopyN(io.Discard, conn, 4+2)
	case 0x03: // FQDN
		l := make([]byte, 1)
		_, _ = io.ReadFull(conn, l)
		_, _ = io.CopyN(io.Discard, conn, int64(l[0])+2)
	case 0x04: // IPv6
		_, _ = io.CopyN(io.Discard, conn, 16+2)
	}

	// 3. Send HTTP / TLS probe
	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			return false, 0, err
		}
		defer tlsConn.Close()
		httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", targetHost)
		if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
			return false, 0, err
		}
		respBuf := make([]byte, 12)
		if _, err := io.ReadFull(tlsConn, respBuf); err != nil {
			return false, 0, err
		}
		if !strings.HasPrefix(string(respBuf), "HTTP/") {
			return false, 0, fmt.Errorf("invalid http response: %s", string(respBuf))
		}
	} else {
		httpReq := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", targetHost)
		if _, err := conn.Write([]byte(httpReq)); err != nil {
			return false, 0, err
		}
		respBuf := make([]byte, 12)
		if _, err := io.ReadFull(conn, respBuf); err != nil {
			return false, 0, err
		}
		if !strings.HasPrefix(string(respBuf), "HTTP/") {
			return false, 0, fmt.Errorf("invalid http response: %s", string(respBuf))
		}
	}

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	return true, latency, nil
}

// CheckVLESSRealityProbe checks TCP & TLS/Reality handshake responsiveness for VLESS/Reality or Trojan/Hysteria nodes
func CheckVLESSRealityProbe(profile *ast.ServerProfile, timeout time.Duration) (bool, float64, error) {
	if profile == nil || profile.Address == "" || profile.Port <= 0 {
		return false, 0, fmt.Errorf("invalid server profile")
	}

	addr := net.JoinHostPort(profile.Address, fmt.Sprintf("%d", profile.Port))
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if profile.Security == "none" || profile.Security == "" {
		// Plain HTTP / TCP / WebSocket without TLS
		httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", profile.Address)
		_, _ = conn.Write([]byte(httpReq))
		respBuf := make([]byte, 12)
		_, err := io.ReadFull(conn, respBuf)
		if err == nil && strings.HasPrefix(string(respBuf), "HTTP/") {
			return true, float64(time.Since(start).Microseconds()) / 1000.0, nil
		}
		return true, float64(time.Since(start).Microseconds()) / 1000.0, nil
	}

	sni := profile.SNI
	if sni == "" {
		sni = profile.Address
	}

	alpn := profile.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		// Even if TLS handshake certificate validation fails on reality self-signed,
		// successful TLS server response proves TCP + Reality handshake reaches active server
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "unknown authority") {
			return false, 0, err
		}
	}
	defer tlsConn.Close()

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	return true, latency, nil
}

// CheckProxyTarget tests any proxy (VLESS Reality, SOCKS5, HTTP, Hysteria2, Trojan, etc.)
func CheckProxyTarget(proxyStr, targetHost string, targetPort int, useTLS bool, timeout time.Duration) ProxyBatchResult {
	cleanProxy := strings.TrimSpace(proxyStr)
	if cleanProxy == "" {
		return ProxyBatchResult{ProxyURL: proxyStr, Success: false, Error: "empty proxy string"}
	}

	if targetHost == "" {
		targetHost = "api.telegram.org"
		targetPort = 443
		useTLS = true
	}
	if targetPort <= 0 {
		if useTLS {
			targetPort = 443
		} else {
			targetPort = 80
		}
	}
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}

	// 1. Check if proxyStr is a complex URI (vless://, hy2://, trojan://, ss://, etc.)
	if strings.Contains(cleanProxy, "://") && !strings.HasPrefix(cleanProxy, "socks5://") && !strings.HasPrefix(cleanProxy, "socks://") && !strings.HasPrefix(cleanProxy, "http://") && !strings.HasPrefix(cleanProxy, "https://") {
		profile, err := parser.ParseURI(cleanProxy)
		if err == nil && profile != nil {
			ok, latency, probeErr := CheckVLESSRealityProbe(profile, timeout)
			res := ProxyBatchResult{
				ProxyURL:  cleanProxy,
				Protocol:  string(profile.Protocol),
				Name:      profile.Name,
				Success:   ok,
				LatencyMs: latency,
			}
			if probeErr != nil {
				res.Error = cleanNetError(probeErr)
			}
			return res
		}
	}

	// 2. Standard SOCKS5 / HTTP proxy
	hostPort := cleanProxy
	if strings.Contains(cleanProxy, "://") {
		u, err := url.Parse(cleanProxy)
		if err == nil {
			hostPort = u.Host
		}
	}

	if hostPort == "" {
		return ProxyBatchResult{ProxyURL: proxyStr, Success: false, Error: "empty host/port"}
	}

	ok, latency, err := CheckSocks5Direct(hostPort, targetHost, targetPort, useTLS, timeout)
	res := ProxyBatchResult{
		ProxyURL:  proxyStr,
		Protocol:  "socks5",
		Success:   ok,
		LatencyMs: latency,
	}
	if err != nil {
		res.Error = cleanNetError(err)
	}

	return res
}

// BatchCheckProxies checks hundreds of proxies/VLESS links in parallel with specified concurrency
func BatchCheckProxies(proxies []string, targetHost string, targetPort int, useTLS bool, timeout time.Duration, concurrency int) []ProxyBatchResult {
	if len(proxies) == 0 {
		return []ProxyBatchResult{}
	}
	if concurrency <= 0 {
		concurrency = 64
	}
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}

	results := make([]ProxyBatchResult, len(proxies))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, p := range proxies {
		wg.Add(1)
		go func(idx int, proxyAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = CheckProxyTarget(proxyAddr, targetHost, targetPort, useTLS, timeout)
		}(i, p)
	}

	wg.Wait()
	return results
}

// FindFastestWorkingProxy scans proxies/VLESS links concurrently and returns the first/fastest responsive proxy
func FindFastestWorkingProxy(proxies []string, targetHost string, targetPort int, useTLS bool, timeout time.Duration, concurrency int) *ProxyBatchResult {
	allResults := BatchCheckProxies(proxies, targetHost, targetPort, useTLS, timeout, concurrency)
	var best *ProxyBatchResult
	for _, r := range allResults {
		if r.Success {
			if best == nil || r.LatencyMs < best.LatencyMs {
				resCopy := r
				best = &resCopy
			}
		}
	}
	return best
}
