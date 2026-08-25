package diagnostics

import (
	"io"
	"net"
	"testing"
	"time"
)

// startMockSocks5Server creates an in-memory mock SOCKS5 server for benchmarking & unit tests
func startMockSocks5Server(t *testing.T, delay time.Duration) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock socks5 server: %v", err)
	}

	stopChan := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopChan:
					return
				default:
					return
				}
			}
			go handleMockSocksConn(conn, delay)
		}
	}()

	return ln.Addr().String(), func() {
		close(stopChan)
		ln.Close()
	}
}

func handleMockSocksConn(conn net.Conn, delay time.Duration) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if delay > 0 {
		time.Sleep(delay)
	}

	// 1. Read greeting
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	// Reply: 0x05, 0x00 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Read connect request
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	// Read address
	switch hdr[3] {
	case 0x01: // IPv4
		addrBuf := make([]byte, 4+2)
		io.ReadFull(conn, addrBuf)
	case 0x03: // FQDN
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		fqdnBuf := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, fqdnBuf)
	}

	// Reply: Success (0x05, 0x00, 0x00, 0x01, 127.0.0.1, port)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return
	}

	// Read HTTP probe request
	httpReq := make([]byte, 64)
	n, _ := conn.Read(httpReq)
	if n > 0 {
		// Send HTTP 204 response
		httpResp := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
		conn.Write([]byte(httpResp))
	}
}

func TestCheckSocks5Direct(t *testing.T) {
	addr, cleanup := startMockSocks5Server(t, 5*time.Millisecond)
	defer cleanup()

	ok, latency, err := CheckSocks5Direct(addr, "cp.cloudflare.com", 80, false, 2*time.Second)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true, got ok=false")
	}
	if latency <= 0 {
		t.Fatalf("expected latency > 0, got %v", latency)
	}
	t.Logf("Single SOCKS5 check succeeded in %.2f ms", latency)
}

func TestBatchCheckProxiesSpeed(t *testing.T) {
	addr, cleanup := startMockSocks5Server(t, 2*time.Millisecond)
	defer cleanup()

	// Simulate a batch of 200 proxies
	totalProxies := 200
	proxies := make([]string, totalProxies)
	for i := 0; i < totalProxies; i++ {
		if i%10 == 0 {
			// Mix in mock working proxy
			proxies[i] = addr
		} else {
			// Mix in dead proxy (closed port)
			proxies[i] = "127.0.0.1:59999"
		}
	}

	start := time.Now()
	results := BatchCheckProxies(proxies, "cp.cloudflare.com", 80, false, 100*time.Millisecond, 64)
	elapsed := time.Since(start)

	workingCount := 0
	for _, r := range results {
		if r.Success {
			workingCount++
		}
	}

	t.Logf("Tested %d proxies in %v (concurrency=64), working=%d", totalProxies, elapsed, workingCount)
	if workingCount != 20 {
		t.Fatalf("expected 20 working proxies, got %d", workingCount)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("batch check took too long: %v (expected < 1s)", elapsed)
	}
}
