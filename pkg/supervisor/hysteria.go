package supervisor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// CheckHysteriaStatus checks if Hysteria 2 Admin API is responding on the given port.
func CheckHysteriaStatus(adminPort int) bool {
	if adminPort <= 0 {
		return false
	}
	resp, err := localHTTPClient.Get(fmt.Sprintf("http://127.0.0.1:%d/traffic", adminPort))
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		return true
	}
	return false
}

var (
	hyTrafficMu         sync.RWMutex
	hyCumulativeTraffic = make(map[int]map[string]*ClientTraffic)
)

// ResetHysteriaCumulativeTraffic clears the in-memory cumulative traffic map.
func ResetHysteriaCumulativeTraffic() {
	hyTrafficMu.Lock()
	defer hyTrafficMu.Unlock()
	hyCumulativeTraffic = make(map[int]map[string]*ClientTraffic)
}

// FetchHysteriaTraffic queries a Hysteria 2 admin API endpoint (/traffic and /online).
func FetchHysteriaTraffic(adminPort int) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)
	if adminPort <= 0 {
		return result, nil
	}

	// 1. Fetch /traffic (Hysteria resets its internal counters on read, so we accumulate them per port)
	trafficURL := fmt.Sprintf("http://127.0.0.1:%d/traffic", adminPort)
	resp, err := localHTTPClient.Get(trafficURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var rawTraffic map[string]struct {
			Tx int64 `json:"tx"`
			Rx int64 `json:"rx"`
		}
		if err := json.Unmarshal(body, &rawTraffic); err == nil && len(rawTraffic) > 0 {
			hyTrafficMu.Lock()
			portMap, exists := hyCumulativeTraffic[adminPort]
			if !exists {
				portMap = make(map[string]*ClientTraffic)
				hyCumulativeTraffic[adminPort] = portMap
			}
			for email, t := range rawTraffic {
				ct, exists := portMap[email]
				if !exists {
					ct = &ClientTraffic{Email: email}
					portMap[email] = ct
				}
				ct.DownBytes += t.Tx
				ct.UpBytes += t.Rx
			}
			hyTrafficMu.Unlock()
		}
	}

	// 2. Fetch /online
	onlineURL := fmt.Sprintf("http://127.0.0.1:%d/online", adminPort)
	rawOnline := make(map[string]int)
	respOnline, err := localHTTPClient.Get(onlineURL)
	if err == nil && respOnline.StatusCode == http.StatusOK {
		defer respOnline.Body.Close()
		body, _ := io.ReadAll(respOnline.Body)
		_ = json.Unmarshal(body, &rawOnline)
	}

	// Build result snapshot merging cumulative bytes with live online status
	hyTrafficMu.RLock()
	if portMap, exists := hyCumulativeTraffic[adminPort]; exists {
		for email, ct := range portMap {
			connCount := rawOnline[email]
			result[email] = ClientTraffic{
				Email:       email,
				DownBytes:   ct.DownBytes,
				UpBytes:     ct.UpBytes,
				Connections: connCount,
				Online:      connCount > 0,
			}
		}
	}
	hyTrafficMu.RUnlock()

	for email, count := range rawOnline {
		if _, exists := result[email]; !exists {
			result[email] = ClientTraffic{
				Email:       email,
				DownBytes:   0,
				UpBytes:     0,
				Connections: count,
				Online:      count > 0,
			}
		}
	}

	return result, nil
}

// KickHysteriaClient sends a kick request to Hysteria 2 Admin API (/kick).
func KickHysteriaClient(adminPort int, email string) error {
	if adminPort <= 0 {
		return fmt.Errorf("invalid admin port: %d", adminPort)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/kick", adminPort)
	payload, _ := json.Marshal([]string{email})

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 150 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hysteria kick failed with status: %d", resp.StatusCode)
	}

	return nil
}
