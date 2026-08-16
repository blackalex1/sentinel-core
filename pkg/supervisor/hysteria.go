package supervisor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// FetchHysteriaTraffic queries a Hysteria 2 admin API endpoint (/traffic and /online).
func FetchHysteriaTraffic(adminPort int) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)
	if adminPort <= 0 {
		return result, nil
	}

	// 1. Fetch /traffic
	trafficURL := fmt.Sprintf("http://127.0.0.1:%d/traffic", adminPort)
	resp, err := localHTTPClient.Get(trafficURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var rawTraffic map[string]struct {
			Tx int64 `json:"tx"`
			Rx int64 `json:"rx"`
		}
		if err := json.Unmarshal(body, &rawTraffic); err == nil {
			for email, t := range rawTraffic {
				result[email] = ClientTraffic{
					Email:     email,
					DownBytes: t.Tx,
					UpBytes:   t.Rx,
					Online:    false,
				}
			}
		}
	}

	// 2. Fetch /online
	onlineURL := fmt.Sprintf("http://127.0.0.1:%d/online", adminPort)
	respOnline, err := localHTTPClient.Get(onlineURL)
	if err == nil && respOnline.StatusCode == http.StatusOK {
		defer respOnline.Body.Close()
		body, _ := io.ReadAll(respOnline.Body)
		var rawOnline map[string]int
		if err := json.Unmarshal(body, &rawOnline); err == nil {
			for email, count := range rawOnline {
				entry := result[email]
				entry.Email = email
				entry.Connections = count
				entry.Online = count > 0
				result[email] = entry
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
