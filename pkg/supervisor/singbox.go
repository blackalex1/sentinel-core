package supervisor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CheckSingBoxStatus checks if Sing-box Clash API is responding.
func CheckSingBoxStatus(clashAddr string) bool {
	if clashAddr == "" {
		clashAddr = "127.0.0.1:9090"
	}
	resp, err := localHTTPClient.Get("http://" + clashAddr + "/connections")
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		return true
	}
	return false
}

// FetchSingBoxTraffic queries Sing-box Clash API /connections endpoint and calculates per-client stats.
func FetchSingBoxTraffic(clashAddr string) (map[string]ClientTraffic, error) {
	result := make(map[string]ClientTraffic)
	if clashAddr == "" {
		clashAddr = "127.0.0.1:9090"
	}

	url := fmt.Sprintf("http://%s/connections", clashAddr)
	resp, err := localHTTPClient.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return result, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	var data struct {
		Connections []struct {
			ID       string `json:"id"`
			Download int64  `json:"download"`
			Upload   int64  `json:"upload"`
			User     string `json:"user"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Metadata struct {
				User        string `json:"user"`
				InboundUser string `json:"inboundUser"`
				ClientUser  string `json:"clientUser"`
				Username    string `json:"username"`
				AuthUser    string `json:"auth_user"`
				Name        string `json:"name"`
				Email       string `json:"email"`
				Client      string `json:"client"`
				SourceIP    string `json:"sourceIP"`
				Source_IP   string `json:"source_ip"`
				ClientIP    string `json:"clientIP"`
				RemoteHost  string `json:"host"`
			} `json:"metadata"`
		} `json:"connections"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return result, err
	}

	ipSetByUser := make(map[string]map[string]bool)

	for _, conn := range data.Connections {
		email := conn.Metadata.User
		if email == "" {
			email = conn.Metadata.InboundUser
		}
		if email == "" {
			email = conn.Metadata.ClientUser
		}
		if email == "" {
			email = conn.Metadata.Username
		}
		if email == "" {
			email = conn.Metadata.AuthUser
		}
		if email == "" {
			email = conn.Metadata.Email
		}
		if email == "" {
			email = conn.Metadata.Name
		}
		if email == "" {
			email = conn.Metadata.Client
		}
		if email == "" {
			email = conn.User
		}
		if email == "" {
			email = conn.Username
		}
		if email == "" {
			email = conn.Email
		}
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}

		entry := result[email]
		entry.Email = email
		entry.DownBytes += conn.Download
		entry.UpBytes += conn.Upload
		entry.Connections++
		entry.Online = true

		srcIP := conn.Metadata.SourceIP
		if srcIP == "" {
			srcIP = conn.Metadata.Source_IP
		}
		if srcIP == "" {
			srcIP = conn.Metadata.ClientIP
		}
		srcIP = strings.TrimSpace(srcIP)

		if ipSetByUser[email] == nil {
			ipSetByUser[email] = make(map[string]bool)
		}
		if srcIP != "" {
			ipSetByUser[email][srcIP] = true
		}

		result[email] = entry
	}

	for email, ips := range ipSetByUser {
		entry := result[email]
		for ip := range ips {
			entry.ActiveIPs = append(entry.ActiveIPs, ip)
		}
		result[email] = entry
	}

	return result, nil
}

// CloseSingBoxConnections sends DELETE requests to Clash API for active connections of a specified user.
func CloseSingBoxConnections(clashAddr string, email string) error {
	if clashAddr == "" {
		clashAddr = "127.0.0.1:9090"
	}

	url := fmt.Sprintf("http://%s/connections", clashAddr)
	client := &http.Client{Timeout: 150 * time.Millisecond}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data struct {
		Connections []struct {
			ID       string `json:"id"`
			User     string `json:"user"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Metadata struct {
				User        string `json:"user"`
				InboundUser string `json:"inboundUser"`
				ClientUser  string `json:"clientUser"`
				Username    string `json:"username"`
				AuthUser    string `json:"auth_user"`
				Name        string `json:"name"`
				Email       string `json:"email"`
				Client      string `json:"client"`
			} `json:"metadata"`
		} `json:"connections"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	for _, conn := range data.Connections {
		cUser := conn.Metadata.User
		if cUser == "" {
			cUser = conn.Metadata.InboundUser
		}
		if cUser == "" {
			cUser = conn.Metadata.ClientUser
		}
		if cUser == "" {
			cUser = conn.Metadata.Username
		}
		if cUser == "" {
			cUser = conn.Metadata.AuthUser
		}
		if cUser == "" {
			cUser = conn.Metadata.Email
		}
		if cUser == "" {
			cUser = conn.Metadata.Name
		}
		if cUser == "" {
			cUser = conn.Metadata.Client
		}
		if cUser == "" {
			cUser = conn.User
		}
		if cUser == "" {
			cUser = conn.Username
		}
		if cUser == "" {
			cUser = conn.Email
		}
		if strings.EqualFold(strings.TrimSpace(cUser), email) {
			delURL := fmt.Sprintf("http://%s/connections/%s", clashAddr, conn.ID)
			delReq, err := http.NewRequest(http.MethodDelete, delURL, nil)
			if err == nil {
				delResp, err := client.Do(delReq)
				if err == nil {
					delResp.Body.Close()
				}
			}
		}
	}

	return nil
}
