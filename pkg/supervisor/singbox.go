package supervisor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	sbTrafficMu      sync.RWMutex
	sbUserCumulative = make(map[string]map[string]*ClientTraffic) // clashAddr -> email -> *ClientTraffic
	sbLastConnStats  = make(map[string][2]int64)                  // connID -> [upload, download]
	sbConnUser       = make(map[string]string)                   // connID -> email
	sbLastTotals     = make(map[string][2]int64)                  // clashAddr -> [uploadTotal, downloadTotal]
	sbLastSeenUser   = make(map[string]string)                   // clashAddr -> lastActiveEmail
)

// ResetSingBoxCumulativeTraffic clears in-memory cumulative traffic for Sing-box.
func ResetSingBoxCumulativeTraffic() {
	sbTrafficMu.Lock()
	defer sbTrafficMu.Unlock()
	sbUserCumulative = make(map[string]map[string]*ClientTraffic)
	sbLastConnStats = make(map[string][2]int64)
	sbConnUser = make(map[string]string)
	sbLastTotals = make(map[string][2]int64)
	sbLastSeenUser = make(map[string]string)
}

// CheckSingBoxStatus checks if Sing-box Clash API is responding.
func CheckSingBoxStatus(clashAddr string) bool {
	if clashAddr == "" {
		clashAddr = "127.0.0.1:9090"
	}
	resp, err := localHTTPClient.Get("http://" + clashAddr + "/connections")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
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
	if err == nil {
		defer resp.Body.Close()
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		sbTrafficMu.RLock()
		if addrMap, exists := sbUserCumulative[clashAddr]; exists {
			for email, ct := range addrMap {
				result[email] = ClientTraffic{
					Email:     email,
					DownBytes: ct.DownBytes,
					UpBytes:   ct.UpBytes,
					Online:    false,
				}
			}
		}
		sbTrafficMu.RUnlock()
		return result, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	var data struct {
		DownloadTotal int64 `json:"downloadTotal"`
		UploadTotal   int64 `json:"uploadTotal"`
		Connections []struct {
			ID       string   `json:"id"`
			Download int64    `json:"download"`
			Upload   int64    `json:"upload"`
			User     string   `json:"user"`
			Username string   `json:"username"`
			Email    string   `json:"email"`
			UUID     string   `json:"uuid"`
			Chains   []string `json:"chains"`
			Metadata struct {
				User        string   `json:"user"`
				InboundUser string   `json:"inboundUser"`
				ClientUser  string   `json:"clientUser"`
				Username    string   `json:"username"`
				AuthUser    string   `json:"auth_user"`
				Name        string   `json:"name"`
				Email       string   `json:"email"`
				Client      string   `json:"client"`
				UUID        string   `json:"uuid"`
				Outbound    string   `json:"outbound"`
				Chains      []string `json:"chains"`
				SourceIP    string   `json:"sourceIP"`
				SourcePort  string   `json:"sourcePort"`
				Source_IP   string   `json:"source_ip"`
				ClientIP    string   `json:"clientIP"`
				RemoteHost  string   `json:"host"`
			} `json:"metadata"`
		} `json:"connections"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return result, err
	}

	ipSetByUser := make(map[string]map[string]bool)
	liveUsers := make(map[string]int)
	activeConnIDs := make(map[string]bool)

	sbTrafficMu.Lock()
	addrMap, exists := sbUserCumulative[clashAddr]
	if !exists {
		addrMap = make(map[string]*ClientTraffic)
		sbUserCumulative[clashAddr] = addrMap
	}

	var activeDeltasUp, activeDeltasDown int64

	for _, conn := range data.Connections {
		connID := conn.ID
		if connID != "" {
			activeConnIDs[connID] = true
		}

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
			email = conn.Metadata.UUID
		}
		if email == "" {
			email = conn.User
		}
		if email == "" {
			email = conn.Username
		}
		if email == "" {
			email = conn.UUID
		}
		hasExplicitUser := (email != "")
		if email == "" {
			email = GetSessionTracker().ResolveSingBoxUser(conn.Metadata.SourceIP, conn.Metadata.SourcePort)
		}
		email = strings.TrimSpace(email)
		if email == "" && (conn.Metadata.SourceIP == "" || conn.Metadata.SourceIP == "127.0.0.1") {
			email = sbLastSeenUser[clashAddr]
		}
		prev := sbLastConnStats[connID]
		prevUp, prevDown := prev[0], prev[1]

		var deltaUp, deltaDown int64
		if conn.Upload >= prevUp {
			deltaUp = conn.Upload - prevUp
		} else {
			deltaUp = conn.Upload
		}
		if conn.Download >= prevDown {
			deltaDown = conn.Download - prevDown
		} else {
			deltaDown = conn.Download
		}

		sbLastConnStats[connID] = [2]int64{conn.Upload, conn.Download}
		activeDeltasUp += deltaUp
		activeDeltasDown += deltaDown

		if email == "" {
			continue
		}

		liveUsers[email]++
		sbLastSeenUser[clashAddr] = email
		if connID != "" {
			sbConnUser[connID] = email
		}

		ct, ctExists := addrMap[email]
		if !ctExists {
			ct = &ClientTraffic{Email: email}
			addrMap[email] = ct
		}
		ct.UpBytes += deltaUp
		ct.DownBytes += deltaDown

		// Attribute traffic to specific outbound / fallback tag if present
		outboundTag := conn.Metadata.Outbound
		if outboundTag == "" && len(conn.Chains) > 0 {
			outboundTag = conn.Chains[len(conn.Chains)-1]
		}
		if outboundTag == "" && len(conn.Metadata.Chains) > 0 {
			outboundTag = conn.Metadata.Chains[len(conn.Metadata.Chains)-1]
		}
		if outboundTag != "" && outboundTag != "direct" && outboundTag != "block" && outboundTag != "blocked" {
			outboundKey := "outbound:" + outboundTag
			obCt, obExists := addrMap[outboundKey]
			if !obExists {
				obCt = &ClientTraffic{Email: outboundKey}
				addrMap[outboundKey] = obCt
			}
			obCt.UpBytes += deltaUp
			obCt.DownBytes += deltaDown
		}

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
			if srcIP != "127.0.0.1" && srcIP != "::1" && hasExplicitUser {
				GetSessionTracker().RegisterExternalConnect("sing-box", email, srcIP)
			}
		}
	}

	// Detect connections that closed during this polling interval
	var closedUsers []string
	for cID, prevEmail := range sbConnUser {
		if !activeConnIDs[cID] {
			if prevEmail != "" && !containsString(closedUsers, prevEmail) {
				closedUsers = append(closedUsers, prevEmail)
			}
			delete(sbConnUser, cID)
			delete(sbLastConnStats, cID)
		}
	}

	// Calculate closed connections delta from DownloadTotal / UploadTotal
	if data.DownloadTotal > 0 || data.UploadTotal > 0 {
		prevTotals := sbLastTotals[clashAddr]
		prevUpTotal, prevDownTotal := prevTotals[0], prevTotals[1]

		var deltaTotalUp, deltaTotalDown int64
		if data.UploadTotal >= prevUpTotal {
			deltaTotalUp = data.UploadTotal - prevUpTotal
		} else {
			deltaTotalUp = data.UploadTotal
		}
		if data.DownloadTotal >= prevDownTotal {
			deltaTotalDown = data.DownloadTotal - prevDownTotal
		} else {
			deltaTotalDown = data.DownloadTotal
		}
		sbLastTotals[clashAddr] = [2]int64{data.UploadTotal, data.DownloadTotal}

		unaccountedUp := deltaTotalUp - activeDeltasUp
		unaccountedDown := deltaTotalDown - activeDeltasDown

		if unaccountedUp > 0 || unaccountedDown > 0 {
			var targetEmails []string
			if len(closedUsers) > 0 {
				targetEmails = closedUsers
			} else if lastEmail := sbLastSeenUser[clashAddr]; lastEmail != "" {
				targetEmails = []string{lastEmail}
			} else if len(addrMap) == 1 {
				for em := range addrMap {
					targetEmails = []string{em}
					break
				}
			} else if resolved := GetSessionTracker().ResolveSingBoxUser("", ""); resolved != "" {
				targetEmails = []string{resolved}
			}

			if len(targetEmails) > 0 {
				perUp := unaccountedUp / int64(len(targetEmails))
				remUp := unaccountedUp % int64(len(targetEmails))
				perDown := unaccountedDown / int64(len(targetEmails))
				remDown := unaccountedDown % int64(len(targetEmails))

				for i, targetEmail := range targetEmails {
					ct, ctExists := addrMap[targetEmail]
					if !ctExists {
						ct = &ClientTraffic{Email: targetEmail}
						addrMap[targetEmail] = ct
					}
					addUp := perUp
					if i == 0 {
						addUp += remUp
					}
					addDown := perDown
					if i == 0 {
						addDown += remDown
					}
					ct.UpBytes += addUp
					ct.DownBytes += addDown
				}
			}
		}
	}

	// Clean up stale closed connection IDs from memory
	for cID := range sbLastConnStats {
		if !activeConnIDs[cID] {
			delete(sbLastConnStats, cID)
		}
	}

	// Snapshot all known Sing-box users (cumulative + live status)
	for email, ct := range addrMap {
		connCount := liveUsers[email]
		result[email] = ClientTraffic{
			Email:       email,
			DownBytes:   ct.DownBytes,
			UpBytes:     ct.UpBytes,
			Connections: connCount,
			Online:      connCount > 0,
		}
	}
	sbTrafficMu.Unlock()

	for email, ips := range ipSetByUser {
		entry := result[email]
		for ip := range ips {
			if !containsString(entry.ActiveIPs, ip) {
				entry.ActiveIPs = append(entry.ActiveIPs, ip)
			}
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

	apiURL := fmt.Sprintf("http://%s/connections", clashAddr)
	client := &http.Client{Timeout: 150 * time.Millisecond}

	resp, err := client.Get(apiURL)
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
			delURL := fmt.Sprintf("http://%s/connections/%s", clashAddr, url.PathEscape(conn.ID))
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
