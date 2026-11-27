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
		defer closeQuietly(resp.Body)
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
		DownloadTotal int64               `json:"downloadTotal"`
		UploadTotal   int64               `json:"uploadTotal"`
		Connections   []clashConnSnapshot `json:"connections"`
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

		email := extractSingBoxConnUser(conn)
		hasExplicitUser := (email != "")
		if email == "" {
			email = GetSessionTracker().ResolveSingBoxUser(conn.Metadata.SourceIP, conn.Metadata.SourcePort)
		}
		email = strings.TrimSpace(email)
		if email == "" && (conn.Metadata.SourceIP == "" || conn.Metadata.SourceIP == "127.0.0.1") {
			email = sbLastSeenUser[clashAddr]
		}
		deltaUp, deltaDown := updateSingBoxConnDelta(connID, conn.Upload, conn.Download)
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

		recordSingBoxUserTraffic(addrMap, email, deltaUp, deltaDown)
		if outboundTag := resolveSingBoxOutboundTag(conn); outboundTag != "" {
			recordSingBoxUserTraffic(addrMap, "outbound:"+outboundTag, deltaUp, deltaDown)
		}

		srcIP := strings.TrimSpace(firstNonEmpty(conn.Metadata.SourceIP, conn.Metadata.Source_IP, conn.Metadata.ClientIP))
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

	closedUsers := collectClosedSingBoxUsers(activeConnIDs)
	attributeClosedSingBoxTraffic(clashAddr, addrMap, closedUsers, data.UploadTotal, data.DownloadTotal, activeDeltasUp, activeDeltasDown)

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

type clashConnSnapshot struct {
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
}

func extractSingBoxConnUser(conn clashConnSnapshot) string {
	return firstNonEmpty(
		conn.Metadata.User,
		conn.Metadata.InboundUser,
		conn.Metadata.ClientUser,
		conn.Metadata.Username,
		conn.Metadata.AuthUser,
		conn.Metadata.Email,
		conn.Metadata.Name,
		conn.Metadata.Client,
		conn.Metadata.UUID,
		conn.User,
		conn.Username,
		conn.Email,
		conn.UUID,
	)
}

func updateSingBoxConnDelta(connID string, upload, download int64) (int64, int64) {
	prev := sbLastConnStats[connID]
	deltaUp := upload
	if upload >= prev[0] {
		deltaUp = upload - prev[0]
	}
	deltaDown := download
	if download >= prev[1] {
		deltaDown = download - prev[1]
	}
	sbLastConnStats[connID] = [2]int64{upload, download}
	return deltaUp, deltaDown
}

func recordSingBoxUserTraffic(addrMap map[string]*ClientTraffic, key string, deltaUp, deltaDown int64) {
	ct, exists := addrMap[key]
	if !exists {
		ct = &ClientTraffic{Email: key}
		addrMap[key] = ct
	}
	ct.UpBytes += deltaUp
	ct.DownBytes += deltaDown
}

func resolveSingBoxOutboundTag(conn clashConnSnapshot) string {
	outboundTag := conn.Metadata.Outbound
	if outboundTag == "" && len(conn.Chains) > 0 {
		outboundTag = conn.Chains[len(conn.Chains)-1]
	}
	if outboundTag == "" && len(conn.Metadata.Chains) > 0 {
		outboundTag = conn.Metadata.Chains[len(conn.Metadata.Chains)-1]
	}
	if outboundTag == "" || outboundTag == "direct" || outboundTag == "block" || outboundTag == "blocked" {
		return ""
	}
	return outboundTag
}

func collectClosedSingBoxUsers(activeConnIDs map[string]bool) []string {
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
	return closedUsers
}

func attributeClosedSingBoxTraffic(
	clashAddr string,
	addrMap map[string]*ClientTraffic,
	closedUsers []string,
	uploadTotal, downloadTotal, activeDeltasUp, activeDeltasDown int64,
) {
	if downloadTotal <= 0 && uploadTotal <= 0 {
		return
	}
	prevTotals := sbLastTotals[clashAddr]
	deltaTotalUp := uploadTotal
	if uploadTotal >= prevTotals[0] {
		deltaTotalUp = uploadTotal - prevTotals[0]
	}
	deltaTotalDown := downloadTotal
	if downloadTotal >= prevTotals[1] {
		deltaTotalDown = downloadTotal - prevTotals[1]
	}
	sbLastTotals[clashAddr] = [2]int64{uploadTotal, downloadTotal}

	unaccountedUp := deltaTotalUp - activeDeltasUp
	unaccountedDown := deltaTotalDown - activeDeltasDown
	if unaccountedUp <= 0 && unaccountedDown <= 0 {
		return
	}

	targetEmails := resolveClosedTrafficTargets(clashAddr, addrMap, closedUsers)
	if len(targetEmails) == 0 {
		return
	}

	perUp := unaccountedUp / int64(len(targetEmails))
	remUp := unaccountedUp % int64(len(targetEmails))
	perDown := unaccountedDown / int64(len(targetEmails))
	remDown := unaccountedDown % int64(len(targetEmails))

	for i, targetEmail := range targetEmails {
		addUp := perUp
		if i == 0 {
			addUp += remUp
		}
		addDown := perDown
		if i == 0 {
			addDown += remDown
		}
		recordSingBoxUserTraffic(addrMap, targetEmail, addUp, addDown)
	}
}

func resolveClosedTrafficTargets(clashAddr string, addrMap map[string]*ClientTraffic, closedUsers []string) []string {
	if len(closedUsers) > 0 {
		return closedUsers
	}
	if lastEmail := sbLastSeenUser[clashAddr]; lastEmail != "" {
		return []string{lastEmail}
	}
	if len(addrMap) == 1 {
		for em := range addrMap {
			return []string{em}
		}
	}
	if resolved := GetSessionTracker().ResolveSingBoxUser("", ""); resolved != "" {
		return []string{resolved}
	}
	return nil
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
	defer closeQuietly(resp.Body)

	var data struct {
		Connections []clashConnSnapshot `json:"connections"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	for _, conn := range data.Connections {
		cUser := extractSingBoxConnUser(conn)
		if strings.EqualFold(strings.TrimSpace(cUser), email) {
			delURL := fmt.Sprintf("http://%s/connections/%s", clashAddr, url.PathEscape(conn.ID))
			delReq, err := http.NewRequest(http.MethodDelete, delURL, nil)
			if err == nil {
				delResp, err := client.Do(delReq)
				if err == nil {
					closeQuietly(delResp.Body)
				}
			}
		}
	}

	return nil
}
