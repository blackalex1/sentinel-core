package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLogSearchXrayAndSingbox(t *testing.T) {
	nowStr := time.Now().Format("2006/01/02 15:04:05")
	lines := []string{
		fmt.Sprintf("%s [info] 192.168.1.100:54321 accepted tcp:203.0.113.193:22 [VLESS-TCP >> direct] email: attacker@xray.com", nowStr),
		fmt.Sprintf("%s [info] 10.0.0.5:12345 accepted tcp:[203.0.113.193]:22 email: bad_user@domain.com", nowStr),
		fmt.Sprintf("%s [info] inbound/vless[inbound-8]: [test_client_alpha] inbound connection to 198.51.100.22:22", nowStr),
	}

	// 1. Match attacker@xray.com
	email1, ip1, tag1 := FindEmailAndIPInXrayLog(lines[:1], "", "203.0.113.193", 22, 300)
	if email1 != "attacker@xray.com" || ip1 != "192.168.1.100" || tag1 != "VLESS-TCP >> direct" {
		t.Errorf("unexpected xray search result: email=%q, ip=%q, tag=%q", email1, ip1, tag1)
	}

	// 2. Match bracketed IP
	email2, _, _ := FindEmailAndIPInXrayLog(lines[1:2], "", "203.0.113.193", 22, 300)
	if email2 != "bad_user@domain.com" {
		t.Errorf("unexpected bracketed ip result: %q", email2)
	}

	// 4. Test False-Positive Prevention: searching for a different destination IP MUST NOT match
	email4, _, _ := FindEmailAndIPInXrayLog(lines, "", "198.51.100.137", 22, 300)
	if email4 != "" {
		t.Errorf("expected empty email for non-matching dstIP, got %q", email4)
	}

	// 5. Test domain vs IP separation: user accessing telegram on port 443 must not match attack to another IP on 443
	tgLines := []string{
		fmt.Sprintf("%s [info] inbound/vless[inbound-8]: [test_user_phone] inbound connection to api.telegram.org:443", nowStr),
		fmt.Sprintf("%s [info] 192.168.1.50:50123 accepted tcp:api.telegram.org:443 [VLESS-TCP >> direct] email: innocent_user", nowStr),
	}
	emailTg, _, _ := FindEmailAndIPInXrayLog(tgLines, "", "198.51.100.137", 443, 300)
	if emailTg != "" {
		t.Errorf("expected empty email when searching for 198.51.100.137, but matched telegram user: %q", emailTg)
	}
}

func TestLogSearchHysteria(t *testing.T) {
	nowStr := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	lines := []string{
		fmt.Sprintf(`{"time":"%s","id":"tunnel_user","reqAddr":"203.0.113.193:22"}`, nowStr),
		fmt.Sprintf(`{"time":"%s","auth":"alice@hy2.com","addr":"192.168.1.88:45678"}`, nowStr),
		fmt.Sprintf(`{"time":"%s","id":"innocent_user","reqAddr":"api.telegram.org:443"}`, nowStr),
	}

	// 1. Match Hysteria user
	email1 := FindEmailInHysteriaLog(lines, "203.0.113.193", 22, 300)
	if email1 != "tunnel_user" {
		t.Errorf("expected tunnel_user, got %q", email1)
	}

	// 2. Find client IP for email
	ip := FindClientIPForEmailInHysteriaLog(lines, "alice@hy2.com", 300)
	if ip != "192.168.1.88" {
		t.Errorf("expected 192.168.1.88, got %q", ip)
	}

	// 3. Prevent false match for non-matching dst IP on port 443
	emailUnmatched := FindEmailInHysteriaLog(lines, "198.51.100.137", 443, 300)
	if emailUnmatched != "" {
		t.Errorf("expected empty email for non-matching dst IP on port 443, got %q", emailUnmatched)
	}

	// 4. Text-based Hysteria logs
	textLines := []string{
		fmt.Sprintf("%s [info] client connected: auth=hysteria_text_user@victim.org, 203.0.113.5:44321", nowStr),
		fmt.Sprintf("%s [debug] connection: hysteria_text_user@victim.org (203.0.113.5:44321) -> 198.51.100.42:22", nowStr),
	}
	emailText := FindEmailInHysteriaLog(textLines, "198.51.100.42", 22, 300)
	if emailText != "hysteria_text_user@victim.org" {
		t.Errorf("expected hysteria_text_user@victim.org, got %q", emailText)
	}
	ipText := FindClientIPForEmailInHysteriaLog(textLines, "hysteria_text_user@victim.org", 300)
	if ipText != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %q", ipText)
	}
}

func TestCascadedTwoPanelRoutingAndAttribution(t *testing.T) {
	now := time.Now()
	nowStr := now.Format("2006/01/02 15:04:05")
	nowISO := now.UTC().Format("2006-01-02T15:04:05Z")
	tzPrefix := now.Format("-0700")

	// Panel 1 (Upstream LXC 104) logs:
	panel1Logs := []string{
		fmt.Sprintf("%s %s INFO [1001 0ms] inbound/vless[vless-phone-in]: inbound connection from 192.168.1.50:41234", tzPrefix, nowStr),
		fmt.Sprintf("%s %s INFO [1001 10ms] inbound/vless[vless-phone-in]: [cascaded_user@test.lan] inbound connection to 203.0.113.195:22", tzPrefix, nowStr),
		fmt.Sprintf("%s [info] 192.168.1.50:41234 accepted tcp:203.0.113.195:22 [vless-phone-in >> out-vps-test] email: cascaded_user@test.lan", nowStr),
	}

	// Panel 2 (Exit VPS 198.51.100.14) logs:
	panel2Logs := []string{
		// Transit tunnel receiving cascaded traffic from Panel 1
		fmt.Sprintf(`{"time":"%s","id":"vps_transit_tunnel","reqAddr":"203.0.113.195:22"}`, nowISO),
		fmt.Sprintf(`{"time":"%s","auth":"vps_transit_tunnel","addr":"192.168.1.104:55123"}`, nowISO),
		// Direct client connected directly to Panel 2
		fmt.Sprintf("%s [info] 192.0.2.45:41235 accepted tcp:198.51.100.88:3389 [xray-direct-in >> direct] email: direct_user@test.lan", nowStr),
		// Innocent client browsing Telegram
		fmt.Sprintf(`{"time":"%s","id":"innocent_user@test.lan","reqAddr":"api.telegram.org:443"}`, nowISO),
	}

	// 1. Cascaded attack on 203.0.113.195:22 -> true culprit must be found on Panel 1
	p1Email, p1IP, p1Tag := FindEmailAndIPInXrayLog(panel1Logs, "", "203.0.113.195", 22, 45)
	if p1Email != "cascaded_user@test.lan" {
		t.Fatalf("expected Panel 1 culprit 'cascaded_user@test.lan', got %q", p1Email)
	}
	if p1IP != "192.168.1.50" {
		t.Errorf("expected Panel 1 client IP '192.168.1.50', got %q", p1IP)
	}
	if p1Tag == "" {
		t.Errorf("expected non-empty inbound tag on Panel 1")
	}

	// On Panel 2, transit account is identified
	p2TunnelUser := FindEmailInHysteriaLog(panel2Logs, "203.0.113.195", 22, 45)
	if p2TunnelUser != "vps_transit_tunnel" {
		t.Fatalf("expected Panel 2 transit user 'vps_transit_tunnel', got %q", p2TunnelUser)
	}

	// 2. Direct attack on 198.51.100.88:3389 -> direct client must be found on Panel 2
	p2DirectEmail, p2DirectIP, _ := FindEmailAndIPInXrayLog(panel2Logs, "", "198.51.100.88", 3389, 45)
	if p2DirectEmail != "direct_user@test.lan" {
		t.Fatalf("expected Panel 2 direct client 'direct_user@test.lan', got %q", p2DirectEmail)
	}
	if p2DirectIP != "192.0.2.45" {
		t.Errorf("expected Panel 2 direct client IP '192.0.2.45', got %q", p2DirectIP)
	}

	// Panel 1 must NOT match the direct attack
	p1DirectCheck, _, _ := FindEmailAndIPInXrayLog(panel1Logs, "", "198.51.100.88", 3389, 45)
	if p1DirectCheck != "" {
		t.Errorf("expected empty email on Panel 1 for direct VPS attack, got %q", p1DirectCheck)
	}

	// 3. Telegram user on 443 must NOT match attack to 198.51.100.137:443
	innocentCheck := FindEmailInHysteriaLog(panel2Logs, "198.51.100.137", 443, 45)
	if innocentCheck != "" {
		t.Errorf("expected empty email for Telegram user on non-matching IP, got %q", innocentCheck)
	}
}

func TestLogSearch_IPv6_RFC3849(t *testing.T) {
	now := time.Now()
	nowStr := now.Format("2006/01/02 15:04:05")
	nowISO := now.UTC().Format("2006-01-02T15:04:05Z")
	tzPrefix := now.Format("-0700")

	// 1. Xray with IPv6 client and destination
	xrayLines := []string{
		fmt.Sprintf("%s [info] [2001:db8:cafe::42]:54321 accepted tcp:[2001:db8:1000::1]:22 [VLESS-TCP >> direct] email: ipv6_attacker@test.example", nowStr),
	}
	email1, ip1, tag1 := FindEmailAndIPInXrayLog(xrayLines, "", "2001:db8:1000::1", 22, 300)
	if email1 != "ipv6_attacker@test.example" || ip1 != "2001:db8:cafe::42" {
		t.Errorf("unexpected xray IPv6 search result: email=%q, ip=%q, tag=%q", email1, ip1, tag1)
	}

	// 2. Sing-box two-line format with IPv6
	sbLines := []string{
		fmt.Sprintf("%s %s INFO [2001 0ms] inbound/vless[vless-in]: inbound connection from [2001:db8:cafe::42]:54321", tzPrefix, nowStr),
		fmt.Sprintf("%s %s INFO [2001 5ms] inbound/vless[vless-in]: [sb_ipv6_user@test.example] inbound connection to [2001:db8:1000::1]:22", tzPrefix, nowStr),
	}
	email2, ip2, _ := FindEmailAndIPInXrayLog(sbLines, "", "2001:db8:1000::1", 22, 300)
	if email2 != "sb_ipv6_user@test.example" || ip2 != "2001:db8:cafe::42" {
		t.Errorf("unexpected sing-box IPv6 result: email=%q, ip=%q", email2, ip2)
	}

	// 3. Hysteria 2 log with IPv6
	hyLines := []string{
		fmt.Sprintf(`{"time":"%s","id":"hy2_ipv6_user@test.example","reqAddr":"[2001:db8:1000::1]:22"}`, nowISO),
		fmt.Sprintf(`{"time":"%s","auth":"hy2_ipv6_user@test.example","addr":"[2001:db8:cafe::42]:53124"}`, nowISO),
	}
	email3 := FindEmailInHysteriaLog(hyLines, "2001:db8:1000::1", 22, 300)
	if email3 != "hy2_ipv6_user@test.example" {
		t.Errorf("expected hy2_ipv6_user@test.example, got %q", email3)
	}

	clientIP := FindClientIPForEmailInHysteriaLog(hyLines, "hy2_ipv6_user@test.example", 300)
	if clientIP != "2001:db8:cafe::42" {
		t.Errorf("expected full IPv6 client IP 2001:db8:cafe::42, got %q", clientIP)
	}
}

func TestCascadedThreeServerRoutingAndAttribution_IPv4_to_IPv6(t *testing.T) {
	now := time.Now()
	nowStr := now.Format("2006/01/02 15:04:05")
	nowISO := now.UTC().Format("2006-01-02T15:04:05Z")
	tzPrefix := now.Format("-0700")

	// Target sensitive service (RFC 3849 IPv6 test target on SSH port 22)
	targetIPv6 := "2001:db8:bad:c0de::1"
	targetPort := 22

	// =========================================================================
	// SERVER 1: Gateway / Home Node (Client connects via IPv4, routes out via IPv4)
	// Real client: attacker_v4_v6@corp.lan from RFC 5737 IP 198.51.100.42
	// Outbound tunnel to Server 2 over IPv4: 198.51.100.20:443
	// =========================================================================
	server1Logs := []string{
		fmt.Sprintf("%s %s INFO [10001 0ms] inbound/vless[vless-phone-in]: inbound connection from 198.51.100.42:51234", tzPrefix, nowStr),
		fmt.Sprintf("%s %s INFO [10001 5ms] inbound/vless[vless-phone-in]: [attacker_v4_v6@corp.lan] inbound connection to [%s]:%d", tzPrefix, nowStr, targetIPv6, targetPort),
		fmt.Sprintf("%s [info] 198.51.100.42:51234 accepted tcp:[%s]:%d [vless-phone-in >> out-server2-v4] email: attacker_v4_v6@corp.lan", nowStr, targetIPv6, targetPort),
	}

	// =========================================================================
	// SERVER 2: Intermediate Relay / Transit Hop
	// Inbound: IPv4 connection from Server 1 (198.51.100.10:45123), user: server1_transit_tunnel@corp.lan
	// Outbound: IPv6 tunnel to Server 3 ([2001:db8:2000::3]:8443)
	// =========================================================================
	server2Logs := []string{
		fmt.Sprintf(`{"time":"%s","auth":"server1_transit_tunnel@corp.lan","addr":"198.51.100.10:45123"}`, nowISO),
		fmt.Sprintf(`{"time":"%s","id":"server1_transit_tunnel@corp.lan","reqAddr":"[%s]:%d"}`, nowISO, targetIPv6, targetPort),
		fmt.Sprintf("%s [info] 198.51.100.10:45123 accepted tcp:[%s]:%d [v4-relay-in >> out-server3-v6] email: server1_transit_tunnel@corp.lan", nowStr, targetIPv6, targetPort),
	}

	// =========================================================================
	// SERVER 3: Exit VPS (Receives traffic over IPv6, exits to sensitive target)
	// Inbound: IPv6 connection from Server 2 ([2001:db8:2000::2]:52341), user: server2_transit_tunnel@corp.lan
	// Outbound: Direct connection to sensitive target [2001:db8:bad:c0de::1]:22
	// Also has innocent user browsing HTTPS
	// =========================================================================
	server3Logs := []string{
		fmt.Sprintf(`{"time":"%s","auth":"server2_transit_tunnel@corp.lan","addr":"[2001:db8:2000::2]:52341"}`, nowISO),
		fmt.Sprintf(`{"time":"%s","id":"server2_transit_tunnel@corp.lan","reqAddr":"[%s]:%d"}`, nowISO, targetIPv6, targetPort),
		fmt.Sprintf("[TCP] [2001:db8:2000::2]:52341 -> [%s]:%d (user: server2_transit_tunnel@corp.lan)", targetIPv6, targetPort),
		fmt.Sprintf("%s [info] [2001:db8:2000::2]:52341 accepted tcp:[%s]:%d [v6-exit-in >> direct] email: server2_transit_tunnel@corp.lan", nowStr, targetIPv6, targetPort),
		// Innocent client on Server 3
		fmt.Sprintf(`{"time":"%s","id":"innocent_user@corp.lan","reqAddr":"[2001:db8:good::1]:443"}`, nowISO),
	}

	// -------------------------------------------------------------------------
	// STEP 1: Investigation on SERVER 3 (Incident detection point)
	// -------------------------------------------------------------------------
	s3EmailJSON := FindEmailInHysteriaLog(server3Logs, targetIPv6, targetPort, 45)
	if s3EmailJSON != "server2_transit_tunnel@corp.lan" {
		t.Fatalf("Server 3 Hysteria investigation failed, expected 'server2_transit_tunnel@corp.lan', got %q", s3EmailJSON)
	}
	s3IP := FindClientIPForEmailInHysteriaLog(server3Logs, s3EmailJSON, 45)
	if s3IP != "2001:db8:2000::2" {
		t.Errorf("Server 3 client IP resolution failed, expected '2001:db8:2000::2', got %q", s3IP)
	}

	// Also verify Xray search on Server 3
	s3EmailXray, s3IPXray, _ := FindEmailAndIPInXrayLog(server3Logs, "", targetIPv6, targetPort, 45)
	if s3EmailXray != "server2_transit_tunnel@corp.lan" {
		t.Fatalf("Server 3 Xray investigation failed, expected 'server2_transit_tunnel@corp.lan', got %q", s3EmailXray)
	}
	if s3IPXray != "2001:db8:2000::2" {
		t.Errorf("Server 3 Xray client IP resolution failed, expected '2001:db8:2000::2', got %q", s3IPXray)
	}

	// -------------------------------------------------------------------------
	// STEP 2: Investigation on SERVER 2 (Intermediate relay node)
	// Server 3 found tunnel from Server 2 -> Now investigate Server 2 for the same target!
	// -------------------------------------------------------------------------
	s2EmailHys := FindEmailInHysteriaLog(server2Logs, targetIPv6, targetPort, 45)
	if s2EmailHys != "server1_transit_tunnel@corp.lan" {
		t.Fatalf("Server 2 Hysteria investigation failed, expected 'server1_transit_tunnel@corp.lan', got %q", s2EmailHys)
	}
	s2IPHys := FindClientIPForEmailInHysteriaLog(server2Logs, s2EmailHys, 45)
	if s2IPHys != "198.51.100.10" {
		t.Errorf("Server 2 client IP resolution failed, expected '198.51.100.10', got %q", s2IPHys)
	}

	s2EmailXray, s2IPXray, _ := FindEmailAndIPInXrayLog(server2Logs, "", targetIPv6, targetPort, 45)
	if s2EmailXray != "server1_transit_tunnel@corp.lan" {
		t.Fatalf("Server 2 Xray investigation failed, expected 'server1_transit_tunnel@corp.lan', got %q", s2EmailXray)
	}
	if s2IPXray != "198.51.100.10" {
		t.Errorf("Server 2 Xray client IP resolution failed, expected '198.51.100.10', got %q", s2IPXray)
	}

	// -------------------------------------------------------------------------
	// STEP 3: Investigation on SERVER 1 (Origin Gateway)
	// Server 2 found tunnel from Server 1 -> Now investigate Server 1 for the same target!
	// Must uncover the TRUE original client attacker_v4_v6@corp.lan!
	// -------------------------------------------------------------------------
	s1Email, s1IP, s1Tag := FindEmailAndIPInXrayLog(server1Logs, "", targetIPv6, targetPort, 45)
	if s1Email != "attacker_v4_v6@corp.lan" {
		t.Fatalf("Server 1 origin investigation failed, expected 'attacker_v4_v6@corp.lan', got %q", s1Email)
	}
	if s1IP != "198.51.100.42" {
		t.Errorf("Server 1 origin client IP failed, expected '198.51.100.42', got %q", s1IP)
	}
	if !strings.Contains(s1Tag, "vless-phone-in") {
		t.Errorf("Server 1 inbound tag failed, expected 'vless-phone-in', got %q", s1Tag)
	}

	// -------------------------------------------------------------------------
	// STEP 4: Test bracketed query equivalence [2001:db8:bad:c0de::1] vs 2001:db8:bad:c0de::1
	// -------------------------------------------------------------------------
	bracketQuery := fmt.Sprintf("[%s]", targetIPv6)
	s1EmailBracket, _, _ := FindEmailAndIPInXrayLog(server1Logs, "", bracketQuery, targetPort, 45)
	if s1EmailBracket != "attacker_v4_v6@corp.lan" {
		t.Errorf("Bracketed query %q failed to match on Server 1, got %q", bracketQuery, s1EmailBracket)
	}

	// -------------------------------------------------------------------------
	// STEP 5: Negative checks
	// Innocent user on Server 3 must never be attributed
	// -------------------------------------------------------------------------
	innocentCheck := FindEmailInHysteriaLog(server3Logs, "2001:db8:good::1", 22, 45)
	if innocentCheck != "" {
		t.Errorf("expected empty email for port 22 on good host, got %q", innocentCheck)
	}
}
