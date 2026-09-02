package detector

import (
	"fmt"
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
}

func TestCascadedTwoPanelRoutingAndAttribution(t *testing.T) {
	nowStr := time.Now().Format("2006/01/02 15:04:05")
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Panel 1 (Upstream LXC 104) logs:
	panel1Logs := []string{
		fmt.Sprintf("+0300 %s INFO [1001 0ms] inbound/vless[vless-phone-in]: inbound connection from 192.168.1.50:41234", nowStr),
		fmt.Sprintf("+0300 %s INFO [1001 10ms] inbound/vless[vless-phone-in]: [cascaded_user@test.lan] inbound connection to 203.0.113.195:22", nowStr),
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
