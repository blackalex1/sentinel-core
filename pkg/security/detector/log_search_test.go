package detector

import (
	"fmt"
	"testing"
	"time"
)

func TestLogSearchXrayAndSingbox(t *testing.T) {
	nowStr := time.Now().Format("2006/01/02 15:04:05")
	lines := []string{
		fmt.Sprintf("%s [info] 192.168.1.100:54321 accepted tcp:13.251.130.193:22 [VLESS-TCP >> direct] email: attacker@xray.com", nowStr),
		fmt.Sprintf("%s [info] 10.0.0.5:12345 accepted tcp:[13.251.130.193]:22 email: bad_user@domain.com", nowStr),
		fmt.Sprintf("%s [info] inbound/vless[inbound-8]: [test_client_alpha] inbound connection to 198.51.100.22:22", nowStr),
	}

	// 1. Match attacker@xray.com
	email1, ip1, tag1 := FindEmailAndIPInXrayLog(lines[:1], "", "13.251.130.193", 22, 300)
	if email1 != "attacker@xray.com" || ip1 != "192.168.1.100" || tag1 != "VLESS-TCP >> direct" {
		t.Errorf("unexpected xray search result: email=%q, ip=%q, tag=%q", email1, ip1, tag1)
	}

	// 2. Match bracketed IP
	email2, _, _ := FindEmailAndIPInXrayLog(lines[1:2], "", "13.251.130.193", 22, 300)
	if email2 != "bad_user@domain.com" {
		t.Errorf("unexpected bracketed ip result: %q", email2)
	}

	// 3. Match sing-box inbound tag
	email3, _, _ := FindEmailAndIPInXrayLog(lines[2:], "", "198.51.100.22", 22, 300)
	if email3 != "test_client_alpha" {
		t.Errorf("unexpected singbox inbound tag result: %q", email3)
	}
}

func TestLogSearchHysteria(t *testing.T) {
	nowStr := time.Now().Format("2006-01-02T15:04:05Z")
	lines := []string{
		fmt.Sprintf(`{"time":"%s","id":"tunnel_user","reqAddr":"13.251.130.193:22"}`, nowStr),
		fmt.Sprintf(`{"time":"%s","auth":"alice@hy2.com","addr":"192.168.1.88:45678"}`, nowStr),
	}

	// 1. Match Hysteria user
	email1 := FindEmailInHysteriaLog(lines, "13.251.130.193", 22, 300)
	if email1 != "tunnel_user" {
		t.Errorf("expected tunnel_user, got %q", email1)
	}

	// 2. Find client IP for email
	ip := FindClientIPForEmailInHysteriaLog(lines, "alice@hy2.com", 300)
	if ip != "192.168.1.88" {
		t.Errorf("expected 192.168.1.88, got %q", ip)
	}
}
