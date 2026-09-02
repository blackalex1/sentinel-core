package detector

import (
	"fmt"
	"testing"
	"time"
)

// TestAllProtocolLogsAttributionMatrix tests that log lines from all supported protocols
// across Xray, Sing-box, and Hysteria 2 are accurately parsed and matched without false positives.
func TestAllProtocolLogsAttributionMatrix(t *testing.T) {
	nowStr := time.Now().Format("2006/01/02 15:04:05")
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	dstIP := "203.0.113.80"
	dstPort := 22

	testCases := []struct {
		name         string
		core         string
		protocol     string
		logs         []string
		expectedUser string
		expectedIP   string
	}{
		// -------------------------------------------------------------
		// XRAY PROTOCOLS
		// -------------------------------------------------------------
		{
			name:     "Xray VLESS Reality TCP Vision",
			core:     "xray",
			protocol: "vless",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.11:51234 accepted tcp:%s:%d [vless-reality-in >> direct] email: vless_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "vless_user@test.lan",
			expectedIP:   "192.168.1.11",
		},
		{
			name:     "Xray VLESS WebSocket TLS",
			core:     "xray",
			protocol: "vless",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.12:51235 accepted tcp:%s:%d [vless-ws-in >> direct] email: vless_ws_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "vless_ws_user@test.lan",
			expectedIP:   "192.168.1.12",
		},
		{
			name:     "Xray VLESS gRPC TLS",
			core:     "xray",
			protocol: "vless",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.13:51236 accepted tcp:%s:%d [vless-grpc-in >> direct] email: vless_grpc_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "vless_grpc_user@test.lan",
			expectedIP:   "192.168.1.13",
		},
		{
			name:     "Xray VMess TCP AEAD",
			core:     "xray",
			protocol: "vmess",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.14:51237 accepted tcp:%s:%d [vmess-tcp-in >> direct] email: vmess_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "vmess_user@test.lan",
			expectedIP:   "192.168.1.14",
		},
		{
			name:     "Xray VMess WebSocket TLS",
			core:     "xray",
			protocol: "vmess",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.15:51238 accepted tcp:%s:%d [vmess-ws-in >> direct] email: vmess_ws_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "vmess_ws_user@test.lan",
			expectedIP:   "192.168.1.15",
		},
		{
			name:     "Xray Shadowsocks 2022 Blake3",
			core:     "xray",
			protocol: "shadowsocks",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.16:51239 accepted tcp:%s:%d [ss2022-in >> direct] email: ss2022_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "ss2022_user@test.lan",
			expectedIP:   "192.168.1.16",
		},
		{
			name:     "Xray Shadowsocks AEAD AES-256-GCM",
			core:     "xray",
			protocol: "shadowsocks",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.17:51240 accepted tcp:%s:%d [ss-aead-in >> direct] email: ss_aead_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "ss_aead_user@test.lan",
			expectedIP:   "192.168.1.17",
		},
		{
			name:     "Xray Trojan TLS",
			core:     "xray",
			protocol: "trojan",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.18:51241 accepted tcp:%s:%d [trojan-in >> direct] email: trojan_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "trojan_user@test.lan",
			expectedIP:   "192.168.1.18",
		},
		{
			name:     "Xray Trojan gRPC",
			core:     "xray",
			protocol: "trojan",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.19:51242 accepted tcp:%s:%d [trojan-grpc-in >> direct] email: trojan_grpc_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "trojan_grpc_user@test.lan",
			expectedIP:   "192.168.1.19",
		},
		{
			name:     "Xray SOCKS5 Inbound",
			core:     "xray",
			protocol: "socks",
			logs: []string{
				fmt.Sprintf("%s [info] 192.168.1.20:51243 accepted tcp:%s:%d [socks-in >> direct] email: socks_user@test.lan", nowStr, dstIP, dstPort),
			},
			expectedUser: "socks_user@test.lan",
			expectedIP:   "192.168.1.20",
		},

		// -------------------------------------------------------------
		// SING-BOX PROTOCOLS (2-Line connID Format)
		// -------------------------------------------------------------
		{
			name:     "Sing-box VLESS Reality",
			core:     "singbox",
			protocol: "vless",
			logs: []string{
				fmt.Sprintf("+0300 %s INFO [2001 0ms] inbound/vless[sb-vless-in]: inbound connection from 192.168.1.21:52001", nowStr),
				fmt.Sprintf("+0300 %s INFO [2001 10ms] inbound/vless[sb-vless-in]: [sb_vless_user@test.lan] inbound connection to %s:%d", nowStr, dstIP, dstPort),
			},
			expectedUser: "sb_vless_user@test.lan",
			expectedIP:   "192.168.1.21",
		},
		{
			name:     "Sing-box Shadowsocks 2022 Blake3",
			core:     "singbox",
			protocol: "shadowsocks",
			logs: []string{
				fmt.Sprintf("+0300 %s INFO [2002 0ms] inbound/shadowsocks[sb-ss-in]: inbound connection from 192.168.1.22:52002", nowStr),
				fmt.Sprintf("+0300 %s INFO [2002 12ms] inbound/shadowsocks[sb-ss-in]: [sb_ss_user@test.lan] inbound connection to %s:%d", nowStr, dstIP, dstPort),
			},
			expectedUser: "sb_ss_user@test.lan",
			expectedIP:   "192.168.1.22",
		},
		{
			name:     "Sing-box TUIC v5",
			core:     "singbox",
			protocol: "tuic",
			logs: []string{
				fmt.Sprintf("+0300 %s INFO [2003 0ms] inbound/tuic[sb-tuic-in]: inbound connection from 192.168.1.23:52003", nowStr),
				fmt.Sprintf("+0300 %s INFO [2003 14ms] inbound/tuic[sb-tuic-in]: [sb_tuic_user@test.lan] inbound connection to %s:%d", nowStr, dstIP, dstPort),
			},
			expectedUser: "sb_tuic_user@test.lan",
			expectedIP:   "192.168.1.23",
		},
		{
			name:     "Sing-box Hysteria 2 Inbound",
			core:     "singbox",
			protocol: "hysteria2",
			logs: []string{
				fmt.Sprintf("+0300 %s INFO [2004 0ms] inbound/hysteria2[sb-hy2-in]: inbound connection from 192.168.1.24:52004", nowStr),
				fmt.Sprintf("+0300 %s INFO [2004 15ms] inbound/hysteria2[sb-hy2-in]: [sb_hy2_user@test.lan] inbound connection to %s:%d", nowStr, dstIP, dstPort),
			},
			expectedUser: "sb_hy2_user@test.lan",
			expectedIP:   "192.168.1.24",
		},
		{
			name:     "Sing-box Mixed / SOCKS5 Inbound",
			core:     "singbox",
			protocol: "mixed",
			logs: []string{
				fmt.Sprintf("+0300 %s INFO [2005 0ms] inbound/mixed[sb-mixed-in]: inbound connection from 192.168.1.25:52005", nowStr),
				fmt.Sprintf("+0300 %s INFO [2005 8ms] inbound/mixed[sb-mixed-in]: [sb_mixed_user@test.lan] inbound connection to %s:%d", nowStr, dstIP, dstPort),
			},
			expectedUser: "sb_mixed_user@test.lan",
			expectedIP:   "192.168.1.25",
		},

		// -------------------------------------------------------------
		// HYSTERIA 2 STANDALONE PROTOCOLS (JSON & TEXT)
		// -------------------------------------------------------------
		{
			name:     "Hysteria 2 Native JSON Format",
			core:     "hysteria",
			protocol: "hysteria2",
			logs: []string{
				fmt.Sprintf(`{"time":"%s","id":"hy2_native_user@test.lan","reqAddr":"%s:%d"}`, nowISO, dstIP, dstPort),
				fmt.Sprintf(`{"time":"%s","auth":"hy2_native_user@test.lan","addr":"192.168.1.26:53001"}`, nowISO),
			},
			expectedUser: "hy2_native_user@test.lan",
			expectedIP:   "192.168.1.26",
		},
		{
			name:     "Hysteria 2 Text Connection Log",
			core:     "hysteria",
			protocol: "hysteria2",
			logs: []string{
				fmt.Sprintf(`%s [INFO] client connected 192.168.1.27:53002 auth=hy2_text_user@test.lan`, nowStr),
				fmt.Sprintf(`%s [INFO] tcp:%s:%d connection: hy2_text_user@test.lan`, nowStr, dstIP, dstPort),
			},
			expectedUser: "hy2_text_user@test.lan",
			expectedIP:   "192.168.1.27",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.core == "hysteria" {
				email := FindEmailInHysteriaLog(tc.logs, dstIP, dstPort, 45)
				if email != tc.expectedUser {
					t.Fatalf("[%s] expected email %q, got %q", tc.name, tc.expectedUser, email)
				}
				ip := FindClientIPForEmailInHysteriaLog(tc.logs, email, 45)
				if ip != tc.expectedIP {
					t.Errorf("[%s] expected IP %q, got %q", tc.name, tc.expectedIP, ip)
				}
			} else {
				email, ip, _ := FindEmailAndIPInXrayLog(tc.logs, "", dstIP, dstPort, 45)
				if email != tc.expectedUser {
					t.Fatalf("[%s] expected email %q, got %q", tc.name, tc.expectedUser, email)
				}
				if ip != tc.expectedIP {
					t.Errorf("[%s] expected IP %q, got %q", tc.name, tc.expectedIP, ip)
				}
			}
		})
	}
}
