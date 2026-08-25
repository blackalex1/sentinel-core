package netfilter

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// FindRealVPNClientIP searches conntrack table entries for the original VPN client IP.
// conntrackDump is optional; if empty on Linux, it reads directly from /proc/net/nf_conntrack.
func FindRealVPNClientIP(proto, containerIP, dstIP string, sport, dpt int, conntrackDump string) string {
	var lines []string

	if conntrackDump != "" {
		scanner := bufio.NewScanner(strings.NewReader(conntrackDump))
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
	} else if runtime.GOOS == "linux" {
		conntrackPaths := []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"}
		for _, p := range conntrackPaths {
			if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
				scanner := bufio.NewScanner(bytes.NewReader(data))
				for scanner.Scan() {
					lines = append(lines, scanner.Text())
				}
				break
			}
		}

		if len(lines) == 0 {
			if out, err := exec.Command("conntrack", "-L").Output(); err == nil && len(out) > 0 {
				scanner := bufio.NewScanner(bytes.NewReader(out))
				for scanner.Scan() {
					lines = append(lines, scanner.Text())
				}
			}
		}
	}

	if len(lines) == 0 {
		return ""
	}

	protoLower := strings.ToLower(proto)

	for _, line := range lines {
		if !strings.Contains(strings.ToLower(line), protoLower) {
			continue
		}

		parts := strings.Fields(line)
		var srcs []string
		var dsts []string
		var sports []int
		var dports []int

		for _, p := range parts {
			if idx := strings.IndexByte(p, '='); idx > 0 {
				k := p[:idx]
				v := p[idx+1:]
				switch k {
				case "src":
					srcs = append(srcs, v)
				case "dst":
					dsts = append(dsts, v)
				case "sport":
					if val, err := strconv.Atoi(v); err == nil {
						sports = append(sports, val)
					}
				case "dport":
					if val, err := strconv.Atoi(v); err == nil {
						dports = append(dports, val)
					}
				}
			}
		}

		if len(srcs) >= 2 && len(dsts) >= 2 && len(sports) >= 2 && len(dports) >= 2 {
			origSrc := srcs[0]
			origDst := dsts[0]
			replySrc := srcs[1]
			replyDst := dsts[1]

			origSport := sports[0]
			origDport := dports[0]
			replySport := sports[1]
			replyDport := dports[1]

			// Direction 1: Match reply flow
			if replyDst == containerIP && replySrc == dstIP && replySport == dpt && replyDport == sport {
				return origSrc
			}

			// Direction 2: Match orig flow
			if origSport == sport && origDport == dpt && origDst == dstIP && replyDst == containerIP {
				return origSrc
			}
		}
	}

	return ""
}
