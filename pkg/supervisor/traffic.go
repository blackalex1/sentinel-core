package supervisor

import (
	"net/http"
	"time"
)

// HTTPClient with fast timeout for localhost queries
var localHTTPClient = &http.Client{
	Timeout: 500 * time.Millisecond,
}

// AggregateTraffic combines traffic metrics from multiple cores for each client.
func AggregateTraffic(metricsList ...map[string]ClientTraffic) map[string]ClientTraffic {
	aggregated := make(map[string]ClientTraffic)

	for _, metrics := range metricsList {
		for email, t := range metrics {
			entry := aggregated[email]
			entry.Email = email
			entry.DownBytes += t.DownBytes
			entry.UpBytes += t.UpBytes
			entry.Connections += t.Connections
			if t.Online {
				entry.Online = true
			}
			for _, ip := range t.ActiveIPs {
				if !containsString(entry.ActiveIPs, ip) {
					entry.ActiveIPs = append(entry.ActiveIPs, ip)
				}
			}
			aggregated[email] = entry
		}
	}

	return aggregated
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
