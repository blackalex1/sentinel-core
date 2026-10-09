package singbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMirror_DefaultMirrorsConfigured(t *testing.T) {
	if len(DefaultMirrors) < 4 {
		t.Fatalf("expected at least 4 default mirrors, got %d", len(DefaultMirrors))
	}
	for _, m := range DefaultMirrors {
		if m.Name == "" || m.GeositePattern == "" || m.GeoipPattern == "" || m.ProbeURL == "" {
			t.Errorf("mirror %q has empty fields: %+v", m.Name, m)
		}
	}
}

func TestMirror_GetActiveRuleMirror(t *testing.T) {
	mirror := GetActiveRuleMirror()
	if mirror.Name == "" {
		t.Fatal("expected non-empty active rule mirror")
	}
	if !strings.Contains(mirror.GeositePattern, "%s") {
		t.Errorf("geosite pattern must have placeholder: %s", mirror.GeositePattern)
	}
}

func TestMirror_ProbeOutboundsViaClashAPI(t *testing.T) {
	// Mock Clash API server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/proxies/proxy-working/delay") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int{"delay": 45})
			return
		}
		if strings.Contains(r.URL.Path, "/proxies/proxy-failing/delay") {
			http.Error(w, "connection timeout", http.StatusGatewayTimeout)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	hostPort := strings.TrimPrefix(ts.URL, "http://")
	outbounds := []string{"proxy-failing", "proxy-working"}

	working := ProbeOutboundsViaClashAPI(hostPort, outbounds, "https://example.com/test", 1*time.Second)
	if working != "proxy-working" {
		t.Errorf("expected working outbound 'proxy-working', got %q", working)
	}
}
