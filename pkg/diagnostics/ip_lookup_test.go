package diagnostics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetPublicIPWithMockServer(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"success": true,
			"ip": "203.0.113.42",
			"country": "Germany",
			"country_code": "DE",
			"city": "Frankfurt",
			"region": "Hesse",
			"connection": {
				"asn": "AS12345",
				"org": "Sentinel Testing Org"
			}
		}`))
	}))
	defer mockServer.Close()

	// Temporarily override endpoints
	origEndpoints := defaultIPEndpoints
	defer func() { defaultIPEndpoints = origEndpoints }()

	defaultIPEndpoints = []ipEndpoint{
		{
			URL:    mockServer.URL,
			IsJSON: true,
			Parser: origEndpoints[0].Parser,
		},
	}

	info, err := GetPublicIP(0, "", "", 1*time.Second)
	if err != nil {
		t.Fatalf("GetPublicIP failed: %v", err)
	}

	if info.IP != "203.0.113.42" {
		t.Errorf("expected IP 203.0.113.42, got %s", info.IP)
	}
	if info.Country != "Germany" {
		t.Errorf("expected country Germany, got %s", info.Country)
	}
	if info.CountryCode != "DE" {
		t.Errorf("expected country code DE, got %s", info.CountryCode)
	}
}
