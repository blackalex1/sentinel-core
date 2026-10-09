package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// RuleMirror represents a CDN or mirror for sing-box geosite and geoip rule-sets.
type RuleMirror struct {
	Name           string `json:"name"`
	GeositePattern string `json:"geositePattern"`
	GeoipPattern   string `json:"geoipPattern"`
	ProbeURL       string `json:"probeUrl"`
}

// DefaultMirrors contains independent mirrors tested for availability.
var DefaultMirrors = []RuleMirror{
	{
		Name:           "fastly-jsdelivr",
		GeositePattern: "https://fastly.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/%s.srs",
		GeoipPattern:   "https://fastly.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/%s.srs",
		ProbeURL:       "https://fastly.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-vk.srs",
	},
	{
		Name:           "testingcf-jsdelivr",
		GeositePattern: "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/%s.srs",
		GeoipPattern:   "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/%s.srs",
		ProbeURL:       "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-vk.srs",
	},
	{
		Name:           "gcore-jsdelivr",
		GeositePattern: "https://gcore.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/%s.srs",
		GeoipPattern:   "https://gcore.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/%s.srs",
		ProbeURL:       "https://gcore.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-vk.srs",
	},
	{
		Name:           "cdn-jsdelivr",
		GeositePattern: "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/%s.srs",
		GeoipPattern:   "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/%s.srs",
		ProbeURL:       "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-vk.srs",
	},
	{
		Name:           "gh-proxy",
		GeositePattern: "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs",
		GeoipPattern:   "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs",
		ProbeURL:       "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-vk.srs",
	},
	{
		Name:           "github-raw",
		GeositePattern: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs",
		GeoipPattern:   "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs",
		ProbeURL:       "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-vk.srs",
	},
}

var (
	cachedMirror     *RuleMirror
	cachedMirrorTime time.Time
	mirrorMu         sync.RWMutex
)

// ProbeMirrorsDirect tests all mirrors concurrently via direct HTTP requests.
// Returns the first responding mirror within the timeout.
func ProbeMirrorsDirect(timeout time.Duration) *RuleMirror {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan RuleMirror, len(DefaultMirrors))
	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	for _, m := range DefaultMirrors {
		wg.Add(1)
		go func(mirror RuleMirror) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "HEAD", mirror.ProbeURL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					select {
					case resultCh <- mirror:
					default:
					}
				}
			}
		}(m)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	start := time.Now()
	select {
	case best := <-resultCh:
		if best.Name != "" {
			elapsedMs := time.Since(start).Milliseconds()
			log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_DIRECT_MIRROR_OK", best.Name, elapsedMs))
			return &best
		}
	case <-ctx.Done():
	}

	log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_DIRECT_MIRRORS_BLOCKED"))
	return nil
}

// GetActiveRuleMirror returns the active cached mirror or tests direct connectivity.
// Falls back to the first default mirror if no direct connection is available.
func GetActiveRuleMirror() RuleMirror {
	mirrorMu.RLock()
	if cachedMirror != nil && time.Since(cachedMirrorTime) < 10*time.Minute {
		m := *cachedMirror
		mirrorMu.RUnlock()
		return m
	}
	mirrorMu.RUnlock()

	log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_CHECKING_DIRECT_MIRRORS"))
	best := ProbeMirrorsDirect(1500 * time.Millisecond)

	mirrorMu.Lock()
	defer mirrorMu.Unlock()
	if best != nil {
		cachedMirror = best
		cachedMirrorTime = time.Now()
		return *best
	}

	cachedMirror = &DefaultMirrors[0]
	cachedMirrorTime = time.Now()
	return DefaultMirrors[0]
}

// ProbeOutboundsViaClashAPI probes a list of proxy outbounds via Sing-box Clash API
// to verify which outbound can reach the target mirror URL.
func ProbeOutboundsViaClashAPI(clashAddr string, outbounds []string, mirrorProbeURL string, timeout time.Duration) string {
	if clashAddr == "" {
		clashAddr = "127.0.0.1:9090"
	}
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	client := &http.Client{
		Timeout: timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan string, len(outbounds))
	var wg sync.WaitGroup

	for _, ob := range outbounds {
		if ob == "" || ob == "direct" || ob == "block" {
			continue
		}
		wg.Add(1)
		go func(tag string) {
			defer wg.Done()
			apiURL := fmt.Sprintf("http://%s/proxies/%s/delay?timeout=%d&url=%s",
				clashAddr,
				url.PathEscape(tag),
				timeout.Milliseconds(),
				url.QueryEscape(mirrorProbeURL),
			)
			req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil || resp == nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				var data struct {
					Delay int `json:"delay"`
				}
				if json.NewDecoder(resp.Body).Decode(&data) == nil && data.Delay > 0 {
					select {
					case resultCh <- tag:
					default:
					}
				}
			}
		}(ob)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	select {
	case workingTag := <-resultCh:
		if workingTag != "" {
			return workingTag
		}
	case <-ctx.Done():
	}

	return ""
}
