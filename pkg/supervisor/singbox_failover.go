package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultFailoverProbeURL      = "https://www.gstatic.com/generate_204"
	defaultFailoverProbeInterval = 30
	defaultFailoverMinInterval   = 5 * time.Second
	defaultFailoverProbeTimeout  = 5 * time.Second
	defaultFailThreshold         = 2
	defaultRecoverThreshold      = 2
)

// SingBoxFailoverGroup describes a strict-priority selector group managed over Clash API.
type SingBoxFailoverGroup struct {
	Tag           string   `json:"tag"`
	Primary       string   `json:"primary"`
	Outbounds     []string `json:"outbounds"`
	ProbeURL      string   `json:"probeUrl"`
	ProbeInterval int      `json:"probeInterval"` // seconds
	Strategy      string   `json:"strategy"`
}

type clashProxyEntry struct {
	Type string   `json:"type"`
	Name string   `json:"name"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type clashProxiesResp struct {
	Proxies map[string]clashProxyEntry `json:"proxies"`
}

type failoverNodeState struct {
	failStreak int
	okStreak   int
}

type failoverGroupState struct {
	lastProbe time.Time
	nodes     map[string]*failoverNodeState
}

// SingBoxFailoverController monitors Clash API selector groups configured with strict priority
// and handles failure failover + primary failback with anti-flap hysteresis.
type SingBoxFailoverController struct {
	mu               sync.Mutex
	groups           map[string]SingBoxFailoverGroup
	states           map[string]*failoverGroupState
	failThreshold    int
	recoverThreshold int
	minInterval      time.Duration
	probeTimeout     time.Duration
	httpClient       *http.Client

	watchCancel context.CancelFunc
	watchDone   chan struct{}
}

func newSingBoxFailoverController() *SingBoxFailoverController {
	return &SingBoxFailoverController{
		groups:           make(map[string]SingBoxFailoverGroup),
		states:           make(map[string]*failoverGroupState),
		failThreshold:    defaultFailThreshold,
		recoverThreshold: defaultRecoverThreshold,
		minInterval:      defaultFailoverMinInterval,
		probeTimeout:     defaultFailoverProbeTimeout,
		// Delay probes can take several hundred ms to several seconds; never share the 400ms localHTTPClient.
		httpClient: &http.Client{Timeout: defaultFailoverProbeTimeout + 3*time.Second},
	}
}

func (c *Controller) getFailoverController() *SingBoxFailoverController {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failover == nil {
		c.failover = newSingBoxFailoverController()
	}
	return c.failover
}

// ConfigureSingBoxFailover stores strict-priority failover group metadata for Clash API management.
func (c *Controller) ConfigureSingBoxFailover(clashAddr string, groups []SingBoxFailoverGroup) {
	if strings.TrimSpace(clashAddr) != "" {
		c.mu.Lock()
		c.clashAPIAddr = strings.TrimSpace(clashAddr)
		c.clashAddrExplicit = true
		c.mu.Unlock()
	}
	fc := c.getFailoverController()
	fc.SetGroups(groups)
}

// ConfigureSingBoxFailoverFromFile parses a sing-box config JSON file and registers any priority selectors.
func (c *Controller) ConfigureSingBoxFailoverFromFile(clashAddr, configPath string) {
	if strings.TrimSpace(configPath) == "" {
		return
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	groups := ExtractSingBoxFailoverGroupsFromConfig(raw)
	c.ConfigureSingBoxFailover(clashAddr, groups)
}

// StartSingBoxFailoverWatcher starts the background strict-priority failover loop for Sing-box.
func (c *Controller) StartSingBoxFailoverWatcher() {
	fc := c.getFailoverController()
	fc.Start(func() string {
		return c.getActiveClashAddr()
	})
}

// StopSingBoxFailoverWatcher stops the background Sing-box failover loop if running.
func (c *Controller) StopSingBoxFailoverWatcher() {
	fc := c.getFailoverController()
	fc.Stop()
}

// StepSingBoxFailover runs a single synchronous failover check pass across active priority groups.
func (c *Controller) StepSingBoxFailover() error {
	fc := c.getFailoverController()
	return fc.Step(c.getActiveClashAddr(), time.Now())
}

// SetGroups replaces configured priority groups while preserving active health streak state where still valid.
func (fc *SingBoxFailoverController) SetGroups(groups []SingBoxFailoverGroup) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	next := make(map[string]SingBoxFailoverGroup, len(groups))
	for _, g := range groups {
		if g.Tag == "" || !isPriorityStrategyName(g.Strategy) {
			continue
		}
		if g.ProbeURL == "" {
			g.ProbeURL = defaultFailoverProbeURL
		}
		if g.ProbeInterval <= 0 {
			g.ProbeInterval = defaultFailoverProbeInterval
		}
		if g.Primary == "" && len(g.Outbounds) > 0 {
			g.Primary = g.Outbounds[0]
		}
		next[g.Tag] = g
	}
	fc.groups = next
	for tag := range fc.states {
		if _, ok := next[tag]; !ok {
			delete(fc.states, tag)
		}
	}
}

// Start spawns the background watcher goroutine (idempotent).
func (fc *SingBoxFailoverController) Start(clashAddrFn func() string) {
	fc.mu.Lock()
	if fc.watchCancel != nil {
		fc.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fc.watchCancel = cancel
	fc.watchDone = done
	fc.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if addr := clashAddrFn(); addr != "" {
					_ = fc.Step(addr, now)
				}
			}
		}
	}()
}

// Stop terminates the background watcher goroutine and waits for it to exit.
func (fc *SingBoxFailoverController) Stop() {
	fc.mu.Lock()
	cancel := fc.watchCancel
	done := fc.watchDone
	fc.watchCancel = nil
	fc.watchDone = nil
	fc.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Step queries Clash API /proxies and evaluates any priority selector group whose probe interval has elapsed.
func (fc *SingBoxFailoverController) Step(clashAddr string, now time.Time) error {
	baseURL := normalizeClashBaseURL(clashAddr)
	if baseURL == "" {
		return nil
	}

	proxies, err := fc.fetchProxies(baseURL)
	if err != nil {
		return err
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	candidatesByTag := make(map[string]SingBoxFailoverGroup, len(fc.groups))
	for tag, g := range fc.groups {
		candidatesByTag[tag] = g
	}
	// Auto-discover compiler-generated priority selectors (primary ending in -primary or -node-1)
	// so failover works even when sing-box was started externally or loaded from raw JSON.
	for tag, p := range proxies {
		if _, exists := candidatesByTag[tag]; exists {
			continue
		}
		if strings.EqualFold(p.Type, "selector") && len(p.All) >= 2 && isCompilerPriorityPrimary(tag, p.All[0]) {
			candidatesByTag[tag] = SingBoxFailoverGroup{
				Tag:           tag,
				Primary:       p.All[0],
				Outbounds:     append([]string(nil), p.All...),
				ProbeURL:      defaultFailoverProbeURL,
				ProbeInterval: defaultFailoverProbeInterval,
				Strategy:      "priority",
			}
		}
	}

	for tag, group := range candidatesByTag {
		proxyInfo, ok := proxies[tag]
		if !ok || !strings.EqualFold(proxyInfo.Type, "selector") {
			continue
		}
		fc.reconcileGroupLocked(baseURL, group, proxyInfo, now)
	}
	return nil
}

func (fc *SingBoxFailoverController) reconcileGroupLocked(baseURL string, group SingBoxFailoverGroup, proxyInfo clashProxyEntry, now time.Time) {
	candidates := resolveCandidateOrder(group, proxyInfo.All)
	if len(candidates) < 2 {
		return
	}

	interval := time.Duration(group.ProbeInterval) * time.Second
	if group.ProbeInterval <= 0 {
		interval = defaultFailoverProbeInterval * time.Second
	}
	if fc.minInterval > 0 && interval < fc.minInterval {
		interval = fc.minInterval
	}

	st := fc.getOrCreateGroupStateLocked(group.Tag)
	if !st.lastProbe.IsZero() && now.Sub(st.lastProbe) < interval {
		return
	}
	st.lastProbe = now

	probeURL := group.ProbeURL
	if strings.TrimSpace(probeURL) == "" {
		probeURL = defaultFailoverProbeURL
	}

	curIdx := indexOfString(candidates, proxyInfo.Now)
	if curIdx < 0 {
		if target := fc.firstHealthyNode(baseURL, candidates, probeURL); target != "" {
			if err := fc.selectProxy(baseURL, group.Tag, target); err == nil {
				st.node(target).okStreak = 1
				st.node(target).failStreak = 0
			}
		} else if err := fc.selectProxy(baseURL, group.Tag, candidates[0]); err == nil {
			log.Printf("[sentinel-core] sing-box priority group %s initialized to %s", group.Tag, candidates[0])
		}
		return
	}

	if curIdx == 0 {
		primary := candidates[0]
		ns := st.node(primary)
		if fc.probeDelay(baseURL, primary, probeURL) {
			ns.failStreak = 0
			ns.okStreak++
			return
		}
		ns.okStreak = 0
		ns.failStreak++
		if ns.failStreak < fc.failThreshold {
			return
		}
		if target := fc.firstHealthyNode(baseURL, candidates[1:], probeURL); target != "" {
			if err := fc.selectProxy(baseURL, group.Tag, target); err == nil {
				log.Printf("[sentinel-core] sing-box failover %s: %s -> %s (primary failed %d probes)", group.Tag, primary, target, ns.failStreak)
				fc.closeFailedGroupConnections(baseURL, group.Tag, primary)
				tns := st.node(target)
				tns.failStreak = 0
				tns.okStreak = 1
			}
		}
		return
	}

	// Currently running on a backup node (curIdx > 0): check higher-priority candidates for failback.
	var highestHealthyHigher string
	for i := 0; i < curIdx; i++ {
		cand := candidates[i]
		ns := st.node(cand)
		if fc.probeDelay(baseURL, cand, probeURL) {
			ns.failStreak = 0
			ns.okStreak++
			if highestHealthyHigher == "" {
				highestHealthyHigher = cand
			}
			if ns.okStreak >= fc.recoverThreshold {
				if err := fc.selectProxy(baseURL, group.Tag, cand); err == nil {
					log.Printf("[sentinel-core] sing-box failback %s: %s -> %s (higher-priority recovered)", group.Tag, candidates[curIdx], cand)
					return
				}
			}
		} else {
			ns.okStreak = 0
			ns.failStreak++
		}
	}

	// Higher-priority nodes didn't meet recoverThreshold yet; check health of active backup.
	current := candidates[curIdx]
	curState := st.node(current)
	if fc.probeDelay(baseURL, current, probeURL) {
		curState.failStreak = 0
		curState.okStreak++
		return
	}

	curState.okStreak = 0
	curState.failStreak++
	if curState.failStreak < fc.failThreshold {
		return
	}

	// Current backup also failed repeatedly: immediately recover to a healthy higher-priority node if one passed this tick,
	// or fall through to lower-priority backups.
	target := highestHealthyHigher
	if target == "" {
		target = fc.firstHealthyNode(baseURL, candidates[curIdx+1:], probeURL)
	}
	if target != "" {
		if err := fc.selectProxy(baseURL, group.Tag, target); err == nil {
			log.Printf("[sentinel-core] sing-box failover %s: %s -> %s (active backup failed %d probes)", group.Tag, current, target, curState.failStreak)
			fc.closeFailedGroupConnections(baseURL, group.Tag, current)
			tns := st.node(target)
			tns.failStreak = 0
			tns.okStreak = 1
		}
	}
}

func (st *failoverGroupState) node(name string) *failoverNodeState {
	ns, ok := st.nodes[name]
	if !ok {
		ns = &failoverNodeState{}
		st.nodes[name] = ns
	}
	return ns
}

func (fc *SingBoxFailoverController) getOrCreateGroupStateLocked(tag string) *failoverGroupState {
	st, ok := fc.states[tag]
	if !ok {
		st = &failoverGroupState{nodes: make(map[string]*failoverNodeState)}
		fc.states[tag] = st
	}
	return st
}

func (fc *SingBoxFailoverController) firstHealthyNode(baseURL string, candidates []string, probeURL string) string {
	for _, c := range candidates {
		if fc.probeDelay(baseURL, c, probeURL) {
			return c
		}
	}
	return ""
}

func (fc *SingBoxFailoverController) fetchProxies(baseURL string) (map[string]clashProxyEntry, error) {
	resp, err := fc.httpClient.Get(baseURL + "/proxies")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clash /proxies returned status %d", resp.StatusCode)
	}

	var parsed clashProxiesResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed.Proxies, nil
}

func (fc *SingBoxFailoverController) probeDelay(baseURL, nodeName, probeURL string) bool {
	timeoutMs := int(fc.probeTimeout / time.Millisecond)
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	endpoint := fmt.Sprintf("%s/proxies/%s/delay?timeout=%d&url=%s",
		baseURL, url.PathEscape(nodeName), timeoutMs, url.QueryEscape(probeURL))

	resp, err := fc.httpClient.Get(endpoint)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}
	var payload struct {
		Delay int `json:"delay"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}
	return payload.Delay >= 0
}

func (fc *SingBoxFailoverController) selectProxy(baseURL, groupTag, nodeName string) error {
	body, err := json.Marshal(map[string]string{"name": nodeName})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/proxies/%s", baseURL, url.PathEscape(groupTag))
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := fc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("clash PUT %s returned status %d", endpoint, resp.StatusCode)
	}
	return nil
}

func (fc *SingBoxFailoverController) closeFailedGroupConnections(baseURL, groupTag, deadNode string) {
	resp, err := fc.httpClient.Get(baseURL + "/connections")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}
	var payload struct {
		Connections []struct {
			ID     string   `json:"id"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}
	for _, conn := range payload.Connections {
		if containsString(conn.Chains, groupTag) && containsString(conn.Chains, deadNode) {
			req, err := http.NewRequest(http.MethodDelete, baseURL+"/connections/"+url.PathEscape(conn.ID), nil)
			if err != nil {
				continue
			}
			delResp, err := fc.httpClient.Do(req)
			if err == nil {
				_ = delResp.Body.Close()
			}
		}
	}
}

// ExtractSingBoxFailoverGroupsFromConfig discovers compiler-generated strict-priority selector outbounds from raw sing-box JSON.
func ExtractSingBoxFailoverGroupsFromConfig(rawJSON []byte) []SingBoxFailoverGroup {
	var cfg struct {
		Outbounds []struct {
			Type      string   `json:"type"`
			Tag       string   `json:"tag"`
			Default   string   `json:"default"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return nil
	}

	var groups []SingBoxFailoverGroup
	for _, ob := range cfg.Outbounds {
		if !strings.EqualFold(ob.Type, "selector") || ob.Tag == "" || len(ob.Outbounds) < 2 {
			continue
		}
		primary := ob.Default
		if primary == "" {
			primary = ob.Outbounds[0]
		}
		if !isCompilerPriorityPrimary(ob.Tag, primary) {
			continue
		}
		groups = append(groups, SingBoxFailoverGroup{
			Tag:           ob.Tag,
			Primary:       primary,
			Outbounds:     ob.Outbounds,
			ProbeURL:      defaultFailoverProbeURL,
			ProbeInterval: defaultFailoverProbeInterval,
			Strategy:      "priority",
		})
	}
	return groups
}

func isCompilerPriorityPrimary(groupTag, primaryTag string) bool {
	return primaryTag == groupTag+"-primary" || primaryTag == groupTag+"-node-1"
}

func isPriorityStrategyName(strategy string) bool {
	s := strings.ToLower(strings.TrimSpace(strategy))
	return s == "" || s == "priority" || s == "primary" || s == "fallback"
}

func normalizeClashBaseURL(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.TrimRight(trimmed, "/")
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		if strings.HasPrefix(trimmed, ":") {
			trimmed = "127.0.0.1" + trimmed
		} else if strings.HasPrefix(trimmed, "0.0.0.0:") {
			trimmed = "127.0.0.1:" + strings.TrimPrefix(trimmed, "0.0.0.0:")
		}
		trimmed = "http://" + trimmed
	}
	return trimmed
}

func resolveCandidateOrder(group SingBoxFailoverGroup, clashAll []string) []string {
	var ordered []string
	if len(group.Outbounds) > 0 {
		for _, ob := range group.Outbounds {
			if ob == "" {
				continue
			}
			if len(clashAll) == 0 || containsString(clashAll, ob) {
				if !containsString(ordered, ob) {
					ordered = append(ordered, ob)
				}
			}
		}
	}
	if len(ordered) == 0 {
		for _, ob := range clashAll {
			if ob != "" && !containsString(ordered, ob) {
				ordered = append(ordered, ob)
			}
		}
	}
	if group.Primary != "" {
		if idx := indexOfString(ordered, group.Primary); idx > 0 {
			ordered = append([]string{group.Primary}, append(ordered[:idx], ordered[idx+1:]...)...)
		}
	}
	return ordered
}

func indexOfString(slice []string, val string) int {
	for i, item := range slice {
		if item == val {
			return i
		}
	}
	return -1
}
